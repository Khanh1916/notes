---
layout: post
title: "OracleSecLab: a black-box walkthrough of four Oracle web bugs"
date: 2026-11-13
author: Nguyen Nam Khanh
tags: [oracle, sql-injection, plsql, business-logic, supply-chain, ctf, walkthrough]
description: >
  A black-box walkthrough of OracleSecLab, an intentionally vulnerable Oracle and
  PHP student portal I built. Starting from nothing but the running app, I find and
  exploit four bugs: UNION SQL injection, a negative-quantity logic flaw, a
  broken-access-control supply-chain chain, and PL/SQL injection through
  EXECUTE IMMEDIATE.
platform: Self-hosted
difficulty: Intermediate
flags: 4
flags_label: Findings
read: 13
bilingual: true
---

<div class="lang-en" markdown="1">

> Lab use only. OracleSecLab is an app I wrote with these bugs on purpose, to
> teach database security. Everything below runs against my own copy on
> `localhost` in Docker. Never point these techniques at a system you do not own
> or have permission to test.

OracleSecLab is a university portal ("FPT Student Portal") on Oracle 23c Free,
PHP 8.3 and Apache. I built it to practise against Oracle, which behaves unlike
the MySQL and PostgreSQL labs most people learn on: its own SQL dialect (`DUAL`,
`ROWNUM`, `USER_TABLES`), its own PL/SQL, its own injection and enumeration
habits. I go at it black-box, with nothing but the running app, and find four bugs
hidden among dozens of ordinary pages.

| # | Vulnerability | Where | OWASP 2021 |
|---|---|---|---|
| 1 | Oracle UNION SQL injection (fragmented flag) | `search.php?q=` | A03 Injection |
| 2 | Business-logic flaw (negative quantity) | `store.php` | A04 Insecure Design |
| 3 | Broken access control into supply-chain poisoning | `partner_config.php` + `admin.php` | A01 / A06 |
| 4 | Oracle PL/SQL injection (`EXECUTE IMMEDIATE`) | `course_lookup.php` | A03 Injection |

---

## Scope and rules of engagement

The scope is one target: the `dbs401-oracle-app` on `http://localhost:8080` and the
Oracle database behind it. Everything the app serves is fair game. Nothing outside the
container is.

It is a black-box test. I get no source code and no database credentials, only the two
ordinary app logins any user would have (`student1`, and later `admin`). I work from
the running app alone and infer the rest from how it behaves.

Rules of engagement are simple because I own the box and nobody else is on it: it runs
on my own machine, not a shared or production system, so any technique is allowed,
injection and fuzzing included, and I need no change window or emergency contact.
Nothing here is destructive: I read and extract, I do not drop tables or wipe data.

---

## Run it yourself

The whole lab is one command, no Oracle install:

```bash
git clone https://github.com/Khanh1916/oracle-sec-lab.git
cd oracle-sec-lab
RANDOMIZE_FLAGS=1 docker compose up -d
```

Then open `http://localhost:8080/dbs401-oracle-app` and log in. The accounts I use
below:

| Username | Password | Role |
|---|---|---|
| `student1` | `Student@123` | Student (150 credits) |
| `admin` | `Admin@DBS401!2024` | Admin |

> A note on the flags. Every flag here has the shape `DBS401{...}`. I ran my copy
> with `RANDOMIZE_FLAGS=1`, so every flag in the screenshots is a throwaway value
> for that one container, not the real answer. The point is for you to produce the
> flag yourself instead of copying the final string.

Here is the portal after I log in as `student1`, an ordinary academic dashboard.
None of it matters to the bugs.

![The FPT Student Portal dashboard after logging in as a student]({{ '/images/oracle-sec-lab/00-dashboard.jpg' | relative_url }})

---

## Recon

First, what is the server running. I look at the headers and the URL endings:

```bash
curl -sI http://localhost:8080/dbs401-oracle-app/ | grep -iE 'server|x-powered-by'
```

Apache and PHP, and every page ends in `.php`. The backend is not obvious yet, but
the lab name (DBS401) and the SQL errors later make it Oracle.

Next I map the app: walk the whole left menu for the public pages, then fuzz paths
and parameters for the hidden parts:

```bash
ffuf -u 'http://localhost:8080/dbs401-oracle-app/FUZZ.php' -w words.txt -mc 200,302
ffuf -u 'http://localhost:8080/dbs401-oracle-app/admin.php?FUZZ=1' -w params.txt -mc 200
```

That gives the interesting surface: `search.php` (Student Search), `store.php`
(Material Store) and `course_lookup.php` (Course Info) are in the menu;
`partner_config.php` and a `check_updates` parameter on `admin.php` only show up
through fuzzing.

Now, which pages are likely to break. The ones that only display static data,
timetables, transcripts, I skip. The suspicious ones take my input and push it to
the server: Student Search (free text that probably ends up in a query), Material
Store (a quantity field, an easy money-math bug), Course Info (a lookup by code that
hits the database), and the admin update (it pulls a file from outside, a
supply-chain risk). A quick single-quote-and-odd-number probe confirms them.

---

## Assets

Before exploiting anything, I take stock of what is actually worth reaching in this
app, and how sensitive each piece is. That is what decides which findings matter
later.

| Asset | Where | Sensitivity | Why it matters |
|---|---|---|---|
| Student records (PII) | `STUDENTS` and related tables | High | Names, IDs and academic data, a privacy breach on its own |
| The four flags | `FLAGS`, `AUDIT_LOGS`, `CONFIG_STORE`, `PLSQL_VAULT` | High | The goal of the lab, standing in for any crown-jewel secret |
| Database config and secrets | `CONFIG_STORE` (e.g. `update_url`) | High | Internal URLs and settings that open further attacks |
| Admin functions | `admin.php`, `partner_config.php` | High | Privileged actions a normal user should never reach |
| Partner update integration | the `check_updates` flow | Critical | Pulls and runs an external file, a foothold for code execution |
| Audit logs | `AUDIT_LOGS` | Medium | Useful to an attacker for hiding, and it also leaks a flag fragment |

---

## Challenge 1: Oracle UNION SQL injection

The Student Search page (`search.php`) looks ordinary. Search a real major and you
get a table of students:

![A normal search for "Software" returning student rows]({{ '/images/oracle-sec-lab/01-search-normal.jpg' | relative_url }})

The first probe is a single quote. Send `?q='` and the page returns "Search
failed" instead of results, a caught error rather than a stack trace:

![A single quote triggers "Search failed. Please check your input."]({{ '/images/oracle-sec-lab/02-search-quote-error.jpg' | relative_url }})

That error on a lone quote is the tell: the input reaches the query and breaks its
syntax, but the app hides the details (blind SQLi). From the way the search
behaves, the input goes into a `LIKE '%...%'` match inside parentheses, so to take
over the query I close the quote and the parenthesis and comment out the rest. The
prefix is `KEYWORD%') ... --`.

Testing a few keywords shows a filter: DDL words like `DROP` and `UPDATE` come back
rejected, but `UNION SELECT` goes through. The filter is a plain substring match,
so even `update_url` is rejected because it contains `UPDATE`. That matters in
Challenge 3.

Oracle `UNION` needs the same column count and compatible types on both sides, and
every `SELECT` needs a `FROM` (that is what `DUAL` is for). A `1,2,3` guess fails
on type, so I feed strings:

```sql
x%') UNION SELECT 1,'a','b' FROM DUAL--
```

`USER_TABLES` lists the schema's tables:

```sql
x%') UNION SELECT ROWNUM, table_name, NULL FROM USER_TABLES WHERE ROWNUM<=14--
```

![UNION injection listing the schema's tables, including FLAGS and CONFIG_STORE]({{ '/images/oracle-sec-lab/03-union-tables.jpg' | relative_url }})

Some names stand out: `FLAGS`, `AUDIT_LOGS`, `CONFIG_STORE`, plus decoys like
`FAKE_FLAGS` and `FLAG_ARCHIVE`. Dumping `FLAGS` gives a fragment and a decoy:

```sql
x%') UNION SELECT 1, flag_code, flag_part FROM FLAGS--
```

![The FLAGS table yields one real hex fragment and one base64 decoy]({{ '/images/oracle-sec-lab/04-flags-fragments.jpg' | relative_url }})

`FL1_PART_A` is hex (decode it and it starts `DBS401{SQL_`). `FL_DECOY_B` is base64
for `SOME_FAKE_FLAG_HERE`, so ignore it. The other two real pieces sit elsewhere,
in different encodings:

- Part B in `AUDIT_LOGS.metadata_note`, a JSON fragment written backwards.
- Part C in `CONFIG_STORE` under `sys_alpha_marker`, base64.

```sql
x%') UNION SELECT 1, metadata_note, action FROM AUDIT_LOGS
     WHERE action='SYSTEM_AUDIT_CHECK'--

x%') UNION SELECT 1, config_value, config_key FROM CONFIG_STORE
     WHERE config_key='sys_alpha_marker'--
```

Decode each piece (hex to ASCII, reverse the string, base64 to ASCII) and join
them into one `DBS401{SQL_..._..._...}` flag. Two base64 decoys in `CONFIG_STORE`
and `FLAGS` are there to waste a scanner's time; a clean decode is not the same as
a correct one.

---

## Challenge 2: a negative quantity is free money

The Material Store (`store.php`) sells a cheap study guide (100 credits) and one
locked item, "Exam Leak 2024 (CLASSIFIED)", for 999,999 credits. My account has
150:

![The store: 150 credits, a cheap item, and a locked 999,999-credit item]({{ '/images/oracle-sec-lab/06-store-before.jpg' | relative_url }})

The order form checks that I can afford it, but not that the quantity is positive.
Ordering a negative quantity makes my balance go up instead of down, so the server
is doing cost = qty × price and subtracting that from my credits. Order −10,000 of
the 100-credit guide:

```text
cost        = -10,000 * 100          = -1,000,000
new_credits =    150 - (-1,000,000)  =  1,000,150
```

Subtracting a negative adds it. The balance jumps past 999,999 and the locked item
unlocks, with the flag:

![After ordering a negative quantity, credits jump to 1,000,150 and the flag unlocks]({{ '/images/oracle-sec-lab/07-store-flag.jpg' | relative_url }})

No injection, no tooling, just an input the form never expected.

---

## Challenge 3: broken access control into a supply-chain poison

The `check_updates` action I found during recon reads a partner manifest URL,
fetches that JSON, and if the manifest claims a newer version it processes the
payload. Control that URL and I control what the admin's server fetches.

The URL is a private config row, not shown in the UI. I already have SQL injection
from Challenge 1, so I dump `CONFIG_STORE`. I cannot name `update_url` (the filter
blocks `UPDATE`), so I dump the whole table and read the row:

```sql
x%') UNION SELECT 1, config_key, config_value FROM CONFIG_STORE
     WHERE config_key NOT LIKE 'runtime%'--
```

![SQLi reveals the private update_url and the app_version from CONFIG_STORE]({{ '/images/oracle-sec-lab/05-config-recon.jpg' | relative_url }})

The server fetches updates from `http://127.0.0.1:8081/manifest.json`, and the
current `app_version` is `3.1.0`. To trigger the update path my manifest has to
claim a higher version.

A hidden page, `partner_config.php`, changes that URL. It is labelled "ADMIN ONLY",
but it only checks that I am logged in, nothing more, so an ordinary student
account can open it and change partner config:

![A logged-in student can open the admin-only partner configuration page]({{ '/images/oracle-sec-lab/08-partner-config-student.jpg' | relative_url }})

I point the URL at a manifest of my own (in the lab, `demo.json`, version `9.9.9`
with the expected `flag_part`). The save goes through:

![The student successfully overwrites the partner manifest URL]({{ '/images/oracle-sec-lab/09-partner-poisoned.jpg' | relative_url }})

Back as admin, "check for updates" fetches my manifest, sees `9.9.9 > 3.1.0`,
trusts it, takes the `flag_part` from my file, combines it with a server-side half,
and hex-decodes the result onto the page:

![The admin update check fetches the poisoned manifest and reveals the supply-chain flag]({{ '/images/oracle-sec-lab/10-admin-flag.jpg' | relative_url }})

"Update successful! System upgraded to version 9.9.9", and the flag drops out. A
student with no privileges got data of their choosing run inside the admin's
trust. That is a supply-chain attack: you compromise something the target trusts
and let the target pull it in.

---

## Challenge 4: PL/SQL injection through EXECUTE IMMEDIATE

The Course Info lookup (`course_lookup.php`) takes a course code. A normal code
returns a normal course name:

![A normal course-code lookup returns "Database Security"]({{ '/images/oracle-sec-lab/11-course-normal.jpg' | relative_url }})

The code looks like it is passed as a bound parameter, which should be safe. But
injecting into it still returns data, so the value must end up in dynamic SQL
deeper in: a stored function that concatenates the code into a string and runs it
with `EXECUTE IMMEDIATE`. The bind at the call site protects nothing once that
happens.

The lookup returns a single value, so the injected query has to return exactly one
row. The obvious payload hits two rows, and the function reports "Ambiguous result"
(Oracle's `TOO_MANY_ROWS`):

```sql
zzz' UNION SELECT secret_flag FROM PLSQL_VAULT--
```

![The naive UNION returns two rows and fails with "Ambiguous result"]({{ '/images/oracle-sec-lab/12-course-ambiguous.jpg' | relative_url }})

Filter to the one real row and the flag comes back as a course name:

```sql
zzz' UNION SELECT secret_flag FROM PLSQL_VAULT WHERE label='CHALLENGE_4'--
```

![Filtering to one row extracts Flag 4 through the PL/SQL injection]({{ '/images/oracle-sec-lab/13-course-flag.jpg' | relative_url }})

---

## Impact

Each bug's severity the way a pentest report scores it, likelihood times impact:

| Vulnerability | Likelihood | Impact | Severity |
|---|---|---|---|
| UNION SQL injection | High, a single quote gets in | Reads the whole database: student records, config, secrets | Critical |
| Negative-quantity logic | High, just a negative number | Mint credits and buy restricted items, scoped to the store | High |
| Broken access control + supply chain | Medium, chains SQLi with a hidden page | Makes the admin server fetch and run an attacker-controlled file | Critical |
| PL/SQL injection | High, injects through the lookup | Reads a protected vault that looked safe | High |

## Remediation

Each bug has a direct fix, ordered here by how badly it bites.

| Vulnerability | Fix |
|---|---|
| UNION SQL injection | Use bind variables for every query and never build SQL by string concatenation. Validate input against an allow-list, and run the app on a least-privilege database account, not one that can read every table. The substring filter here is not a defence and should go. |
| Broken access control + supply chain | Check authorization on the server for every privileged action, by role, not just "logged in". For updates, pin the source, verify the manifest with a signature or checksum, and never trust a version number the client controls. |
| PL/SQL injection | Keep `EXECUTE IMMEDIATE` on bind variables and never concatenate user input into the dynamic statement. Validate identifiers with `DBMS_ASSERT`. |
| Negative-quantity logic | Validate the quantity on the server (an integer greater than zero) and re-check every business rule, like the balance, server-side before the order commits. |

---

> Source and full setup: [github.com/Khanh1916/oracle-sec-lab](https://github.com/Khanh1916/oracle-sec-lab)


</div>

<div class="lang-vi" markdown="1">

> OracleSecLab là app tôi tự viết, cố ý cài sẵn các lỗ hổng để
> dạy về bảo mật cơ sở dữ liệu. Mọi thứ bên dưới chạy trên máy cá nhân, ở
> `localhost`, trong Docker. Các lỗ hổng đều là cố ý. Không áp dụng các kỹ thuật
> này lên hệ thống bạn không sở hữu hoặc chưa được phép.

OracleSecLab là một fake academy portal ("FPT Student Portal") chạy trên Oracle
23c Free, PHP 8.3 và Apache. Tôi dựng nó để luyện trên Oracle, vốn khác với các
lab MySQL, PostgreSQL mà đa số người học quen: cú pháp SQL riêng (`DUAL`, `ROWNUM`,
`USER_TABLES`), có PL/SQL, và lối inject, liệt kê bảng riêng. Ở đây tôi tiếp cận
bài toán theo hướng black-box, chỉ tương tác với ứng dụng đang chạy, từ đó phát
hiện bốn lỗ hổng nằm xen lẫn giữa các tính năng thông thường.

| # | Lỗ hổng | Ở đâu | OWASP 2021 |
|---|---|---|---|
| 1 | Oracle UNION SQL injection (flag chia mảnh) | `search.php?q=` | A03 Injection |
| 2 | Lỗi business logic (số lượng âm) | `store.php` | A04 Insecure Design |
| 3 | Broken access control thành supply-chain poisoning | `partner_config.php` + `admin.php` | A01 / A06 |
| 4 | Oracle PL/SQL injection (`EXECUTE IMMEDIATE`) | `course_lookup.php` | A03 Injection |

---

## Scope and rules of engagement

Phạm vi kiểm thử gói gọn trong một mục tiêu: `dbs401-oracle-app` tại `http://localhost:8080`
và cơ sở dữ liệu Oracle phía sau. Toàn bộ các endpoint và tính năng do ứng dụng cung cấp
đều thuộc phạm vi kiểm thử; mọi thành phần ngoài container đều nằm ngoài phạm vi.

Đây là đánh giá black-box: không có mã nguồn, không có thông tin đăng nhập database,
chỉ khởi đầu với tài khoản người dùng thông thường (`student1`, sau đó mở rộng sang
`admin`). Mọi phán đoán về cấu trúc bên dưới đều dựa trên phản hồi thực tế của ứng dụng.

Quy tắc phối hợp (Rules of engagement) được xác định rõ ràng: môi trường lab chạy cục bộ
trên máy cá nhân, không ảnh hưởng đến hệ thống dùng chung hay môi trường production, do
đó có thể tự do áp dụng các kỹ thuật tấn công từ injection đến fuzzing mà không cần đặt
khung thời gian bảo trì. Quá trình kiểm thử không thực hiện các hành động phá hoại, chỉ
trích xuất dữ liệu phục vụ mục đích học tập mà không xóa hay can thiệp vào cấu trúc bảng.

---

## Môi trường thực hành

Cả lab gói trong một câu lệnh, không cần cài Oracle:

```bash
git clone https://github.com/Khanh1916/oracle-sec-lab.git
cd oracle-sec-lab
RANDOMIZE_FLAGS=1 docker compose up -d
```

Mở `http://localhost:8080/dbs401-oracle-app` rồi đăng nhập. Hai tài khoản tôi dùng
ở dưới:

| Tài khoản | Mật khẩu | Vai trò |
|---|---|---|
| `student1` | `Student@123` | Student (150 credit) |
| `admin` | `Admin@DBS401!2024` | Admin |

> Lưu ý về flag. Flag ở đây đều có dạng `DBS401{...}`. Tôi bật `RANDOMIZE_FLAGS=1`
> khi chạy, nên mỗi flag trong hình chỉ là giá trị random của riêng container đó,
> không phải đáp án thật. Mục đích là muốn bạn tự làm ra flag chứ không copy sẵn
> đáp án.

Đây là trang portal sau khi đăng nhập bằng `student1`, một dashboard học vụ bình
thường. Giao diện này không liên quan đến lỗ hổng.

![Dashboard của FPT Student Portal sau khi đăng nhập bằng tài khoản sinh viên]({{ '/images/oracle-sec-lab/00-dashboard.jpg' | relative_url }})

---

## Recon

Đầu tiên xem server chạy gì, nhìn header và đuôi URL:

```bash
curl -sI http://localhost:8080/dbs401-oracle-app/ | grep -iE 'server|x-powered-by'
```

Thấy Apache và PHP, các trang đều có đuôi `.php`. Backend chưa rõ ngay, nhưng tên
lab (DBS401) và kiểu lỗi SQL ở phần sau cho thấy đây là Oracle.

Tiếp theo vẽ bản đồ app. Đi hết menu bên trái để lấy các trang công khai, rồi fuzz
đường dẫn và param để tìm phần ẩn:

```bash
ffuf -u 'http://localhost:8080/dbs401-oracle-app/FUZZ.php' -w words.txt -mc 200,302
ffuf -u 'http://localhost:8080/dbs401-oracle-app/admin.php?FUZZ=1' -w params.txt -mc 200
```

Gộp lại được vài chỗ đáng chú ý: `search.php` (Student Search), `store.php` (Material
Store) và `course_lookup.php` (Course Info) nằm trên menu; `partner_config.php` và
param `check_updates` trên `admin.php` thì phải fuzz mới ra.

Tiếp theo là bước xác định bề mặt tấn công. Các trang chỉ hiển thị dữ liệu tĩnh như
thời khóa biểu hay bảng điểm được bỏ qua. Đáng chú ý là các chức năng nhận input từ người
dùng rồi gửi về server: Student Search (nhập văn bản tự do, dễ dính ghép chuỗi SQL),
Material Store (nhập số lượng mua, tiềm ẩn lỗi logic tính toán credit), Course Info (tra
cứu theo mã, cũng truy vấn database), và cơ chế cập nhật của admin (tải file từ máy chủ
đối tác, dễ phát sinh rủi ro chuỗi cung ứng). Thử nghiệm nhanh với dấu nháy đơn và các
giá trị biên xác nhận các điểm này đều có phản ứng bất thường.

---

## Assets

Trước khi khai thác, tôi điểm lại trong app này cái gì thật sự đáng để nhắm tới, và
mỗi thứ nhạy tới đâu. Chính nó quyết định sau này lỗ nào mới đáng lo.

| Tài sản | Ở đâu | Độ nhạy | Vì sao đáng giá |
|---|---|---|---|
| Dữ liệu sinh viên (PII) | bảng `STUDENTS` và các bảng liên quan | Cao | Tên, mã số, dữ liệu học vụ, rò rỉ là đã thành sự cố |
| Bốn flag | `FLAGS`, `AUDIT_LOGS`, `CONFIG_STORE`, `PLSQL_VAULT` | Cao | Mục tiêu của lab, đóng vai mọi secret quan trọng nhất |
| Config và secret của database | `CONFIG_STORE` (ví dụ `update_url`) | Cao | URL nội bộ và thiết lập mở đường cho các đòn sau |
| Chức năng quản trị | `admin.php`, `partner_config.php` | Cao | Thao tác đặc quyền mà user thường không được chạm |
| Tích hợp cập nhật đối tác | luồng `check_updates` | Nghiêm trọng | Kéo và chạy một file bên ngoài, bàn đạp để thực thi code |
| Audit log | `AUDIT_LOGS` | Trung bình | Hữu ích cho attacker để giấu vết, và cũng lộ một mảnh flag |

---

## Challenge 1: Oracle UNION SQL injection

Trang search sinh viên (`search.php`) nhìn bình thường. Thử search một ngành có
thật thì nó trả về một bảng sinh viên:

![Tìm bình thường với "Software" trả về danh sách sinh viên]({{ '/images/oracle-sec-lab/01-search-normal.jpg' | relative_url }})

Phép thử đầu tiên là thêm một dấu nháy đơn. Gửi `?q='` thì trang trả về "Search
failed" thay vì kết quả, là lỗi đã được bắt chứ không phải stack trace:

![Một dấu nháy đơn làm hiện "Search failed. Please check your input."]({{ '/images/oracle-sec-lab/02-search-quote-error.jpg' | relative_url }})

Lỗi hiện ra khi chỉ thêm một dấu nháy chính là dấu hiệu: input đã chạm tới câu truy
vấn và làm hỏng cú pháp, nhưng app giấu chi tiết (blind SQLi). Nhìn cách search
hoạt động thì input đang được đưa vào một phép so khớp `LIKE '%...%'` nằm trong
ngoặc đơn, nên để chiếm câu truy vấn, ta đóng dấu nháy và ngoặc rồi comment phần
còn lại. Đoạn mở đầu là `KEYWORD%') ... --`.

Thử vài từ khóa thì thấy có một bộ lọc: các từ DDL như `DROP`, `UPDATE` bị chặn,
còn `UNION SELECT` đi lọt. Bộ lọc này kiểm tra chuỗi con (substring matching), nên
ngay cả tên cột vô hại như `update_url` cũng bị chặn do chứa từ khóa `UPDATE`. Chi
tiết này sẽ là chìa khóa ở Challenge 3.

`UNION` của Oracle yêu cầu hai vế cùng số cột và cùng kiểu, và mỗi `SELECT` đều cần
một `FROM` (đó là lúc dùng `DUAL`). Đoán `1,2,3` thì lỗi vì sai kiểu, nên ta đưa
chuỗi vào:

```sql
x%') UNION SELECT 1,'a','b' FROM DUAL--
```

`USER_TABLES` liệt kê các bảng trong schema:

```sql
x%') UNION SELECT ROWNUM, table_name, NULL FROM USER_TABLES WHERE ROWNUM<=14--
```

![UNION injection liệt kê các bảng của schema, gồm FLAGS và CONFIG_STORE]({{ '/images/oracle-sec-lab/03-union-tables.jpg' | relative_url }})

Vài cái tên đáng chú ý: `FLAGS`, `AUDIT_LOGS`, `CONFIG_STORE`, cùng vài decoy như
`FAKE_FLAGS` và `FLAG_ARCHIVE`. Dump bảng `FLAGS` chỉ ra một mảnh và một decoy:

```sql
x%') UNION SELECT 1, flag_code, flag_part FROM FLAGS--
```

![Bảng FLAGS cho ra một mảnh hex thật và một decoy base64]({{ '/images/oracle-sec-lab/04-flags-fragments.jpg' | relative_url }})

`FL1_PART_A` là hex (giải ra bắt đầu bằng `DBS401{SQL_`). `FL_DECOY_B` là base64
của `SOME_FAKE_FLAG_HERE`, bỏ qua. Hai mảnh thật còn lại nằm ở chỗ khác, mã hóa
kiểu khác:

- Mảnh B trong `AUDIT_LOGS.metadata_note`, một đoạn JSON viết ngược.
- Mảnh C trong `CONFIG_STORE` ở khóa `sys_alpha_marker`, base64.

```sql
x%') UNION SELECT 1, metadata_note, action FROM AUDIT_LOGS
     WHERE action='SYSTEM_AUDIT_CHECK'--

x%') UNION SELECT 1, config_value, config_key FROM CONFIG_STORE
     WHERE config_key='sys_alpha_marker'--
```

Giải từng mảnh (hex sang ASCII, đảo chuỗi, base64 sang ASCII) rồi ghép thành một
flag `DBS401{SQL_..._..._...}`. Trong `CONFIG_STORE` và `FLAGS` còn hai decoy
base64 nhằm đánh lạc hướng các công cụ quét tự động; giải mã ra một chuỗi đọc
được chưa chắc đó đã là flag thật.

---

## Challenge 2: số lượng âm, nhận credit miễn phí

Material Store (`store.php`) bán tài liệu ôn thi giá rẻ (100 credit) và một tài liệu
bị khóa, "Exam Leak 2024 (CLASSIFIED)", giá 999,999 credit. Tài khoản student của
ta có 150 credit, không đủ mua tài liệu "Exam Leak 2024":

![Store: 150 credit, một tài liệu rẻ, và một tài liệu khóa giá 999,999 credit]({{ '/images/oracle-sec-lab/06-store-before.jpg' | relative_url }})

Form đặt hàng có kiểm tra ta đủ credit không, nhưng không kiểm tra số lượng có phải
số dương. Đặt số lượng âm thì số dư lại tăng thay vì giảm, tức server đang tính
cost = qty × price rồi trừ vào credit. Đặt mua −10,000 cuốn tài liệu 100 credit:

```text
cost        = -10,000 * 100          = -1,000,000
new_credits =    150 - (-1,000,000)  =  1,000,150
```

Trừ một số âm chính là cộng vào. Số dư vượt mốc 999,999, tài liệu bị khóa mở ra kèm
flag:

![Sau khi đặt số lượng âm, credit nhảy lên 1,000,150 và flag mở khóa]({{ '/images/oracle-sec-lab/07-store-flag.jpg' | relative_url }})

Không cần kỹ thuật injection hay công cụ phức tạp, lỗ hổng xuất phát từ việc logic
kiểm tra dữ liệu đầu vào chưa bao quát trường hợp số âm.

---

## Challenge 3: từ broken access control thành supply-chain poisoning

Chức năng `check_updates` tìm được ở bước recon đọc một URL manifest đối tác, tải
JSON đó về, và nếu manifest khai version mới hơn thì xử lý payload. Đổi được URL đó
là ta khiến server admin tải đúng file ta muốn.

URL này là một dòng config riêng tư, không hiện trên giao diện. Ta đã có SQLi từ
Challenge 1 nên dump `CONFIG_STORE`. Không gọi được đích danh `update_url` (bộ lọc
chặn `UPDATE`), nên ta dump cả bảng rồi đọc dòng cần tìm:

```sql
x%') UNION SELECT 1, config_key, config_value FROM CONFIG_STORE
     WHERE config_key NOT LIKE 'runtime%'--
```

![SQLi lộ ra update_url riêng tư và app_version từ CONFIG_STORE]({{ '/images/oracle-sec-lab/05-config-recon.jpg' | relative_url }})

Server tải update từ `http://127.0.0.1:8081/manifest.json`, `app_version` hiện tại
là `3.1.0`. Muốn kích hoạt luồng update, manifest của ta phải khai version cao hơn.

Có một trang ẩn, `partner_config.php`, cho phép sửa URL đó. Nó gắn nhãn "ADMIN
ONLY", nhưng chỉ kiểm tra đã đăng nhập hay chưa, không kiểm tra quyền truy cập gì
thêm, nên một tài khoản student cũng mở được và sửa config của đối tác:

![Một sinh viên đã đăng nhập mở được trang cấu hình đối tác vốn chỉ dành cho admin]({{ '/images/oracle-sec-lab/08-partner-config-student.jpg' | relative_url }})

Ta trỏ URL sang một manifest của mình (trong lab là `demo.json`, version `9.9.9`
kèm `flag_part`). Lưu được luôn:

![Sinh viên ghi đè thành công URL manifest đối tác]({{ '/images/oracle-sec-lab/09-partner-poisoned.jpg' | relative_url }})

Quay lại admin, bấm check update: server tải manifest của ta, thấy `9.9.9 > 3.1.0`
nên tin, lấy `flag_part` từ file của ta, ghép với nửa còn lại ở server, rồi
hex-decode và in ra trang:

![Lần kiểm tra cập nhật của admin tải manifest độc hại và để lộ flag supply-chain]({{ '/images/oracle-sec-lab/10-admin-flag.jpg' | relative_url }})

"Update successful! System upgraded to version 9.9.9", flag hiện ra. Một tài khoản
student không có đặc quyền đã điều khiển được luồng thực thi trong vùng tin cậy của
admin. Bản chất tấn công chuỗi cung ứng (supply-chain) là vậy: thao túng một nguồn tài
nguyên mà mục tiêu vốn hoàn toàn tin tưởng để mục tiêu tự động nạp về.

---

## Challenge 4: PL/SQL injection qua EXECUTE IMMEDIATE

Trang tra cứu Course Info (`course_lookup.php`) nhận một mã môn. Mã bình thường trả
về tên môn bình thường:

![Tra cứu một mã môn bình thường trả về "Database Security"]({{ '/images/oracle-sec-lab/11-course-normal.jpg' | relative_url }})

Nhìn thì mã được truyền dưới dạng bind variable, lẽ ra an toàn. Nhưng inject vào
vẫn trả về dữ liệu, nên giá trị này chắc chắn bị đưa vào một câu SQL động sâu bên
trong: một stored function nối mã vào chuỗi rồi chạy bằng `EXECUTE IMMEDIATE`. Bind
ở chỗ gọi không cứu được gì khi điều đó xảy ra.

Hàm tra cứu trả về đúng một giá trị, nên câu inject phải trả về đúng một dòng.
Payload hiển nhiên trả về hai dòng, và hàm báo "Ambiguous result" (chính là
`TOO_MANY_ROWS` của Oracle):

```sql
zzz' UNION SELECT secret_flag FROM PLSQL_VAULT--
```

![Câu lệnh UNION cơ bản trả về hai dòng và lỗi "Ambiguous result"]({{ '/images/oracle-sec-lab/12-course-ambiguous.jpg' | relative_url }})

Lọc lại còn đúng một dòng thật thì flag hiện ra dưới dạng một tên môn:

```sql
zzz' UNION SELECT secret_flag FROM PLSQL_VAULT WHERE label='CHALLENGE_4'--
```

![Lọc còn một dòng, trích được Flag 4 qua PL/SQL injection]({{ '/images/oracle-sec-lab/13-course-flag.jpg' | relative_url }})

---

## Impact

Xếp mức độ nghiêm trọng cho từng lỗ hổng theo cách một báo cáo pentest hay chấm, lấy
khả năng khai thác nhân với mức ảnh hưởng:

| Lỗ hổng | Khả năng khai thác | Ảnh hưởng | Mức độ |
|---|---|---|---|
| UNION SQL injection | Cao, chỉ một dấu nháy là lọt | Đọc được cả database: dữ liệu sinh viên, config, secret | Nghiêm trọng |
| Lỗi số lượng âm | Cao, chỉ cần một số âm | Tự tạo credit, mở khóa tài liệu trong store | Cao |
| Broken access control + supply-chain | Trung bình, phải ghép SQLi với một trang ẩn | Ép server admin tải và chạy file của attacker | Nghiêm trọng |
| PL/SQL injection | Cao, inject qua ô tra cứu | Đọc được vault vốn nhìn thì an toàn | Cao |

## Remediation

Lỗ nào cũng có cách vá thẳng, xếp theo mức độ nặng.

| Lỗ hổng | Cách khắc phục |
|---|---|
| UNION SQL injection | Dùng bind variable cho mọi câu truy vấn, đừng bao giờ ghép SQL bằng cách nối chuỗi. Lọc input theo allow-list, và chạy app bằng account database quyền thấp nhất chứ không phải account đọc được mọi bảng. Bộ lọc chuỗi con ở đây không phải biện pháp phòng, nên bỏ. |
| Broken access control + supply-chain | Kiểm quyền ở server cho mọi thao tác đặc quyền, theo role chứ không chỉ "đã đăng nhập". Với luồng update, cố định nguồn, xác minh manifest bằng chữ ký hoặc checksum, và đừng tin số version do client kiểm soát. |
| PL/SQL injection | Giữ `EXECUTE IMMEDIATE` chạy trên bind variable, đừng nối input người dùng vào câu SQL động. Kiểm định danh bằng `DBMS_ASSERT`. |
| Lỗi số lượng âm | Kiểm số lượng ở server (số nguyên lớn hơn 0), và kiểm lại mọi quy tắc nghiệp vụ, như số dư, ở phía server trước khi chốt đơn. |

---

> Mã nguồn và hướng dẫn cài đặt: [github.com/Khanh1916/oracle-sec-lab](https://github.com/Khanh1916/oracle-sec-lab)


</div>

