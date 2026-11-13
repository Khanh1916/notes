---
layout: post
title: "OracleSecLab — four Oracle-flavoured web bugs, start to finish"
date: 2026-11-13
author: Nguyen Nam Khanh
tags: [oracle, sql-injection, plsql, business-logic, supply-chain, ctf, walkthrough]
description: >
  A hands-on walkthrough of OracleSecLab, an intentionally vulnerable Oracle +
  PHP student portal I built: UNION SQL injection, a negative-quantity logic
  flaw, a broken-access-control supply-chain chain, and PL/SQL injection through
  EXECUTE IMMEDIATE — each one explained, exploited, and then fixed.
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

> **Lab use only.** OracleSecLab is a *deliberately* vulnerable application I
> wrote for teaching database security. Everything below is done against my own
> copy running on `localhost` in Docker. The weaknesses are intentional — never
> point these techniques at systems you do not own or are not authorised to test.

Most "vulnerable web app" projects you meet while learning — DVWA, WebGoat,
Juice Shop — sit on MySQL, PostgreSQL or SQLite. Oracle is a different animal:
its own SQL dialect (`DUAL`, `ROWNUM`, `USER_TABLES`, `FETCH FIRST`), its own
PL/SQL stored-program model, and its own idioms for injection and enumeration.
So I built **[OracleSecLab](https://github.com/Khanh1916/oracle-sec-lab)** — a
realistic university portal ("FPT Student Portal") on
**Oracle 23c Free + PHP 8.3 + Apache**, with four intentional vulnerabilities
hidden among dozens of perfectly safe pages.

This post is the attacker's-eye walkthrough of all four. For each one I show the
recon, the working payload against the live app, *why* it works, and the fix
that lives in the repo's `secure_versions/`. It supersedes an older three-bug
walkthrough I wrote for the previous version of this app — the code has since
grown a fourth challenge (PL/SQL injection) and a lot more realism.

The four challenges:

| # | Vulnerability | Where | OWASP 2021 |
|---|---|---|---|
| 1 | Oracle UNION SQL injection (fragmented flag) | `search.php?q=` | A03 Injection |
| 2 | Business-logic flaw (negative quantity) | `store.php` | A04 Insecure Design |
| 3 | Broken access control → supply-chain poisoning | `partner_config.php` + `admin.php` | A01 / A06 |
| 4 | Oracle PL/SQL injection (`EXECUTE IMMEDIATE`) | `course_lookup.php` | A03 Injection |

---

## Run it yourself

The whole lab is one command. No manual Oracle install:

```bash
git clone https://github.com/Khanh1916/oracle-sec-lab.git
cd oracle-sec-lab
RANDOMIZE_FLAGS=1 docker compose up -d
```

Then open **http://localhost:8080/dbs401-oracle-app** and log in. The pre-seeded
accounts I use below:

| Username | Password | Role |
|---|---|---|
| `student1` | `Student@123` | Student (150 credits) |
| `admin` | `Admin@DBS401!2024` | Admin |

> **A note on the flags.** Every flag in this lab has the shape `DBS401{...}`.
> I ran my instance with `RANDOMIZE_FLAGS=1`, so each flag in the screenshots is
> a throwaway value unique to that container — not the canonical answer. That is
> deliberate: I want you to be able to follow the *method* without me handing you
> the final strings. Solve it on your own copy and you'll get your own flags.

Here's the portal after logging in as `student1` — a believable academic
dashboard. None of this UI matters to the bugs; it's camouflage.

![The FPT Student Portal dashboard after logging in as a student]({{ '/images/oracle-sec-lab/00-dashboard.jpg' | relative_url }})

---

## Challenge 1 — Oracle UNION SQL injection

### Find the injection point

The **Student Search** page (`search.php`) looks ordinary. Search for a real
major and you get a tidy table of students:

![A normal search for "Software" returning student rows]({{ '/images/oracle-sec-lab/01-search-normal.jpg' | relative_url }})

The classic first probe for SQL injection is a single quote. Send `?q='` and the
page breaks — but gracefully, with a caught error rather than a stack trace:

![A single quote triggers "Search failed. Please check your input."]({{ '/images/oracle-sec-lab/02-search-quote-error.jpg' | relative_url }})

That "Search failed" is the tell. The quote reached the database and broke the
query's syntax. Under the hood, `search.php` builds its SQL by gluing the input
straight into the string:

```php
$sql = "SELECT student_id, full_name, major FROM STUDENTS
        WHERE (full_name LIKE '%$keyword%' OR major LIKE '%$keyword%')
          AND hidden_marker = 'NORMAL' AND ROWNUM <= 5";
```

Our input lands *inside* a `LIKE '%...%'` literal, which itself sits inside
parentheses. So to take over the query we have to (a) close the `%` and the
quote, (b) close the parenthesis, and (c) comment out everything after us. The
breakout prefix is therefore `KEYWORD%') ... --`.

### Mind the keyword blacklist

There is one speed bump: a blacklist that rejects DDL-flavoured words.

```php
$ddlBlacklist = ['DROP','DELETE','UPDATE','INSERT','CREATE','ALTER','TRUNCATE'];
```

`UNION SELECT` isn't on the list, so plain read injection sails through. But note
the trap for later: the check is a case-insensitive substring match, so the
literal text `update_url` (it contains **UPDATE**) is blocked. Keep that in mind
for Challenge 3.

### Column count and types

Oracle `UNION` demands the same column count *and* compatible types on both
sides, and every `SELECT` needs a `FROM` (that's what `DUAL` is for). A naive
`UNION SELECT 1,2,3 FROM DUAL` actually fails here, because columns 2 and 3 are
`VARCHAR2` on the left and numbers on the right — Oracle is strict about that.
Give it strings and it lines up:

```sql
-- three columns: NUMBER, VARCHAR2, VARCHAR2
x%') UNION SELECT 1,'a','b' FROM DUAL--
```

### Enumerate the tables

`USER_TABLES` lists every table the app's schema owns. We put `table_name` in one
of the string columns:

```sql
x%') UNION SELECT ROWNUM, table_name, NULL FROM USER_TABLES WHERE ROWNUM<=14--
```

![UNION injection listing the schema's tables, including FLAGS and CONFIG_STORE]({{ '/images/oracle-sec-lab/03-union-tables.jpg' | relative_url }})

Interesting names jump out: `FLAGS`, `AUDIT_LOGS`, `CONFIG_STORE`,
`ADMIN_SECRETS`, `SYSTEM_HINTS`, and some obvious bait — `FAKE_FLAGS`,
`FLAG_ARCHIVE`. The lab is full of decoys to punish anyone who just greps for the
word "flag".

### The flag is in three pieces, three encodings

Dumping `FLAGS` doesn't give you a flag — it gives you a *fragment*, plus a
decoy:

```sql
x%') UNION SELECT 1, flag_code, flag_part FROM FLAGS--
```

![The FLAGS table yields one real hex fragment and one base64 decoy]({{ '/images/oracle-sec-lab/04-flags-fragments.jpg' | relative_url }})

`FL1_PART_A` is a run of hex (`4442...` → decode as hex bytes → it starts
`DBS401{SQL_`). `FL_DECOY_B` is base64 that cheerfully decodes to
`SOME_FAKE_FLAG_HERE` — ignore it. Two more real pieces are hidden elsewhere, in
*different* encodings, which is the whole point of the challenge:

- **Part B** lives in `AUDIT_LOGS.metadata_note` as a JSON blob with a
  `"fragment"` field that is written **backwards** — reverse it to read it.
- **Part C** lives in `CONFIG_STORE` under `sys_alpha_marker`, **base64**-encoded.

```sql
-- Part B
x%') UNION SELECT 1, metadata_note, action FROM AUDIT_LOGS
     WHERE action='SYSTEM_AUDIT_CHECK'--

-- Part C
x%') UNION SELECT 1, config_value, config_key FROM CONFIG_STORE
     WHERE config_key='sys_alpha_marker'--
```

Decode each piece (hex → ASCII, reverse the string, base64 → ASCII) and
concatenate. The three parts snap together into a single `DBS401{SQL_..._..._...}`
flag. There are also two base64 *decoys* sitting in `CONFIG_STORE`
(`sys_beta_marker`) and `FLAGS` to waste an automated scanner's time — a reminder
that "it decodes cleanly" is not the same as "it's correct".

### The fix

Stop concatenating. Bind the parameter and constrain the input:

```php
$param = '%' . strtolower($keyword) . '%';
$sql   = "SELECT student_id, full_name, major FROM STUDENTS
          WHERE LOWER(full_name) LIKE :kw";
$stmt  = oci_parse($conn, $sql);
oci_bind_by_name($stmt, ':kw', $param);
oci_execute($stmt);
```

A blacklist is not a defence — it's a to-do list for the attacker. Bind
variables are. (See `secure_versions/search_secure.php`.)

---

## Challenge 2 — a negative quantity is free money

The **Material Store** (`store.php`) sells a cheap study guide (100 credits) and
one tantalising locked item, *"Exam Leak 2024 (CLASSIFIED)"*, for 999,999
credits. Our student has 150. Hopeless — at first glance.

![The store: 150 credits, a cheap item, and a locked 999,999-credit item]({{ '/images/oracle-sec-lab/06-store-before.jpg' | relative_url }})

The server checks that you can afford the order, but never checks that the
quantity is positive:

```php
$cost = $qty * $price;            // qty comes straight from the form
if ($credits >= $cost) {
    $newCredits = $credits - $cost;   // subtract a negative = add
}
```

Order **−10,000** of the 100-credit guide and the arithmetic inverts:

```text
cost        = -10,000 * 100          = -1,000,000
new_credits =    150 - (-1,000,000)  =  1,000,150
```

Subtracting a negative number *adds* it. The balance rockets past 999,999, and
the classified item unlocks on the spot:

![After ordering a negative quantity, credits jump to 1,000,150 and the flag unlocks]({{ '/images/oracle-sec-lab/07-store-flag.jpg' | relative_url }})

No injection, no special tooling — just an input the designer never imagined.
This is why it maps to A04, *Insecure Design*: the code does exactly what it was
written to do.

### The fix

Validate the boundary server-side, every time:

```php
if ($qty <= 0 || $qty > 100) {
    $msg = "Quantity must be between 1 and 100.";
} elseif ($credits < $cost) {
    $msg = "Insufficient credits.";
} else {
    $newCredits = $credits - $cost;
}
```

Client-side `min="1"` on the input is cosmetic; the attacker never uses your
form. (See `secure_versions/store_secure.php`.)

---

## Challenge 3 — broken access control into a supply-chain poison

This one is a chain. The admin panel can "check for updates": it reads a partner
**manifest URL** from the database, fetches that JSON, and if the manifest
advertises a newer version it processes the payload. Poison the URL and you
control what the admin's server fetches.

### Recon: find the hidden config

The admin panel only shows *public* config rows. The juicy one —
`update_url` — is marked private, so it never appears in the UI. But we already
have SQL injection from Challenge 1, so we dump `CONFIG_STORE` directly.

Here's the blacklist biting us: a payload containing the text `update_url` is
rejected (it contains "UPDATE"). The workaround is simply **not to name it** —
dump the whole table and read the row from the results:

```sql
x%') UNION SELECT 1, config_key, config_value FROM CONFIG_STORE
     WHERE config_key NOT LIKE 'runtime%'--
```

![SQLi reveals the private update_url and the app_version from CONFIG_STORE]({{ '/images/oracle-sec-lab/05-config-recon.jpg' | relative_url }})

Now we know the server fetches updates from
`http://127.0.0.1:8081/manifest.json` and that the current `app_version` is
`3.1.0`. To trigger the update path, our manifest must claim a *higher* version.

### Broken access control: the config page trusts anyone

There's a hidden page, `partner_config.php`, that lets you change that URL. It's
labelled **"ADMIN ONLY"** — but the label is the only thing guarding it. The
code checks that you're logged in, and nothing more. So an ordinary student
walks right in and edits partner infrastructure:

![A logged-in student can open the admin-only partner configuration page]({{ '/images/oracle-sec-lab/08-partner-config-student.jpg' | relative_url }})

We point the manifest URL at a payload of our choosing. (In a real engagement
you'd host this on your own box; in the lab I serve a second manifest,
`demo.json`, that claims version `9.9.9` and carries the expected `flag_part`.)
The student's save succeeds — access control simply isn't enforced:

![The student successfully overwrites the partner manifest URL]({{ '/images/oracle-sec-lab/09-partner-poisoned.jpg' | relative_url }})

### Spring the trap as admin

Now the admin "checks for updates" (`admin.php?check_updates=1`). The server
fetches our poisoned manifest, sees `9.9.9 > 3.1.0`, trusts it, takes the
`flag_part` hex from *our* file, combines it with a server-side secret half, and
hex-decodes the result straight onto the page:

![The admin update check fetches the poisoned manifest and reveals the supply-chain flag]({{ '/images/oracle-sec-lab/10-admin-flag.jpg' | relative_url }})

"Update successful! System upgraded to version 9.9.9" — and out drops the flag.
One student with no privileges got code/data of their choosing executed in the
admin's trust context. That's the shape of a real supply-chain attack: you don't
breach the target, you breach something the target *trusts*.

### The fix

Three independent failures, three fixes:

1. **Enforce the role.** `partner_config.php` must check
   `$_SESSION['role'] === 'admin'` before writing anything.
2. **Allowlist the origin.** The update URL should be validated against a short
   list of approved hosts, not accepted as free text.
3. **Verify a signature.** Sign manifests (HMAC/RSA) and reject anything that
   doesn't verify — a higher version number is not proof of authenticity.

(See `secure_versions/partner_config_secure.php` and `admin_update_secure.php`.)

---

## Challenge 4 — PL/SQL injection through EXECUTE IMMEDIATE

The last one is the most Oracle-specific, and my favourite, because it looks
*safe*. The **Course Info** lookup (`course_lookup.php`) passes the course code
as a **bind variable**:

```php
$sql = "SELECT FN_COURSE_LOOKUP(:code) AS info FROM DUAL";
oci_bind_by_name($stmt, ':code', $code);   // textbook-correct, right?
```

Any scanner that only looks at the PHP will call this clean. A normal code
returns a normal course name:

![A normal course-code lookup returns "Database Security"]({{ '/images/oracle-sec-lab/11-course-normal.jpg' | relative_url }})

But binding at the call site doesn't help if the *stored function* is the thing
that's vulnerable. Look inside `FN_COURSE_LOOKUP`:

```sql
v_sql := 'SELECT course_name FROM COURSES WHERE course_code = ''' || p_code || '''';
EXECUTE IMMEDIATE v_sql INTO v_result;
```

The bound value arrives safely in PL/SQL — and then the function rebuilds a SQL
string by concatenation and runs it with `EXECUTE IMMEDIATE`. The injection
happens *inside the database*, one layer below where PHP "protected" it. This is
the key lesson: **a bind variable only protects the statement it's bound to.**

### The single-row trap

The function returns one value via `... INTO v_result`, so your injected query
must return **exactly one row**. The flag lives in a `PLSQL_VAULT` table that
also holds a decoy row, so the obvious payload returns two rows and Oracle
raises `TOO_MANY_ROWS`, which the function reports as "Ambiguous result":

```sql
zzz' UNION SELECT secret_flag FROM PLSQL_VAULT--
```

![The naive UNION returns two rows and fails with "Ambiguous result"]({{ '/images/oracle-sec-lab/12-course-ambiguous.jpg' | relative_url }})

Filter down to the single real row and the flag comes back dressed up as a
course name:

```sql
zzz' UNION SELECT secret_flag FROM PLSQL_VAULT WHERE label='CHALLENGE_4'--
```

![Filtering to one row extracts Flag 4 through the PL/SQL injection]({{ '/images/oracle-sec-lab/13-course-flag.jpg' | relative_url }})

### The fix

Fix the stored program, not just the call site. Prefer static SQL with no
dynamic string at all:

```sql
SELECT course_name INTO v_result FROM COURSES WHERE course_code = p_code;
```

If you genuinely need dynamic SQL, **bind** inside `EXECUTE IMMEDIATE` too, and
never concatenate user input:

```sql
EXECUTE IMMEDIATE 'SELECT course_name FROM COURSES WHERE course_code = :c'
  INTO v_result USING p_code;
```

And run the function with **invoker's rights** (`AUTHID CURRENT_USER`) so the web
role can't reach tables like `PLSQL_VAULT` through it. (See
`secure_versions/course_lookup_secure.php`.)

---

## What the lab is really teaching

Four bugs, four different root causes — and not one of them is exotic:

- **Challenge 1 — trust in a blacklist.** String-built SQL plus a keyword
  denylist is injection waiting to happen. Bind variables, not blocklists.
- **Challenge 2 — trust in the client.** The browser form said "1 or more"; the
  attacker said "−10,000". Validate every boundary on the server.
- **Challenge 3 — trust in a label and a version number.** An "ADMIN ONLY"
  banner is not access control, and a bigger version is not a signature. Enforce
  roles, allowlist origins, verify payloads.
- **Challenge 4 — trust in the wrong layer.** A bind variable at the PHP boundary
  is worthless if the stored function concatenates and `EXECUTE IMMEDIATE`s. Fix
  the code that actually builds the query.

Every finding has a matching hardened version in the repo's `secure_versions/`,
so you can diff the vulnerable and the safe implementation side by side. If you
want to try it cold, grab the lab and solve it before re-reading this — the flags
in your container will be yours alone.

> Source and full setup: **[github.com/Khanh1916/oracle-sec-lab](https://github.com/Khanh1916/oracle-sec-lab)**

---

*Written by **Nguyen Nam Khanh** ([@Khanh1916](https://github.com/Khanh1916)).*

</div>

<div class="lang-vi" markdown="1">

> **Chỉ dùng trong lab.** OracleSecLab là ứng dụng *cố ý* cài lỗ hổng mà tôi
> viết để dạy về an toàn cơ sở dữ liệu. Mọi thao tác bên dưới đều chạy trên bản
> của chính tôi, ở `localhost` trong Docker. Các điểm yếu đều là có chủ đích —
> đừng bao giờ nhắm những kỹ thuật này vào hệ thống bạn không sở hữu hoặc chưa
> được phép kiểm thử.

Hầu hết các dự án "web app có lỗ hổng" mà người mới hay gặp — DVWA, WebGoat,
Juice Shop — đều chạy trên MySQL, PostgreSQL hoặc SQLite. Oracle thì khác hẳn:
một phương ngữ SQL riêng (`DUAL`, `ROWNUM`, `USER_TABLES`, `FETCH FIRST`), mô
hình stored-program PL/SQL riêng, và những lối injection, enumeration rất riêng.
Vì vậy tôi dựng **[OracleSecLab](https://github.com/Khanh1916/oracle-sec-lab)** —
một cổng thông tin sinh viên sát thực tế ("FPT Student Portal") chạy trên
**Oracle 23c Free + PHP 8.3 + Apache**, với bốn lỗ hổng cố ý giấu lẫn giữa hàng
chục trang hoàn toàn lành tính.

Bài này là walkthrough nhìn từ phía người tấn công cho cả bốn lỗ. Với mỗi lỗ tôi
sẽ đi qua phần recon, payload chạy thật trên app, giải thích *vì sao* nó ăn, và
bản vá tương ứng trong thư mục `secure_versions/` của repo. Bài này thay cho một
walkthrough ba lỗ cũ tôi viết cho phiên bản trước của app — kể từ đó code đã có
thêm thử thách thứ tư (PL/SQL injection) và được làm cho giống thật hơn nhiều.

Bốn thử thách:

| # | Lỗ hổng | Ở đâu | OWASP 2021 |
|---|---|---|---|
| 1 | Oracle UNION SQL injection (flag chia mảnh) | `search.php?q=` | A03 Injection |
| 2 | Lỗi logic nghiệp vụ (số lượng âm) | `store.php` | A04 Insecure Design |
| 3 | Broken access control → đầu độc supply-chain | `partner_config.php` + `admin.php` | A01 / A06 |
| 4 | Oracle PL/SQL injection (`EXECUTE IMMEDIATE`) | `course_lookup.php` | A03 Injection |

---

## Tự dựng mà chơi

Cả cái lab gói gọn trong một câu lệnh, khỏi phải cài Oracle thủ công:

```bash
git clone https://github.com/Khanh1916/oracle-sec-lab.git
cd oracle-sec-lab
RANDOMIZE_FLAGS=1 docker compose up -d
```

Xong thì mở **http://localhost:8080/dbs401-oracle-app** và đăng nhập. Hai tài
khoản đã seed sẵn mà tôi dùng ở dưới:

| Tài khoản | Mật khẩu | Vai trò |
|---|---|---|
| `student1` | `Student@123` | Sinh viên (150 credit) |
| `admin` | `Admin@DBS401!2024` | Admin |

> **Nói trước về flag.** Flag nào trong lab cũng có dạng `DBS401{...}`. Tôi chạy
> bản của mình với `RANDOMIZE_FLAGS=1`, nên mỗi flag xuất hiện trong ảnh chụp chỉ
> là một giá trị dùng một lần, riêng cho container đó — không phải đáp án chuẩn.
> Đây là cố ý: tôi muốn bạn nắm được *cách làm* chứ không phải chép sẵn chuỗi
> cuối cùng. Cứ tự giải trên bản của bạn, flag sẽ là của riêng bạn.

Đây là cổng thông tin sau khi đăng nhập bằng `student1` — một dashboard học vụ
trông y như thật. Toàn bộ giao diện này chẳng dính dáng gì đến các lỗ hổng; nó
chỉ là lớp ngụy trang.

![Dashboard của FPT Student Portal sau khi đăng nhập bằng tài khoản sinh viên]({{ '/images/oracle-sec-lab/00-dashboard.jpg' | relative_url }})

---

## Thử thách 1 — Oracle UNION SQL injection

### Tìm điểm injection

Trang **Student Search** (`search.php`) trông rất đỗi bình thường. Gõ một chuyên
ngành có thật là bạn nhận về một bảng sinh viên gọn gàng:

![Tìm bình thường với "Software" trả về danh sách sinh viên]({{ '/images/oracle-sec-lab/01-search-normal.jpg' | relative_url }})

Phát thăm dò SQL injection kinh điển nhất là một dấu nháy đơn. Gửi `?q='`, trang
vỡ ngay — nhưng vỡ có kiểm soát, báo lỗi đã bắt được chứ không phun ra stack
trace:

![Một dấu nháy đơn làm hiện "Search failed. Please check your input."]({{ '/images/oracle-sec-lab/02-search-quote-error.jpg' | relative_url }})

Dòng "Search failed" chính là dấu hiệu. Dấu nháy đã lọt xuống database và phá vỡ
cú pháp câu truy vấn. Bên dưới, `search.php` ghép SQL bằng cách dán thẳng input
vào chuỗi:

```php
$sql = "SELECT student_id, full_name, major FROM STUDENTS
        WHERE (full_name LIKE '%$keyword%' OR major LIKE '%$keyword%')
          AND hidden_marker = 'NORMAL' AND ROWNUM <= 5";
```

Input của ta rơi vào *bên trong* một literal `LIKE '%...%'`, mà literal này lại
nằm trong cặp ngoặc đơn. Muốn chiếm quyền câu truy vấn, ta phải (a) đóng dấu `%`
và dấu nháy, (b) đóng ngoặc đơn, rồi (c) comment bỏ phần còn lại phía sau. Tóm
lại, phần đầu để thoát ra là `KEYWORD%') ... --`.

### Coi chừng cái blacklist từ khóa

Có một chướng ngại nhỏ: một blacklist chặn những từ nặng mùi DDL.

```php
$ddlBlacklist = ['DROP','DELETE','UPDATE','INSERT','CREATE','ALTER','TRUNCATE'];
```

`UNION SELECT` không nằm trong danh sách, nên injection kiểu đọc dữ liệu đi lọt
ngon lành. Nhưng để ý cái bẫy dành cho phần sau: nó so khớp theo chuỗi con và
không phân biệt hoa thường, nên riêng chữ `update_url` (vì có **UPDATE** bên
trong) sẽ bị chặn. Nhớ chi tiết này cho Thử thách 3.

### Số cột và kiểu dữ liệu

`UNION` của Oracle bắt hai vế phải cùng số cột *và* kiểu tương thích, và mỗi
`SELECT` đều cần một `FROM` (đó là lúc `DUAL` xuất hiện). Payload ngây thơ
`UNION SELECT 1,2,3 FROM DUAL` thực ra lỗi ở đây, vì cột 2 và 3 bên trái là
`VARCHAR2` còn bên phải lại là số — khoản này Oracle khó tính lắm. Thay bằng
chuỗi là khớp ngay:

```sql
-- ba cột: NUMBER, VARCHAR2, VARCHAR2
x%') UNION SELECT 1,'a','b' FROM DUAL--
```

### Liệt kê các bảng

`USER_TABLES` liệt kê mọi bảng thuộc schema của app. Ta nhét `table_name` vào một
trong hai cột kiểu chuỗi:

```sql
x%') UNION SELECT ROWNUM, table_name, NULL FROM USER_TABLES WHERE ROWNUM<=14--
```

![UNION injection liệt kê các bảng của schema, gồm FLAGS và CONFIG_STORE]({{ '/images/oracle-sec-lab/03-union-tables.jpg' | relative_url }})

Mấy cái tên đáng chú ý lộ ra ngay: `FLAGS`, `AUDIT_LOGS`, `CONFIG_STORE`,
`ADMIN_SECRETS`, `SYSTEM_HINTS`, cùng vài mồi nhử lộ liễu — `FAKE_FLAGS`,
`FLAG_ARCHIVE`. Lab cài đầy decoy để phạt những ai chỉ quen grep mỗi chữ "flag".

### Flag gồm ba mảnh, ba kiểu mã hóa

Dump bảng `FLAGS` không cho bạn nguyên một flag — nó chỉ cho một *mảnh*, kèm thêm
một mồi nhử:

```sql
x%') UNION SELECT 1, flag_code, flag_part FROM FLAGS--
```

![Bảng FLAGS cho ra một mảnh hex thật và một decoy base64]({{ '/images/oracle-sec-lab/04-flags-fragments.jpg' | relative_url }})

`FL1_PART_A` là một chuỗi hex (`4442...` → giải theo byte hex → mở đầu bằng
`DBS401{SQL_`). Còn `FL_DECOY_B` là base64, giải ra tỉnh bơ thành
`SOME_FAKE_FLAG_HERE` — kệ nó. Hai mảnh thật còn lại nằm ở chỗ khác, với các kiểu
mã hóa *khác nhau*, và đó mới là cái cốt của thử thách:

- **Mảnh B** nằm ở `AUDIT_LOGS.metadata_note`, dưới dạng một khối JSON có trường
  `"fragment"` được viết **ngược** — đảo chuỗi lại là đọc được.
- **Mảnh C** nằm trong `CONFIG_STORE` ở khóa `sys_alpha_marker`, mã hóa
  **base64**.

```sql
-- Mảnh B
x%') UNION SELECT 1, metadata_note, action FROM AUDIT_LOGS
     WHERE action='SYSTEM_AUDIT_CHECK'--

-- Mảnh C
x%') UNION SELECT 1, config_value, config_key FROM CONFIG_STORE
     WHERE config_key='sys_alpha_marker'--
```

Giải từng mảnh (hex → ASCII, đảo ngược chuỗi, base64 → ASCII) rồi ghép lại. Ba
mảnh khớp vào nhau thành đúng một flag `DBS401{SQL_..._..._...}`. Ngoài ra còn
hai decoy base64 nằm ở `CONFIG_STORE` (`sys_beta_marker`) và `FLAGS` để ngốn thời
gian của scanner tự động — một lời nhắc rằng "giải ra sạch đẹp" không có nghĩa là
"đúng".

### Bản vá

Ngừng nối chuỗi. Bind tham số và ràng buộc input:

```php
$param = '%' . strtolower($keyword) . '%';
$sql   = "SELECT student_id, full_name, major FROM STUDENTS
          WHERE LOWER(full_name) LIKE :kw";
$stmt  = oci_parse($conn, $sql);
oci_bind_by_name($stmt, ':kw', $param);
oci_execute($stmt);
```

Blacklist không phải là phòng thủ — nó là bản danh sách việc-cần-thử cho kẻ tấn
công. Bind variable mới là phòng thủ. (Xem `secure_versions/search_secure.php`.)

---

## Thử thách 2 — số lượng âm hóa ra là tiền chùa

**Material Store** (`store.php`) bán một cuốn tài liệu ôn thi rẻ tiền (100
credit) và một món bị khóa đầy mời gọi, *"Exam Leak 2024 (CLASSIFIED)"*, giá
999,999 credit. Sinh viên của ta có 150. Thoạt nhìn thì hết cửa.

![Store: 150 credit, một món rẻ, và một món khóa giá 999,999 credit]({{ '/images/oracle-sec-lab/06-store-before.jpg' | relative_url }})

Server có kiểm tra xem bạn đủ tiền trả cho đơn hàng không, nhưng tuyệt nhiên
không kiểm tra số lượng có phải số dương:

```php
$cost = $qty * $price;            // qty lấy thẳng từ form
if ($credits >= $cost) {
    $newCredits = $credits - $cost;   // trừ một số âm = cộng
}
```

Đặt mua **−10,000** cuốn tài liệu giá 100 credit, phép tính lập tức đảo chiều:

```text
cost        = -10,000 * 100          = -1,000,000
new_credits =    150 - (-1,000,000)  =  1,000,150
```

Trừ đi một số âm tức là *cộng* nó vào. Số dư vọt qua mốc 999,999, và món tài liệu
bị khóa mở ra ngay lập tức:

![Sau khi đặt số lượng âm, credit nhảy lên 1,000,150 và flag mở khóa]({{ '/images/oracle-sec-lab/07-store-flag.jpg' | relative_url }})

Không injection, không công cụ gì ghê gớm — chỉ là một input mà người thiết kế
chưa bao giờ nghĩ tới. Đó là lý do nó thuộc A04, *Insecure Design*: đoạn code làm
đúng chính xác những gì nó được viết ra để làm.

### Bản vá

Kiểm tra giá trị biên ở phía server, lần nào cũng vậy:

```php
if ($qty <= 0 || $qty > 100) {
    $msg = "Quantity must be between 1 and 100.";
} elseif ($credits < $cost) {
    $msg = "Insufficient credits.";
} else {
    $newCredits = $credits - $cost;
}
```

Cái `min="1"` trên ô input phía client chỉ để làm cảnh; kẻ tấn công có bao giờ
dùng form của bạn đâu. (Xem `secure_versions/store_secure.php`.)

---

## Thử thách 3 — từ broken access control đến đầu độc supply-chain

Lỗ này là cả một chuỗi. Trang admin có nút "kiểm tra cập nhật": nó đọc một **URL
manifest đối tác** từ database, tải JSON đó về, và nếu manifest khai một phiên
bản mới hơn thì xử lý luôn payload. Đầu độc được cái URL đó là bạn nắm quyền
quyết định server của admin sẽ tải về thứ gì.

### Recon: moi cấu hình ẩn

Trang admin chỉ hiện những dòng cấu hình *công khai*. Dòng ngon nhất —
`update_url` — bị đánh dấu riêng tư nên không bao giờ ló lên giao diện. Nhưng ta
đã có sẵn SQL injection từ Thử thách 1, nên cứ dump thẳng `CONFIG_STORE`.

Và đây là lúc cái blacklist quay ra cắn ta: payload chứa chữ `update_url` sẽ bị
chặn (vì có "UPDATE"). Cách lách đơn giản là **đừng gọi đích danh nó** — dump cả
bảng rồi tự đọc dòng cần tìm trong kết quả:

```sql
x%') UNION SELECT 1, config_key, config_value FROM CONFIG_STORE
     WHERE config_key NOT LIKE 'runtime%'--
```

![SQLi lộ ra update_url riêng tư và app_version từ CONFIG_STORE]({{ '/images/oracle-sec-lab/05-config-recon.jpg' | relative_url }})

Giờ ta biết server tải cập nhật từ `http://127.0.0.1:8081/manifest.json`, và
`app_version` hiện tại là `3.1.0`. Muốn kích hoạt luồng cập nhật, manifest của ta
phải khai một phiên bản *cao hơn*.

### Broken access control: trang cấu hình tin tưởng mọi người

Có một trang ẩn, `partner_config.php`, cho phép sửa cái URL đó. Nó dán nhãn
**"ADMIN ONLY"** — nhưng cái nhãn là thứ duy nhất canh cửa. Code chỉ kiểm tra xem
bạn đã đăng nhập hay chưa, hết. Thế là một sinh viên quèn ung dung đi vào và
chỉnh sửa hạ tầng của đối tác:

![Một sinh viên đã đăng nhập mở được trang cấu hình đối tác vốn chỉ dành cho admin]({{ '/images/oracle-sec-lab/08-partner-config-student.jpg' | relative_url }})

Ta trỏ URL manifest sang một payload do mình chọn. (Trong một kỳ đánh giá thật,
bạn sẽ tự host nó trên máy mình; còn trong lab tôi dựng sẵn một manifest thứ hai,
`demo.json`, khai phiên bản `9.9.9` và kèm sẵn `flag_part` cần thiết.) Sinh viên
lưu thành công — kiểm soát truy cập đơn giản là không hề được thực thi:

![Sinh viên ghi đè thành công URL manifest đối tác]({{ '/images/oracle-sec-lab/09-partner-poisoned.jpg' | relative_url }})

### Sập bẫy khi vào vai admin

Giờ admin bấm "kiểm tra cập nhật" (`admin.php?check_updates=1`). Server tải về
manifest đã bị ta đầu độc, thấy `9.9.9 > 3.1.0`, tin ngay, lấy chuỗi hex
`flag_part` từ file của *ta*, ghép với nửa bí mật nằm sẵn ở server, rồi hex-decode
kết quả in thẳng ra trang:

![Lần kiểm tra cập nhật của admin tải manifest độc hại và để lộ flag supply-chain]({{ '/images/oracle-sec-lab/10-admin-flag.jpg' | relative_url }})

"Update successful! System upgraded to version 9.9.9" — và flag rơi ra. Một sinh
viên không quyền hành gì đã khiến code/dữ liệu do mình chọn được chạy trong vùng
tin cậy của admin. Đó đúng là dáng dấp của một vụ tấn công supply-chain thật: bạn
không chọc thủng mục tiêu, bạn chọc thủng thứ mà mục tiêu *đặt niềm tin vào*.

### Bản vá

Ba điểm hỏng độc lập, ba bản vá:

1. **Thực thi phân quyền.** `partner_config.php` phải kiểm tra
   `$_SESSION['role'] === 'admin'` trước khi ghi bất cứ thứ gì.
2. **Allowlist nguồn gốc.** URL cập nhật phải được đối chiếu với một danh sách
   ngắn các host đã duyệt, chứ không nhận bừa chuỗi tự do.
3. **Xác minh chữ ký.** Hãy ký manifest (HMAC/RSA) và từ chối mọi thứ không xác
   minh được — số phiên bản cao hơn không phải là bằng chứng về tính xác thực.

(Xem `secure_versions/partner_config_secure.php` và `admin_update_secure.php`.)

---

## Thử thách 4 — PL/SQL injection qua EXECUTE IMMEDIATE

Lỗ cuối cùng là lỗ "Oracle" nhất, cũng là lỗ tôi khoái nhất, bởi trông nó *an
toàn* đến lạ. Trang tra cứu **Course Info** (`course_lookup.php`) truyền mã môn
học dưới dạng một **bind variable**:

```php
$sql = "SELECT FN_COURSE_LOOKUP(:code) AS info FROM DUAL";
oci_bind_by_name($stmt, ':code', $code);   // chuẩn sách giáo khoa còn gì?
```

Mọi scanner chỉ nhìn phần PHP đều sẽ chấm đoạn này là sạch. Một mã bình thường
trả về một tên môn bình thường:

![Tra cứu một mã môn bình thường trả về "Database Security"]({{ '/images/oracle-sec-lab/11-course-normal.jpg' | relative_url }})

Nhưng bind ở điểm gọi chẳng cứu được gì nếu bản thân *stored function* mới là chỗ
dính lỗi. Thử ngó vào trong `FN_COURSE_LOOKUP`:

```sql
v_sql := 'SELECT course_name FROM COURSES WHERE course_code = ''' || p_code || '''';
EXECUTE IMMEDIATE v_sql INTO v_result;
```

Giá trị được bind về đến PL/SQL an toàn — rồi function lại tự tay ghép một chuỗi
SQL bằng phép nối và chạy nó qua `EXECUTE IMMEDIATE`. Injection xảy ra *ngay bên
trong database*, thấp hơn một tầng so với chỗ mà PHP tưởng mình đã "bảo vệ". Đây
là bài học cốt lõi: **bind variable chỉ bảo vệ đúng câu lệnh mà nó được gắn
vào.**

### Cái bẫy một dòng

Function trả về một giá trị qua `... INTO v_result`, nên câu truy vấn bạn chèn
vào phải trả về **đúng một dòng**. Flag nằm trong bảng `PLSQL_VAULT`, mà bảng này
còn có thêm một dòng decoy, nên payload hiển nhiên sẽ trả về hai dòng và Oracle
ném ra `TOO_MANY_ROWS`, được function báo lại thành "Ambiguous result":

```sql
zzz' UNION SELECT secret_flag FROM PLSQL_VAULT--
```

![UNION ngây thơ trả về hai dòng và lỗi "Ambiguous result"]({{ '/images/oracle-sec-lab/12-course-ambiguous.jpg' | relative_url }})

Lọc lại còn đúng một dòng thật là flag hiện về, cải trang thành một cái tên môn
học:

```sql
zzz' UNION SELECT secret_flag FROM PLSQL_VAULT WHERE label='CHALLENGE_4'--
```

![Lọc còn một dòng, trích được Flag 4 qua PL/SQL injection]({{ '/images/oracle-sec-lab/13-course-flag.jpg' | relative_url }})

### Bản vá

Vá cái stored program, chứ đừng chỉ vá điểm gọi. Ưu tiên SQL tĩnh, không chuỗi
động nào hết:

```sql
SELECT course_name INTO v_result FROM COURSES WHERE course_code = p_code;
```

Nếu thật sự cần SQL động, hãy **bind** cả bên trong `EXECUTE IMMEDIATE`, và tuyệt
đối không nối chuỗi input người dùng:

```sql
EXECUTE IMMEDIATE 'SELECT course_name FROM COURSES WHERE course_code = :c'
  INTO v_result USING p_code;
```

Và cho function chạy bằng **quyền của người gọi** (`AUTHID CURRENT_USER`) để role
của web không thể với tới những bảng như `PLSQL_VAULT` thông qua nó. (Xem
`secure_versions/course_lookup_secure.php`.)

---

## Rốt cuộc lab này dạy điều gì

Bốn lỗ, bốn nguyên nhân gốc khác nhau — mà chẳng cái nào cao siêu cả:

- **Thử thách 1 — tin vào blacklist.** SQL ghép bằng chuỗi cộng thêm một denylist
  từ khóa là injection sớm muộn cũng xảy ra. Hãy dùng bind variable, đừng dùng
  blocklist.
- **Thử thách 2 — tin vào client.** Form trên trình duyệt ghi "từ 1 trở lên"; kẻ
  tấn công gõ "−10,000". Hãy kiểm tra mọi giá trị biên ở phía server.
- **Thử thách 3 — tin vào một cái nhãn và một con số phiên bản.** Banner "ADMIN
  ONLY" không phải là kiểm soát truy cập, và phiên bản to hơn không phải là chữ
  ký. Hãy thực thi phân quyền, allowlist nguồn gốc, xác minh payload.
- **Thử thách 4 — tin nhầm tầng.** Một bind variable ở ranh giới PHP là vô nghĩa
  nếu stored function vẫn đi nối chuỗi rồi `EXECUTE IMMEDIATE`. Hãy vá đúng đoạn
  code thực sự dựng nên câu truy vấn.

Mỗi lỗ đều có một bản đã làm cứng tương ứng trong `secure_versions/` của repo,
nên bạn có thể đặt bản dính lỗi cạnh bản an toàn mà so từng dòng. Nếu muốn thử
chay, cứ tải lab về và tự giải trước khi đọc lại bài này — flag trong container
của bạn sẽ là của riêng bạn.

> Mã nguồn và hướng dẫn cài đặt đầy đủ: **[github.com/Khanh1916/oracle-sec-lab](https://github.com/Khanh1916/oracle-sec-lab)**

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
