---
layout: post
title: "OracleSecLab: four Oracle web bugs, exploited and fixed"
date: 2026-11-13
author: Nguyen Nam Khanh
tags: [oracle, sql-injection, plsql, business-logic, supply-chain, ctf, walkthrough]
description: >
  A hands-on walkthrough of OracleSecLab, an intentionally vulnerable Oracle and
  PHP student portal I built. It covers UNION SQL injection, a negative-quantity
  logic flaw, a broken-access-control supply-chain chain, and PL/SQL injection
  through EXECUTE IMMEDIATE, with a fix for each.
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

> Lab use only. OracleSecLab is an app I wrote with these bugs on purpose, to
> teach database security. Everything below runs against my own copy on
> `localhost` in Docker. Never point these techniques at a system you do not own
> or have permission to test.

Most of the vulnerable web apps you meet while learning, like DVWA, WebGoat and
Juice Shop, run on MySQL, PostgreSQL or SQLite. Oracle is a different world. It
has its own SQL dialect (`DUAL`, `ROWNUM`, `USER_TABLES`, `FETCH FIRST`), its own
PL/SQL stored programs, and its own habits for injection and enumeration. So I
built OracleSecLab, a university portal ("FPT Student Portal") on Oracle 23c
Free, PHP 8.3 and Apache, with four planted bugs sitting among dozens of safe
pages.

This post walks through all four from the attacker's side. For each one I show
the recon, the payload that works against the live app, why it works, and the fix
in the repo's `secure_versions/`. It replaces an older three-bug walkthrough I
wrote for the previous version of this app. The code has a fourth bug now, PL/SQL
injection, and a lot more around it to get lost in.

The four challenges:

| # | Vulnerability | Where | OWASP 2021 |
|---|---|---|---|
| 1 | Oracle UNION SQL injection (fragmented flag) | `search.php?q=` | A03 Injection |
| 2 | Business-logic flaw (negative quantity) | `store.php` | A04 Insecure Design |
| 3 | Broken access control into supply-chain poisoning | `partner_config.php` + `admin.php` | A01 / A06 |
| 4 | Oracle PL/SQL injection (`EXECUTE IMMEDIATE`) | `course_lookup.php` | A03 Injection |

---

## Run it yourself

The whole lab is one command, no Oracle install:

```bash
git clone https://github.com/Khanh1916/oracle-sec-lab.git
cd oracle-sec-lab
RANDOMIZE_FLAGS=1 docker compose up -d
```

Then open `http://localhost:8080/dbs401-oracle-app` and log in. The accounts I
use below:

| Username | Password | Role |
|---|---|---|
| `student1` | `Student@123` | Student (150 credits) |
| `admin` | `Admin@DBS401!2024` | Admin |

> A note on the flags. Every flag here has the shape `DBS401{...}`. I ran my copy
> with `RANDOMIZE_FLAGS=1`, so every flag in the screenshots is a throwaway value
> for that one container, not the real answer. That is on purpose. I want you to
> follow the method without me handing you the final strings. Solve it on your
> own copy and the flags you get are your own.

Here is the portal after I log in as `student1`, an ordinary academic dashboard.
None of this interface matters to the bugs. It is there to look normal.

![The FPT Student Portal dashboard after logging in as a student]({{ '/images/oracle-sec-lab/00-dashboard.jpg' | relative_url }})

---

## Challenge 1: Oracle UNION SQL injection

### Find the injection point

The Student Search page (`search.php`) looks ordinary. Search a real major and
you get a tidy table of students:

![A normal search for "Software" returning student rows]({{ '/images/oracle-sec-lab/01-search-normal.jpg' | relative_url }})

The first probe I reach for is a single quote. Send `?q='` and the page breaks,
but it breaks politely, with a caught error instead of a stack trace:

![A single quote triggers "Search failed. Please check your input."]({{ '/images/oracle-sec-lab/02-search-quote-error.jpg' | relative_url }})

That "Search failed" is the tell. The quote reached the database and broke the
query syntax. Under the hood, `search.php` builds its SQL by pasting the input
straight into the string:

```php
$sql = "SELECT student_id, full_name, major FROM STUDENTS
        WHERE (full_name LIKE '%$keyword%' OR major LIKE '%$keyword%')
          AND hidden_marker = 'NORMAL' AND ROWNUM <= 5";
```

My input lands inside a `LIKE '%...%'` literal, and that literal sits inside
parentheses. To take over the query I have to close the `%` and the quote, close
the parenthesis, then comment out the rest. So the prefix that breaks out is
`KEYWORD%') ... --`.

### Mind the keyword blacklist

There is one speed bump, a blacklist of DDL words:

```php
$ddlBlacklist = ['DROP','DELETE','UPDATE','INSERT','CREATE','ALTER','TRUNCATE'];
```

`UNION SELECT` is not on the list, so a read-only injection goes straight
through. One trap for later: the check is a case-insensitive substring match, so
the text `update_url` is blocked because it contains `UPDATE`. Remember that for
Challenge 3.

### Column count and types

Oracle `UNION` wants the same number of columns and compatible types on both
sides, and every `SELECT` needs a `FROM`, which is what `DUAL` is for. A plain
`UNION SELECT 1,2,3 FROM DUAL` fails here, because columns 2 and 3 are `VARCHAR2`
on the left and numbers on the right, and Oracle will not line those up. Give it
strings instead:

```sql
-- three columns: NUMBER, VARCHAR2, VARCHAR2
x%') UNION SELECT 1,'a','b' FROM DUAL--
```

### Enumerate the tables

`USER_TABLES` lists every table in the app's schema. I put `table_name` in one of
the string columns:

```sql
x%') UNION SELECT ROWNUM, table_name, NULL FROM USER_TABLES WHERE ROWNUM<=14--
```

![UNION injection listing the schema's tables, including FLAGS and CONFIG_STORE]({{ '/images/oracle-sec-lab/03-union-tables.jpg' | relative_url }})

Some names stand out: `FLAGS`, `AUDIT_LOGS`, `CONFIG_STORE`, `ADMIN_SECRETS`,
`SYSTEM_HINTS`, plus some bait like `FAKE_FLAGS` and `FLAG_ARCHIVE`. The lab is
full of decoys to catch anyone who just greps for the word "flag".

### The flag is in three pieces, three encodings

Dumping `FLAGS` gives you a fragment, not a flag, plus a decoy:

```sql
x%') UNION SELECT 1, flag_code, flag_part FROM FLAGS--
```

![The FLAGS table yields one real hex fragment and one base64 decoy]({{ '/images/oracle-sec-lab/04-flags-fragments.jpg' | relative_url }})

`FL1_PART_A` is a run of hex (`4442...`; decode it as hex bytes and it starts
`DBS401{SQL_`). `FL_DECOY_B` is base64 that decodes to `SOME_FAKE_FLAG_HERE`, so
ignore it. The other two real pieces sit elsewhere, in different encodings, and
that is the point of the challenge:

- Part B is in `AUDIT_LOGS.metadata_note`, a JSON blob with a `"fragment"` field
  written backwards. Reverse it to read it.
- Part C is in `CONFIG_STORE` under `sys_alpha_marker`, base64-encoded.

```sql
-- Part B
x%') UNION SELECT 1, metadata_note, action FROM AUDIT_LOGS
     WHERE action='SYSTEM_AUDIT_CHECK'--

-- Part C
x%') UNION SELECT 1, config_value, config_key FROM CONFIG_STORE
     WHERE config_key='sys_alpha_marker'--
```

Decode each piece (hex to ASCII, reverse the string, base64 to ASCII) and join
them. The three parts form one `DBS401{SQL_..._..._...}` flag. Two more base64
decoys sit in `CONFIG_STORE` (`sys_beta_marker`) and `FLAGS` to burn an automated
scanner's time. Clean decoding does not mean a string is correct.

### The fix

Stop concatenating. Bind the parameter and limit the input:

```php
$param = '%' . strtolower($keyword) . '%';
$sql   = "SELECT student_id, full_name, major FROM STUDENTS
          WHERE LOWER(full_name) LIKE :kw";
$stmt  = oci_parse($conn, $sql);
oci_bind_by_name($stmt, ':kw', $param);
oci_execute($stmt);
```

A blacklist only tells the attacker which words to encode around. Bind variables
are what actually closes the hole. (See `secure_versions/search_secure.php`.)

---

## Challenge 2: a negative quantity is free money

The Material Store (`store.php`) sells a cheap study guide (100 credits) and one
locked item, "Exam Leak 2024 (CLASSIFIED)", for 999,999 credits. My student has
150. Hopeless at first glance.

![The store: 150 credits, a cheap item, and a locked 999,999-credit item]({{ '/images/oracle-sec-lab/06-store-before.jpg' | relative_url }})

The server checks that you can afford the order. It never checks that the
quantity is positive:

```php
$cost = $qty * $price;            // qty comes straight from the form
if ($credits >= $cost) {
    $newCredits = $credits - $cost;   // subtract a negative = add
}
```

Order −10,000 of the 100-credit guide and the arithmetic flips:

```text
cost        = -10,000 * 100          = -1,000,000
new_credits =    150 - (-1,000,000)  =  1,000,150
```

Subtracting a negative number adds it. The balance jumps past 999,999 and the
classified item unlocks:

![After ordering a negative quantity, credits jump to 1,000,150 and the flag unlocks]({{ '/images/oracle-sec-lab/07-store-flag.jpg' | relative_url }})

No injection, no special tooling, just an input the designer never pictured. That
is why it maps to A04, Insecure Design. The code does exactly what it was written
to do.

### The fix

Check the boundary on the server, every time:

```php
if ($qty <= 0 || $qty > 100) {
    $msg = "Quantity must be between 1 and 100.";
} elseif ($credits < $cost) {
    $msg = "Insufficient credits.";
} else {
    $newCredits = $credits - $cost;
}
```

A client-side `min="1"` is decoration. The attacker never opens your form. (See
`secure_versions/store_secure.php`.)

---

## Challenge 3: broken access control into a supply-chain poison

This one is a chain. The admin panel can check for updates: it reads a partner
manifest URL from the database, fetches that JSON, and if the manifest advertises
a newer version it processes the payload. Poison the URL and you decide what the
admin's server fetches.

### Recon: find the hidden config

The admin panel shows only public config rows. The one I want, `update_url`, is
marked private, so it never appears in the interface. I already have SQL injection
from Challenge 1, so I dump `CONFIG_STORE` directly.

Here the blacklist bites: a payload with the text `update_url` is rejected,
because it contains `UPDATE`. The way around it is to not name it. Dump the whole
table and read the row from the results:

```sql
x%') UNION SELECT 1, config_key, config_value FROM CONFIG_STORE
     WHERE config_key NOT LIKE 'runtime%'--
```

![SQLi reveals the private update_url and the app_version from CONFIG_STORE]({{ '/images/oracle-sec-lab/05-config-recon.jpg' | relative_url }})

Now I know the server fetches updates from
`http://127.0.0.1:8081/manifest.json`, and the current `app_version` is `3.1.0`.
To trigger the update path, my manifest has to claim a higher version.

### Broken access control: the config page trusts anyone

There is a hidden page, `partner_config.php`, that changes that URL. It is
labelled "ADMIN ONLY", and that label is the only thing guarding it. The code
checks that you are logged in, nothing more. So an ordinary student walks in and
edits partner infrastructure:

![A logged-in student can open the admin-only partner configuration page]({{ '/images/oracle-sec-lab/08-partner-config-student.jpg' | relative_url }})

I point the manifest URL at a payload of my own. In a real engagement you would
host it on your own box. In the lab I serve a second manifest, `demo.json`, that
claims version `9.9.9` and carries the expected `flag_part`. The student's save
goes through, because nothing enforces access control:

![The student successfully overwrites the partner manifest URL]({{ '/images/oracle-sec-lab/09-partner-poisoned.jpg' | relative_url }})

### Spring the trap as admin

Now the admin checks for updates (`admin.php?check_updates=1`). The server fetches
my poisoned manifest, sees `9.9.9 > 3.1.0`, trusts it, takes the `flag_part` hex
from my file, joins it with a secret half held on the server, and hex-decodes the
result onto the page:

![The admin update check fetches the poisoned manifest and reveals the supply-chain flag]({{ '/images/oracle-sec-lab/10-admin-flag.jpg' | relative_url }})

"Update successful! System upgraded to version 9.9.9", and the flag drops out. A
student with no privileges got data of their choosing run inside the admin's
trust. A real supply-chain attack works the same way: you compromise something
the target trusts, and the target pulls it in for you.

### The fix

Three separate failures, three fixes:

1. Enforce the role. `partner_config.php` has to check
   `$_SESSION['role'] === 'admin'` before it writes anything.
2. Allowlist the origin. Validate the update URL against a short list of approved
   hosts instead of taking free text.
3. Verify a signature. Sign manifests (HMAC or RSA) and reject anything that does
   not verify. A higher version number proves nothing.

(See `secure_versions/partner_config_secure.php` and `admin_update_secure.php`.)

---

## Challenge 4: PL/SQL injection through EXECUTE IMMEDIATE

The last one is the most Oracle-specific, and my favourite, because it looks
safe. The Course Info lookup (`course_lookup.php`) passes the course code as a
bind variable:

```php
$sql = "SELECT FN_COURSE_LOOKUP(:code) AS info FROM DUAL";
oci_bind_by_name($stmt, ':code', $code);   // textbook-correct, right?
```

A scanner that reads only the PHP calls this clean. A normal code returns a
normal course name:

![A normal course-code lookup returns "Database Security"]({{ '/images/oracle-sec-lab/11-course-normal.jpg' | relative_url }})

But binding at the call site does nothing if the vulnerable part is the stored
function itself. Look inside `FN_COURSE_LOOKUP`:

```sql
v_sql := 'SELECT course_name FROM COURSES WHERE course_code = ''' || p_code || '''';
EXECUTE IMMEDIATE v_sql INTO v_result;
```

The bound value arrives in PL/SQL safely, and then the function builds a SQL
string by concatenation and runs it with `EXECUTE IMMEDIATE`. The injection
happens inside the database, one layer below where PHP thought it had things
covered. The lesson is short: a bind variable only protects the statement it is
bound to.

### The single-row trap

The function returns one value through `... INTO v_result`, so the query I inject
has to return exactly one row. The flag sits in a `PLSQL_VAULT` table that also
holds a decoy row, so the obvious payload returns two rows and Oracle raises
`TOO_MANY_ROWS`, which the function reports as "Ambiguous result":

```sql
zzz' UNION SELECT secret_flag FROM PLSQL_VAULT--
```

![The naive UNION returns two rows and fails with "Ambiguous result"]({{ '/images/oracle-sec-lab/12-course-ambiguous.jpg' | relative_url }})

Filter down to the one real row and the flag comes back dressed as a course name:

```sql
zzz' UNION SELECT secret_flag FROM PLSQL_VAULT WHERE label='CHALLENGE_4'--
```

![Filtering to one row extracts Flag 4 through the PL/SQL injection]({{ '/images/oracle-sec-lab/13-course-flag.jpg' | relative_url }})

### The fix

Fix the stored program, not the call site. Prefer static SQL with no dynamic
string at all:

```sql
SELECT course_name INTO v_result FROM COURSES WHERE course_code = p_code;
```

If you do need dynamic SQL, bind inside `EXECUTE IMMEDIATE` too, and never
concatenate user input:

```sql
EXECUTE IMMEDIATE 'SELECT course_name FROM COURSES WHERE course_code = :c'
  INTO v_result USING p_code;
```

Run the function with invoker's rights (`AUTHID CURRENT_USER`) so the web role
cannot reach tables like `PLSQL_VAULT` through it. (See
`secure_versions/course_lookup_secure.php`.)

---

## What the four bugs have in common

The four bugs come from four different mistakes, and none of them is exotic.

The first one trusts a blacklist. SQL built from string concatenation plus a list
of banned keywords is an injection waiting to happen, because the attacker only
has to phrase the payload around the list. Bind variables close that for good.

The second one trusts the client. The form said the quantity starts at 1, the
attacker sent −10,000. Anything the browser can send has to be checked again on
the server.

The third one trusts a label and a version number. An "ADMIN ONLY" banner is not
access control, and a larger version string is not a signature. The server has to
enforce the role itself, restrict the update URL to hosts it already knows, and
verify a signature on whatever it pulls in.

The fourth one trusts the wrong layer. A bind variable at the PHP boundary buys
nothing when the stored function goes on to concatenate and `EXECUTE IMMEDIATE`.
The fix belongs in the code that actually builds the query.

Every bug has a hardened version next to it in `secure_versions/`, so you can read
the vulnerable file and the safe file side by side. If you want to try it cold,
grab the lab and solve it before you reread this. The flags in your container are
yours alone.

> Source and full setup: [github.com/Khanh1916/oracle-sec-lab](https://github.com/Khanh1916/oracle-sec-lab)

---

*Written by Nguyen Nam Khanh ([@Khanh1916](https://github.com/Khanh1916)).*

</div>

<div class="lang-vi" markdown="1">

> Chỉ dùng trong lab. OracleSecLab là app mình tự viết, cố ý cài sẵn mấy lỗ hổng
> này để dạy về an toàn cơ sở dữ liệu. Mọi thứ bên dưới mình chạy trên bản của
> chính mình, ở `localhost` trong Docker. Đừng bao giờ nhắm các kỹ thuật này vào
> hệ thống bạn không sở hữu hoặc chưa được phép kiểm thử.

Hầu hết các web app có lỗ hổng mà người mới hay gặp, như DVWA, WebGoat hay Juice
Shop, đều chạy trên MySQL, PostgreSQL hoặc SQLite. Oracle thì là một thế giới
khác. Nó có phương ngữ SQL riêng (`DUAL`, `ROWNUM`, `USER_TABLES`, `FETCH
FIRST`), có stored program PL/SQL riêng, và có những kiểu injection, enumeration
riêng. Nên mình dựng OracleSecLab, một cổng thông tin sinh viên ("FPT Student
Portal") chạy trên Oracle 23c Free, PHP 8.3 và Apache, với bốn lỗ cài sẵn nằm lẫn
giữa mấy chục trang lành tính.

Bài này đi qua cả bốn lỗ từ phía người tấn công. Mỗi lỗ mình ghi lại phần recon,
payload chạy được trên app, lý do nó ăn, và bản vá nằm trong thư mục
`secure_versions/` của repo. Bài này thay cho một walkthrough ba lỗ mình viết cho
phiên bản trước. Giờ code có thêm lỗ thứ tư, PL/SQL injection, và nhiều thứ xung
quanh hơn để mà lạc vào.

Bốn thử thách:

| # | Lỗ hổng | Ở đâu | OWASP 2021 |
|---|---|---|---|
| 1 | Oracle UNION SQL injection (flag chia mảnh) | `search.php?q=` | A03 Injection |
| 2 | Lỗi logic nghiệp vụ (số lượng âm) | `store.php` | A04 Insecure Design |
| 3 | Broken access control thành đầu độc supply-chain | `partner_config.php` + `admin.php` | A01 / A06 |
| 4 | Oracle PL/SQL injection (`EXECUTE IMMEDIATE`) | `course_lookup.php` | A03 Injection |

---

## Tự dựng mà chơi

Cả cái lab gói trong một câu lệnh, khỏi cài Oracle:

```bash
git clone https://github.com/Khanh1916/oracle-sec-lab.git
cd oracle-sec-lab
RANDOMIZE_FLAGS=1 docker compose up -d
```

Xong thì mở `http://localhost:8080/dbs401-oracle-app` và đăng nhập. Hai tài
khoản mình dùng ở dưới:

| Tài khoản | Mật khẩu | Vai trò |
|---|---|---|
| `student1` | `Student@123` | Sinh viên (150 credit) |
| `admin` | `Admin@DBS401!2024` | Admin |

> Nói trước về flag. Flag nào ở đây cũng có dạng `DBS401{...}`. Mình chạy bản của
> mình với `RANDOMIZE_FLAGS=1`, nên mỗi flag trong ảnh chỉ là giá trị dùng một
> lần cho đúng container đó, không phải đáp án thật. Cố ý đấy. Mình muốn bạn nắm
> được cách làm chứ không phải chép sẵn chuỗi cuối. Bạn tự giải trên bản của mình
> thì flag nhận được là của riêng bạn.

Đây là cổng thông tin sau khi mình đăng nhập bằng `student1`, một dashboard học
vụ bình thường. Toàn bộ giao diện này không liên quan gì tới các lỗ. Nó chỉ cốt
trông cho giống thật.

![Dashboard của FPT Student Portal sau khi đăng nhập bằng tài khoản sinh viên]({{ '/images/oracle-sec-lab/00-dashboard.jpg' | relative_url }})

---

## Thử thách 1: Oracle UNION SQL injection

### Tìm điểm injection

Trang Student Search (`search.php`) trông bình thường. Gõ một chuyên ngành có
thật là bạn nhận về một bảng sinh viên gọn gàng:

![Tìm bình thường với "Software" trả về danh sách sinh viên]({{ '/images/oracle-sec-lab/01-search-normal.jpg' | relative_url }})

Phát thăm dò đầu tiên mình hay thử là một dấu nháy đơn. Gửi `?q='`, trang vỡ
ngay, nhưng vỡ có kiểm soát, báo lỗi đã bắt được chứ không phun ra stack trace:

![Một dấu nháy đơn làm hiện "Search failed. Please check your input."]({{ '/images/oracle-sec-lab/02-search-quote-error.jpg' | relative_url }})

Dòng "Search failed" là dấu hiệu. Dấu nháy đã xuống tới database và phá vỡ cú
pháp câu truy vấn. Bên dưới, `search.php` ghép SQL bằng cách dán thẳng input vào
chuỗi:

```php
$sql = "SELECT student_id, full_name, major FROM STUDENTS
        WHERE (full_name LIKE '%$keyword%' OR major LIKE '%$keyword%')
          AND hidden_marker = 'NORMAL' AND ROWNUM <= 5";
```

Input của mình rơi vào bên trong một literal `LIKE '%...%'`, mà literal này lại
nằm trong cặp ngoặc đơn. Muốn chiếm câu truy vấn, mình phải đóng dấu `%` và dấu
nháy, đóng ngoặc đơn, rồi comment bỏ phần còn lại. Nên đoạn đầu để thoát ra là
`KEYWORD%') ... --`.

### Coi chừng blacklist từ khóa

Có một chướng ngại nhỏ, một blacklist chặn mấy từ DDL:

```php
$ddlBlacklist = ['DROP','DELETE','UPDATE','INSERT','CREATE','ALTER','TRUNCATE'];
```

`UNION SELECT` không nằm trong danh sách, nên injection kiểu đọc dữ liệu đi lọt
thẳng. Một cái bẫy để dành cho sau: phép kiểm là so khớp chuỗi con, không phân
biệt hoa thường, nên riêng chữ `update_url` bị chặn vì có `UPDATE` bên trong. Nhớ
chi tiết này cho Thử thách 3.

### Số cột và kiểu dữ liệu

`UNION` của Oracle đòi hai vế cùng số cột và cùng kiểu tương thích, và mỗi
`SELECT` đều cần một `FROM`, đó là lúc cần tới `DUAL`. Payload ngây thơ
`UNION SELECT 1,2,3 FROM DUAL` lại lỗi ở đây, vì cột 2 và 3 bên trái là `VARCHAR2`
còn bên phải là số, Oracle không chịu ghép hai kiểu đó. Đưa chuỗi vào là xong:

```sql
-- ba cột: NUMBER, VARCHAR2, VARCHAR2
x%') UNION SELECT 1,'a','b' FROM DUAL--
```

### Liệt kê các bảng

`USER_TABLES` liệt kê mọi bảng trong schema của app. Mình nhét `table_name` vào
một cột kiểu chuỗi:

```sql
x%') UNION SELECT ROWNUM, table_name, NULL FROM USER_TABLES WHERE ROWNUM<=14--
```

![UNION injection liệt kê các bảng của schema, gồm FLAGS và CONFIG_STORE]({{ '/images/oracle-sec-lab/03-union-tables.jpg' | relative_url }})

Vài cái tên lộ ra: `FLAGS`, `AUDIT_LOGS`, `CONFIG_STORE`, `ADMIN_SECRETS`,
`SYSTEM_HINTS`, kèm mấy cái mồi như `FAKE_FLAGS` và `FLAG_ARCHIVE`. Lab cài đầy
decoy để bắt ai chỉ quen grep mỗi chữ "flag".

### Flag gồm ba mảnh, ba kiểu mã hóa

Dump bảng `FLAGS` cho bạn một mảnh thôi, không phải cả flag, lại còn kèm một mồi
nhử:

```sql
x%') UNION SELECT 1, flag_code, flag_part FROM FLAGS--
```

![Bảng FLAGS cho ra một mảnh hex thật và một decoy base64]({{ '/images/oracle-sec-lab/04-flags-fragments.jpg' | relative_url }})

`FL1_PART_A` là một chuỗi hex (`4442...`; giải theo byte hex thì mở đầu bằng
`DBS401{SQL_`). `FL_DECOY_B` là base64, giải ra thành `SOME_FAKE_FLAG_HERE`, nên
bỏ qua. Hai mảnh thật còn lại nằm chỗ khác, mã hóa theo kiểu khác, và đó mới là
cái cốt của thử thách:

- Mảnh B nằm ở `AUDIT_LOGS.metadata_note`, một khối JSON có trường `"fragment"`
  viết ngược. Đảo chuỗi lại là đọc được.
- Mảnh C nằm trong `CONFIG_STORE` ở khóa `sys_alpha_marker`, mã hóa base64.

```sql
-- Mảnh B
x%') UNION SELECT 1, metadata_note, action FROM AUDIT_LOGS
     WHERE action='SYSTEM_AUDIT_CHECK'--

-- Mảnh C
x%') UNION SELECT 1, config_value, config_key FROM CONFIG_STORE
     WHERE config_key='sys_alpha_marker'--
```

Giải từng mảnh (hex sang ASCII, đảo ngược chuỗi, base64 sang ASCII) rồi ghép lại.
Ba mảnh ghép thành đúng một flag `DBS401{SQL_..._..._...}`. Còn hai decoy base64
nằm ở `CONFIG_STORE` (`sys_beta_marker`) và `FLAGS` để ngốn thời gian của scanner
tự động. Giải ra sạch đẹp không có nghĩa là đúng.

### Bản vá

Ngừng nối chuỗi. Bind tham số và giới hạn input:

```php
$param = '%' . strtolower($keyword) . '%';
$sql   = "SELECT student_id, full_name, major FROM STUDENTS
          WHERE LOWER(full_name) LIKE :kw";
$stmt  = oci_parse($conn, $sql);
oci_bind_by_name($stmt, ':kw', $param);
oci_execute($stmt);
```

Blacklist chỉ mách cho kẻ tấn công biết cần né những chữ nào. Bind variable mới
là cái bịt được lỗ. (Xem `secure_versions/search_secure.php`.)

---

## Thử thách 2: số lượng âm hóa ra là tiền chùa

Material Store (`store.php`) bán một cuốn tài liệu ôn thi rẻ tiền (100 credit) và
một món bị khóa, "Exam Leak 2024 (CLASSIFIED)", giá 999,999 credit. Sinh viên của
mình có 150. Thoạt nhìn thì hết cửa.

![Store: 150 credit, một món rẻ, và một món khóa giá 999,999 credit]({{ '/images/oracle-sec-lab/06-store-before.jpg' | relative_url }})

Server có kiểm tra xem bạn đủ tiền trả đơn không. Nó không hề kiểm tra số lượng
có phải số dương:

```php
$cost = $qty * $price;            // qty lấy thẳng từ form
if ($credits >= $cost) {
    $newCredits = $credits - $cost;   // trừ một số âm = cộng
}
```

Đặt mua −10,000 cuốn tài liệu 100 credit, phép tính lật ngược:

```text
cost        = -10,000 * 100          = -1,000,000
new_credits =    150 - (-1,000,000)  =  1,000,150
```

Trừ một số âm tức là cộng nó vào. Số dư nhảy qua mốc 999,999 và món tài liệu bị
khóa mở ra:

![Sau khi đặt số lượng âm, credit nhảy lên 1,000,150 và flag mở khóa]({{ '/images/oracle-sec-lab/07-store-flag.jpg' | relative_url }})

Không injection, không công cụ gì ghê gớm, chỉ là một input người thiết kế chưa
từng hình dung. Đó là lý do nó thuộc A04, Insecure Design. Đoạn code làm đúng
chính xác những gì nó được viết ra để làm.

### Bản vá

Kiểm giá trị biên ở phía server, lần nào cũng kiểm:

```php
if ($qty <= 0 || $qty > 100) {
    $msg = "Quantity must be between 1 and 100.";
} elseif ($credits < $cost) {
    $msg = "Insufficient credits.";
} else {
    $newCredits = $credits - $cost;
}
```

Cái `min="1"` phía client chỉ để trang trí. Kẻ tấn công có mở form của bạn đâu.
(Xem `secure_versions/store_secure.php`.)

---

## Thử thách 3: từ broken access control tới đầu độc supply-chain

Lỗ này là cả một chuỗi. Trang admin có nút kiểm tra cập nhật: nó đọc một URL
manifest đối tác từ database, tải JSON đó về, và nếu manifest khai một phiên bản
mới hơn thì xử lý luôn payload. Đầu độc cái URL đó là bạn quyết định được server
của admin tải thứ gì về.

### Recon: moi cấu hình ẩn

Trang admin chỉ hiện những dòng cấu hình công khai. Dòng mình cần, `update_url`,
bị đánh dấu riêng tư nên không bao giờ hiện ra giao diện. Mình đã có sẵn SQL
injection từ Thử thách 1, nên cứ dump thẳng `CONFIG_STORE`.

Đến đây blacklist cắn: payload chứa chữ `update_url` bị chặn, vì có `UPDATE`.
Cách lách là đừng gọi đích danh nó. Dump cả bảng rồi tự đọc dòng cần tìm trong
kết quả:

```sql
x%') UNION SELECT 1, config_key, config_value FROM CONFIG_STORE
     WHERE config_key NOT LIKE 'runtime%'--
```

![SQLi lộ ra update_url riêng tư và app_version từ CONFIG_STORE]({{ '/images/oracle-sec-lab/05-config-recon.jpg' | relative_url }})

Giờ mình biết server tải cập nhật từ `http://127.0.0.1:8081/manifest.json`, và
`app_version` hiện tại là `3.1.0`. Muốn kích hoạt luồng cập nhật, manifest của
mình phải khai một phiên bản cao hơn.

### Broken access control: trang cấu hình tin mọi người

Có một trang ẩn, `partner_config.php`, cho sửa cái URL đó. Nó dán nhãn "ADMIN
ONLY", và cái nhãn là thứ duy nhất canh cửa. Code chỉ kiểm tra bạn đã đăng nhập
hay chưa, hết. Thế là một sinh viên quèn đi thẳng vào sửa hạ tầng của đối tác:

![Một sinh viên đã đăng nhập mở được trang cấu hình đối tác vốn chỉ dành cho admin]({{ '/images/oracle-sec-lab/08-partner-config-student.jpg' | relative_url }})

Mình trỏ URL manifest sang một payload của mình. Trong một kỳ đánh giá thật, bạn
sẽ tự host nó trên máy mình. Còn trong lab mình dựng sẵn một manifest thứ hai,
`demo.json`, khai phiên bản `9.9.9` và kèm sẵn `flag_part`. Sinh viên lưu lọt, vì
chẳng có gì thực thi kiểm soát truy cập:

![Sinh viên ghi đè thành công URL manifest đối tác]({{ '/images/oracle-sec-lab/09-partner-poisoned.jpg' | relative_url }})

### Sập bẫy khi vào vai admin

Giờ admin bấm kiểm tra cập nhật (`admin.php?check_updates=1`). Server tải về
manifest đã bị mình đầu độc, thấy `9.9.9 > 3.1.0`, tin ngay, lấy chuỗi hex
`flag_part` từ file của mình, ghép với nửa bí mật nằm ở server, rồi hex-decode
kết quả in ra trang:

![Lần kiểm tra cập nhật của admin tải manifest độc hại và để lộ flag supply-chain]({{ '/images/oracle-sec-lab/10-admin-flag.jpg' | relative_url }})

"Update successful! System upgraded to version 9.9.9", và flag rơi ra. Một sinh
viên không quyền hành gì đã khiến dữ liệu do mình chọn chạy trong vùng tin cậy
của admin. Một vụ tấn công supply-chain thật diễn ra đúng kiểu này: bạn chiếm một
thứ mà mục tiêu tin tưởng, rồi để chính mục tiêu kéo nó về giúp bạn.

### Bản vá

Ba điểm hỏng riêng biệt, ba bản vá:

1. Thực thi phân quyền. `partner_config.php` phải kiểm tra
   `$_SESSION['role'] === 'admin'` trước khi ghi bất cứ thứ gì.
2. Allowlist nguồn gốc. Đối chiếu URL cập nhật với một danh sách ngắn các host đã
   duyệt, thay vì nhận chuỗi tự do.
3. Xác minh chữ ký. Ký manifest (HMAC hoặc RSA) và từ chối thứ gì không xác minh
   được. Số phiên bản cao hơn chẳng chứng minh được gì.

(Xem `secure_versions/partner_config_secure.php` và `admin_update_secure.php`.)

---

## Thử thách 4: PL/SQL injection qua EXECUTE IMMEDIATE

Lỗ cuối là lỗ Oracle nhất, cũng là lỗ mình khoái nhất, vì trông nó an toàn. Trang
tra cứu Course Info (`course_lookup.php`) truyền mã môn học dưới dạng một bind
variable:

```php
$sql = "SELECT FN_COURSE_LOOKUP(:code) AS info FROM DUAL";
oci_bind_by_name($stmt, ':code', $code);   // chuẩn sách giáo khoa còn gì?
```

Scanner nào chỉ đọc phần PHP đều chấm đoạn này là sạch. Một mã bình thường trả về
một tên môn bình thường:

![Tra cứu một mã môn bình thường trả về "Database Security"]({{ '/images/oracle-sec-lab/11-course-normal.jpg' | relative_url }})

Nhưng bind ở điểm gọi chẳng ích gì nếu chỗ dính lỗi lại là bản thân stored
function. Ngó vào trong `FN_COURSE_LOOKUP`:

```sql
v_sql := 'SELECT course_name FROM COURSES WHERE course_code = ''' || p_code || '''';
EXECUTE IMMEDIATE v_sql INTO v_result;
```

Giá trị được bind về tới PL/SQL an toàn, rồi function tự ghép một chuỗi SQL bằng
phép nối và chạy nó qua `EXECUTE IMMEDIATE`. Injection xảy ra ngay trong database,
thấp hơn một tầng so với chỗ PHP tưởng mình đã lo xong. Bài học gọn thôi: một bind
variable chỉ bảo vệ đúng câu lệnh mà nó được gắn vào.

### Cái bẫy một dòng

Function trả về một giá trị qua `... INTO v_result`, nên câu truy vấn mình chèn
phải trả về đúng một dòng. Flag nằm trong bảng `PLSQL_VAULT`, mà bảng này còn có
một dòng decoy, nên payload hiển nhiên trả về hai dòng và Oracle ném ra
`TOO_MANY_ROWS`, được function báo lại thành "Ambiguous result":

```sql
zzz' UNION SELECT secret_flag FROM PLSQL_VAULT--
```

![UNION ngây thơ trả về hai dòng và lỗi "Ambiguous result"]({{ '/images/oracle-sec-lab/12-course-ambiguous.jpg' | relative_url }})

Lọc còn đúng một dòng thật là flag hiện về, cải trang thành một tên môn học:

```sql
zzz' UNION SELECT secret_flag FROM PLSQL_VAULT WHERE label='CHALLENGE_4'--
```

![Lọc còn một dòng, trích được Flag 4 qua PL/SQL injection]({{ '/images/oracle-sec-lab/13-course-flag.jpg' | relative_url }})

### Bản vá

Vá cái stored program, đừng vá mỗi điểm gọi. Ưu tiên SQL tĩnh, không có chuỗi
động nào:

```sql
SELECT course_name INTO v_result FROM COURSES WHERE course_code = p_code;
```

Nếu thật sự cần SQL động, hãy bind cả bên trong `EXECUTE IMMEDIATE`, và đừng bao
giờ nối chuỗi input người dùng:

```sql
EXECUTE IMMEDIATE 'SELECT course_name FROM COURSES WHERE course_code = :c'
  INTO v_result USING p_code;
```

Và cho function chạy bằng quyền của người gọi (`AUTHID CURRENT_USER`) để role của
web không với tới được những bảng như `PLSQL_VAULT` qua nó. (Xem
`secure_versions/course_lookup_secure.php`.)

---

## Bốn lỗ có điểm gì chung

Bốn lỗ đến từ bốn cái sai khác nhau, mà không cái nào cao siêu cả.

Lỗ thứ nhất tin vào blacklist. SQL ghép từ chuỗi cộng thêm một danh sách từ cấm
là injection sớm muộn cũng tới, vì kẻ tấn công chỉ cần viết payload lách quanh
danh sách đó. Bind variable khóa hẳn đường này.

Lỗ thứ hai tin vào client. Form ghi số lượng bắt đầu từ 1, kẻ tấn công gửi
−10,000. Thứ gì trình duyệt gửi lên đều phải kiểm lại ở server.

Lỗ thứ ba tin vào một cái nhãn và một con số phiên bản. Banner "ADMIN ONLY" không
phải kiểm soát truy cập, và một chuỗi phiên bản to hơn không phải chữ ký. Server
phải tự thực thi phân quyền, giới hạn URL cập nhật trong những host nó đã biết, và
xác minh chữ ký trên thứ nó kéo về.

Lỗ thứ tư tin nhầm tầng. Một bind variable ở ranh giới PHP chẳng mua được gì khi
stored function vẫn đi nối chuỗi rồi `EXECUTE IMMEDIATE`. Chỗ cần vá nằm trong
đoạn code thực sự dựng nên câu truy vấn.

Mỗi lỗ đều có một bản đã làm cứng nằm cạnh trong `secure_versions/`, nên bạn đọc
file dính lỗi và file an toàn cạnh nhau được. Muốn thử chay thì tải lab về và tự
giải trước khi đọc lại bài này. Flag trong container của bạn là của riêng bạn.

> Mã nguồn và hướng dẫn cài đặt đầy đủ: [github.com/Khanh1916/oracle-sec-lab](https://github.com/Khanh1916/oracle-sec-lab)

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
