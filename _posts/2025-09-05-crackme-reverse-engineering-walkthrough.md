---
layout: post
title: "CrackMe 1 to 5: a beginner's guide to x86 reverse engineering with x32dbg"
date: 2025-09-05
author: Nguyen Nam Khanh
tags: [reverse-engineering, x86, assembly, x32dbg, crackme, patching, keygen]
description: >
  A hands-on, beginner-friendly walkthrough of five classic x86 CrackMe challenges:
  from string references and jump flipping to keyfiles, NOP patching, trial period
  extension, and writing a Python keygen.
platform: Windows / x32dbg
difficulty: Beginner
flags: 5
flags_label: Challenges
read: 14
bilingual: true
---

<div class="lang-en" markdown="1">

> Lab use only. All programs analyzed below are intentionally vulnerable CrackMe binaries
> created for reverse engineering education. Never reverse engineer or patch commercial
> software without proper authorization.

When you compile a C or C++ program, the human-readable source code disappears. What remains
is machine code: raw bytes that the CPU decodes into assembly instructions. For many developers,
that binary file feels like an impenetrable black box.

Reverse engineering is the art of opening that box. A CrackMe is an intentionally locked
program designed to teach that skill. There are no source files, no symbols, and no documentation.
You are given an executable file and a simple goal: find the correct serial key, remove an annoying
nag screen, extend an expired trial, or write a key generator.

In this walkthrough, we will analyze five classic x86 Win32 CrackMes from scratch using `x32dbg`.
Each challenge introduces a core reverse-engineering pattern used in real-world binary analysis.

| # | Challenge | Target Mechanism | Primary Technique |
|---|---|---|---|
| 1 | CrackMe 1 | Hardcoded serial comparison | String references & conditional jump flipping (`JNE` -> `JE`) |
| 2 | CrackMe 2 | Keyfile licensing | File I/O analysis & creating valid `keyfile.txt` |
| 3 | CrackMe 3 | Opening/closing nag screens & registration check | NOP padding (`0x90`) & branching modification |
| 4 | CrackMe 4 | Expired 30-day trial period | System time arithmetic analysis (`GetLocalTime`) & value patching |
| 5 | CrackMe 5 | Algorithmic username-to-serial check | Dynamic key analysis (`wsprintfA`) & writing a Python keygen |

---

## Run it yourself

You can download the exact challenge binaries and follow along step by step on Windows.

| | |
|---|---|
| Target | CrackMe 1 to 5 (Win32 Portable Executable) |
| Author | Paul Chin / Cracking Lessons |
| Source | [GitHub repository](https://github.com/tiendungdo12/crackmes-crackinglessons.com) |
| Tool | [x64dbg / x32dbg](https://x64dbg.com/) (Open Source x86/x64 Debugger) |
| Archive password | `crackinglessons.com` |

Setup steps:

1. Download the CrackMe zips (`CrackMe1.zip` to `CrackMe5.zip`) from the GitHub archive and extract them using password `crackinglessons.com`.
2. Download and install `x64dbg`. We will use `x32dbg.exe` located in the `release/x32` folder because these samples are 32-bit PE files.
3. Open `x32dbg`, configure basic preferences (Options -> Preferences -> uncheck System Breakpoint if you want to land straight at the Entry Point), and you are ready.

---

## Challenge 1: hardcoded strings and jump flipping

We start with `CrackMe1.exe`. Running the executable presents a simple dialog with a text input box. Typing a random serial key and clicking Check yields an immediate error:

![CrackMe 1 showing Wrong serial key dialog]({{ '/images/crackme-reversing/01-crackme1-wrong-key.png' | relative_url }})

The error message "Wrong serial key. Try again." is our anchor. In compiled software, user-facing error text must exist in memory, and looking up where that text is referenced points us directly to the check logic.

### Find the reference in x32dbg

Open `CrackMe1.exe` in `x32dbg`. In the CPU view, right-click, select Search for -> All User Modules -> String References.

Filter for `Wrong serial key`:

![Locating the error string in string references]({{ '/images/crackme-reversing/02-crackme1-string-references.png' | relative_url }})

Double-clicking the line jumps directly to address `00401159` in the disassembler:

```assembly
00401137 | 85C0             | test eax, eax
00401139 | 75 19            | jne crackme1.401154
0040113B | 68 E81A4100      | push crackme1.411AE8      ; "Well done!"
00401140 | 68 F41A4100      | push crackme1.411AF4      ; "Cr4cked"
00401145 | 50               | push eax
00401146 | FF15 18D14000    | call dword ptr [<&MessageBoxA>]
...
00401154 | 68 001B4100      | push crackme1.411B00      ; "Cr4cked"
00401159 | 68 081B4100      | push crackme1.411B08      ; "Wrong serial key. Try again."
0040115E | 6A 00            | push 0
00401160 | FF15 18D14000    | call dword ptr [<&MessageBoxA>]
```

Notice the branch at `00401139`: `jne crackme1.401154`. If `eax` is not zero, the program jumps over the "Well done!" block straight to the error message.

Looking just a few lines above `00401137`, we find a string comparison routine comparing our input with address `00411AD8`:

![Disassembly showing the comparison instruction]({{ '/images/crackme-reversing/03-crackme1-cmp-jump.png' | relative_url }})

At address `00411AD8` sits the hardcoded string: `cr4ckingL3ssons`.

We have two ways to solve this:
- Enter the valid serial key directly: `cr4ckingL3ssons`.
- Patch the binary: double-click address `00401139` and change `jne` (`75 19`) to `je` (`74 19`), or change `test eax, eax` to `xor eax, eax`.

Save the patched file via File -> Patch file. Running the patched executable with any random text displays the success dialog:

![CrackMe 1 solved with success message]({{ '/images/crackme-reversing/04-crackme1-success.png' | relative_url }})

---

## Challenge 2: licensing via keyfiles

`CrackMe2.exe` introduces another common licensing scheme: keyfiles. When launched without a license file, the application immediately displays an unregistered notice:

![CrackMe 2 displaying unregistered status window]({{ '/images/crackme-reversing/05-crackme2-unregistered.png' | relative_url }})

The window displays "Unregistered Software. Please crack me." with no input fields on the interface.

### Tracing the File Check in x32dbg

Loading `CrackMe2.exe` into `x32dbg` and searching String References reveals an immediate clue: `keyfile.txt`.

![Analyzing keyfile string in x32dbg]({{ '/images/crackme-reversing/06-crackme2-x32dbg.png' | relative_url }})

Following the reference to `0040103E` exposes the Win32 file handling sequence:

```assembly
0040103E | 68 281B4100      | push crackme2.411B28      ; "keyfile.txt"
00401043 | FF15 00D04000    | call dword ptr [<&CreateFileA>]
00401049 | 8BF0             | mov esi, eax              ; Store returned handle
0040104B | 83FE FF          | cmp esi, -1               ; Compare against INVALID_HANDLE_VALUE (-1)
0040104E | 74 51            | je crackme2.4010A1        ; If not found, jump to unregistered branch
00401050 | 6A 00            | push 0
00401052 | 68 04434100      | push crackme2.414304
00401057 | 6A 1F            | push 1F                   ; nNumberOfBytesToRead = 31 bytes
00401059 | 68 E4424100      | push crackme2.4142E4      ; Output buffer
0040105E | 56               | push esi                  ; File handle
0040105F | FF15 08D04000    | call dword ptr [<&ReadFile>]
...
0040109B | FF15 04D04000    | call dword ptr [<&CloseHandle>]
```

The validation operates in three stages:
1. `CreateFileA` attempts to open `keyfile.txt` in the executable's directory with `OPEN_EXISTING`.
2. If the file is missing, it returns `-1` (`INVALID_HANDLE_VALUE`) and `je crackme2.4010A1` branches to the unregistered dialog.
3. If present, `ReadFile` reads up to 31 bytes into `004142E4`, closes the handle, and appends the content after `Registered to: `. No signature check or encryption is applied.

### Creating a Valid Keyfile

We create a plain text file named `keyfile.txt` in the same directory as `CrackMe2.exe`. Inside Notepad, enter the desired username:

![Creating keyfile.txt with username in Notepad]({{ '/images/crackme-reversing/07-crackme2-notepad.png' | relative_url }})

Save it with standard ANSI encoding. Relaunching `CrackMe2.exe`:

![CrackMe 2 successfully registered to user]({{ '/images/crackme-reversing/08-crackme2-registered.png' | relative_url }})

The window title updates immediately to `Registered to: khanh1916`. Challenge solved without modifying binary code.

---

## Challenge 3: eliminating nag screens and NOP patching

`CrackMe3.exe` demonstrates annoying pop-up screens (nag screens) on launch and exit, along with an About dialog marking the software as unregistered. The challenge has three distinct objectives:
1. Remove the opening nag screen ("Opening Nag").
2. Remove the closing nag screen ("Closing Nag").
3. Make the About dialog display "REGISTERED" instead of "Unregistered".

![CrackMe 3 main interface and nag popups]({{ '/images/crackme-reversing/09-crackme3-nags-composite.png' | relative_url }})

### Objective 1: Bypassing the Opening Nag

Searching for "Opening Nag" in `x32dbg` leads to address `0040102D`:

![Locating the Opening Nag in x32dbg]({{ '/images/crackme-reversing/10-crackme3-opening-nag.png' | relative_url }})

```assembly
0040101D | 833D A0424100 00 | cmp dword ptr [4142A0], 0
00401024 | A3 A4424100      | mov dword ptr [4142A4], eax
00401029 | 75 19            | jne crackme3.401044
0040102B | 6A 00            | push 0
0040102D | 68 D81A4100      | push crackme3.411AD8      ; "Opening Nag"
00401032 | 68 E41A4100      | push crackme3.411AE4      ; "I am a nag screen"
00401037 | 6A 00            | push 0
00401039 | FF15 14D14000    | call dword ptr [<&MessageBoxA>]
0040103F | A1 A4424100      | mov eax, dword ptr [4142A4]
00401044 | 56               | push esi
```

At `00401029`, `jne crackme3.401044` skips the `MessageBoxA` call when the condition is met. Inverting this jump from `jne` to `je` (`74 19`) ensures the opening nag screen is always skipped on startup.

### Objective 2: Neutralizing the Closing Nag with NOPs

Searching for "Closing Nag" lands in the exit procedure around `00401107`. Unlike the opening nag, there is no conditional branch guarding the popup:

```assembly
00401107 | 6A 00            | push 0
00401109 | 68 D81A4100      | push crackme3.411AD8      ; "Closing Nag"
0040110E | 68 E41A4100      | push crackme3.411AE4      ; "I am a nag screen"
00401113 | 6A 00            | push 0
00401115 | FF15 14D14000    | call dword ptr [<&MessageBoxA>]
```

Without a branch to flip, we use NOP padding (`0x90` - No Operation). Highlighting all 15 bytes from `00401107` to `0040111A`, right-click and choose Fill with NOPs:

![Filling the Closing Nag call with NOP instructions]({{ '/images/crackme-reversing/11-crackme3-patch-nops.png' | relative_url }})

The CPU slides through these NOP instructions without executing any popup.

### Objective 3: Flipping the About Dialog

In the About box handler:

```assembly
004010D0 | 74 1A            | je crackme3.4010EC        ; jumps to push "Unregistered"
004010D2 | 6A 40            | push 40
004010D4 | 68 D81A4100      | push crackme3.411AD8      ; "About"
004010D9 | 68 F81A4100      | push crackme3.411AF8      ; "REGISTERED"
...
004010EC | 6A 40            | push 40
004010EE | 68 D81A4100      | push crackme3.411AD8      ; "About"
004010F3 | 68 041B4100      | push crackme3.411B04      ; "Unregistered"
```

Address `004010D0` contains `je 004010EC`. Changing `je` to `jne` redirects execution directly into the `REGISTERED` string block.

Save the patched file: both nag popups are gone, and the About box displays `REGISTERED`:

![CrackMe 3 successfully patched with REGISTERED status]({{ '/images/crackme-reversing/12-crackme3-registered.png' | relative_url }})

---

## Challenge 4: extending trial periods and basic arithmetic

Many commercial applications enforce a 30-day trial period. `CrackMe4.exe` simulates this mechanism. Upon execution, a window appears warning how many days remain in our trial:

![Trial period dialog showing remaining days]({{ '/images/crackme-reversing/13-crackme4-trial-dialog.png' | relative_url }})

### Analyzing System Time Logic

Searching for string `%d days trial period remaining` takes us to address `00401056`:

```assembly
00401036 | 0FB705 EE424100  | movzx eax, word ptr [4142EE] ; Day of month
0040103D | B9 1E000000      | mov ecx, 1E                  ; ECX = 30 (0x1E)
00401042 | 2BC8             | sub ecx, eax                 ; ECX = 30 - current_day
00401044 | 890D A0424100    | mov dword ptr [4142A0], ecx  ; Store remaining days
0040104A | 85C9             | test ecx, ecx
0040104C | 7F 07            | jg crackme4.401055
0040104E | 68 E81A4100      | push crackme4.411AE8         ; "Trial Period has expired"
00401053 | EB 19            | jmp crackme4.40106E
00401055 | 51               | push ecx                     ; Number of days
00401056 | 68 041B4100      | push crackme4.411B04         ; "%d days trial period remaining"
```

Look closely at lines `00401036` to `00401042`:
1. The program calls `GetLocalTime`, storing a `SYSTEMTIME` structure at `004142E0`.
2. Offset `+0xE` (`004142EE`) is `wDay` (the day of the month). `movzx eax, word ptr [4142EE]` loads this number into `eax`.
3. `mov ecx, 1E` loads hexadecimal `1E` (decimal `30`) into register `ecx`.
4. `sub ecx, eax` subtracts the current day of the month from 30!
5. If today is the 3rd, `30 - 3 = 27 days remaining`. If `ecx <= 0`, it jumps to "Trial Period has expired".

![Assembly instructions calculating remaining trial days]({{ '/images/crackme-reversing/14-crackme4-ecx-math.png' | relative_url }})

### Patching the Trial Duration

To extend the trial period, we simply increase the baseline limit at address `0040103D`:

```assembly
mov ecx, 1E   ; 30 days
```

to:

```assembly
mov ecx, 32   ; 50 in decimal
```

With `ecx` set to `0x32` (50), `50 - 3 = 47 days remaining`. Patching the file and restarting produces:

![Extended trial period successfully displaying 47 days]({{ '/images/crackme-reversing/15-crackme4-extended-trial.png' | relative_url }})

Trial extended. A single byte change (`1E` -> `32`) altered the application's business logic entirely.

---

## Challenge 5: dynamic serial algorithms and writing a Keygen

`CrackMe5.exe` elevates the game: the serial key is no longer hardcoded in plaintext. Instead, it is dynamically computed at runtime based on our input username and the current system date.

Entering a test username (`khanh`) and arbitrary serial key triggers the rejection message:

![CrackMe 5 rejecting invalid serial key]({{ '/images/crackme-reversing/16-crackme5-wrong-serial.png' | relative_url }})

### Tracing the Generator Algorithm

Searching for string references, we find a format string at `00411AE8`:

```text
"%s-%d%d%d"
```

Let's inspect the code pushing parameters into this format string around `00401146`:

```assembly
00401146 | 0FB705 A6424100  | movzx eax, word ptr [4142A6] ; wDay (e.g. 10)
0040114D | 50               | push eax
0040114E | 0FB705 A2424100  | movzx eax, word ptr [4142A2] ; wMonth (e.g. 6)
00401155 | 50               | push eax
00401156 | 0FB705 A0424100  | movzx eax, word ptr [4142A0] ; wYear (e.g. 2025)
0040115D | 05 D2040000      | add eax, 4D2                 ; eax = wYear + 0x4D2 (1234)
00401162 | 50               | push eax
00401163 | 8D45 D0          | lea eax, [ebp-30]            ; Username pointer ("khanh")
00401166 | 50               | push eax
00401167 | 8D45 90          | lea eax, [ebp-70]            ; Destination buffer
0040116A | 68 E81A4100      | push crackme5.411AE8         ; "%s-%d%d%d"
0040116F | 50               | push eax
00401170 | FF15 0CD14000    | call dword ptr [<&wsprintfA>]
```

![Disassembly of CrackMe 5 showing wsprintfA formatting]({{ '/images/crackme-reversing/17-crackme5-disasm-date.png' | relative_url }})

The assembly reveals the exact formula:
1. It calls `GetLocalTime` to extract the system date components: Year (`wYear`), Month (`wMonth`), and Day (`wDay`).
2. It takes `wYear` and adds hexadecimal `0x4D2` (which equals decimal `1234`).
   - For year 2025: `2025 + 1234 = 3259`.
   - For year 2026: `2026 + 1234 = 3260`.
3. It calls `wsprintfA` with format string `"%s-%d%d%d"`:
   - First argument `%s`: your input username.
   - Second argument `%d`: `wYear + 1234`.
   - Third argument `%d`: `wMonth`.
   - Fourth argument `%d`: `wDay`.

If username is `khanh`, date is June 10th, 2025:
* Serial: `khanh-3259610`.

If date is September 5th, 2025:
* Serial: `khanh-325995`.

### Writing a Python Keygen

Instead of patching the binary, we write a standalone Python script to generate valid keys for any name on any given day:

```python
import datetime

def generate_key(username: str, date: datetime.date = None) -> str:
    if date is None:
        date = datetime.date.today()
    transformed_year = date.year + 1234
    return f"{username}-{transformed_year}{date.month}{date.day}"

if __name__ == "__main__":
    name = "khanh"
    key = generate_key(name)
    print(f"Generated Serial for '{name}': {key}")
```

Entering the generated key into `CrackMe5.exe` yields immediate success:

![CrackMe 5 solved using algorithmic keygen]({{ '/images/crackme-reversing/18-crackme5-keygen-success.png' | relative_url }})

---

## Defense: how to protect software against binary reversing

These five challenges illustrate the fundamental vulnerabilities of naive client-side software protections. Every weakness here has an established defensive remedy:

| Vulnerability in CrackMe | How It Was Exploited | How Developers Should Fix It |
|---|---|---|
| Plaintext hardcoded strings | String reference search in debugger | Encrypt strings at compile time or use stack strings; resolve strings dynamically at runtime. |
| Single conditional jump checks | Flipped `JNE` to `JE` with 1 byte edit | Perform integrity checks on executable sections (`.text` checksum / digital signatures); verify authorization server-side. |
| In-memory popup execution | Filled `MessageBoxA` call with NOPs | Avoid client-only enforcement; tie core operational logic to cryptographic tokens rather than visual popups. |
| Predictable local clock reads | Modified `mov ecx, 1E` calculation | Fetch tamper-proof time stamps from a secure remote NTP server or digital license server. |
| Reversible keygen formula | Derived arithmetic in `wsprintfA` | Use asymmetric cryptography (RSA / Ed25519) for offline licensing: software verifies signature with public key; only developer holds private key. |

---

> Practice files archive: [github.com/tiendungdo12/crackmes-crackinglessons.com](https://github.com/tiendungdo12/crackmes-crackinglessons.com)  
> Analysis tool: [x64dbg / x32dbg](https://x64dbg.com/)

</div>

<div class="lang-vi" markdown="1">

> Mọi file nhị phân bên dưới là các bài tập CrackMe mẫu dùng cho mục đích học tập dịch ngược mã.
> Đừng bao giờ áp dụng kỹ thuật bẻ khóa này lên các phần mềm thương mại có bản quyền.

Khi bạn biên dịch một chương trình C hay C++, mã nguồn dễ đọc sẽ biến mất. Thứ còn lại
chỉ là mã máy: các byte dữ liệu thô mà CPU dịch thành các lệnh hợp ngữ (Assembly). Với nhiều
lập trình viên, file nhị phân `.exe` đó giống như một chiếc hộp đen bất khả xâm phạm.

Dịch ngược mã (Reverse Engineering) là kỹ thuật mở chiếc hộp đen đó. Một file CrackMe là
một chương trình được cố tình khóa lại nhằm mục đích luyện tập. Bạn không có mã nguồn, không
có file symbol (`.pdb`), và không có tài liệu hướng dẫn. Trong tay chỉ có một file thực thi
và một mục tiêu cụ thể: tìm đúng serial key, gỡ bỏ màn hình nag screen khó chịu, gia hạn
bản dùng thử đã hết hạn, hoặc viết ra một trình sinh key tự động (Keygen).

Trong bài viết này, ta sẽ cùng mổ xẻ năm bài CrackMe kinh điển dạng Win32 x86 bằng công cụ
`x32dbg`. Mỗi bài đại diện cho một kỹ thuật dịch ngược cốt lõi thường gặp trong phân tích mã độc
và bảo mật phần mềm.

| # | Thử thách | Cơ chế mục tiêu | Kỹ thuật giải quyết |
|---|---|---|---|
| 1 | CrackMe 1 | So sánh chuỗi kiểm tra cố định | Tìm string reference & đảo cờ nhảy điều kiện (`JNE` -> `JE`) |
| 2 | CrackMe 2 | Bản quyền qua file giấy phép (Keyfile) | Phân tích API đọc file & tạo file `keyfile.txt` hợp lệ |
| 3 | CrackMe 3 | Màn hình nhắc nhở (Nag screens) & trạng thái đăng ký | Lấp lệnh bằng NOP (`0x90`) & đổi nhánh gọi chuỗi |
| 4 | CrackMe 4 | Hạn dùng thử 30 ngày (Trial period) | Phân tích phép toán thời gian (`GetLocalTime`) & sửa trực tiếp giá trị |
| 5 | CrackMe 5 | Thuật toán sinh serial theo tên người dùng | Dịch ngược hàm định dạng (`wsprintfA`) & viết Keygen bằng Python |

---

## Môi trường thực hành

Bạn có thể tải đúng bộ mẫu CrackMe này về và tự thực hành từng bước trên Windows.

| | |
|---|---|
| Mục tiêu | CrackMe 1 đến 5 (Win32 Portable Executable) |
| Tác giả | Paul Chin / Cracking Lessons |
| Nguồn file | [Kho lưu trữ GitHub](https://github.com/tiendungdo12/crackmes-crackinglessons.com) |
| Công cụ | [x64dbg / x32dbg](https://x64dbg.com/) (Trình debugger x86 mã nguồn mở) |
| Mật khẩu giải nén | `crackinglessons.com` |

Các bước chuẩn bị:

1. Tải các file zip (`CrackMe1.zip` đến `CrackMe5.zip`) từ kho GitHub và giải nén bằng mật khẩu `crackinglessons.com`.
2. Tải và cài đặt `x64dbg`. Ta sẽ dùng file `x32dbg.exe` nằm trong thư mục `release/x32` vì các mẫu CrackMe này đều là ứng dụng 32-bit.
3. Khởi chạy `x32dbg`, cấu hình cơ bản (Options -> Preferences -> bỏ chọn System Breakpoint nếu muốn dừng thẳng ở Entry Point của chương trình).

---

## Challenge 1: tìm chuỗi cố định và đảo cờ lệnh nhảy

Ta bắt đầu với `CrackMe1.exe`. Chạy file, chương trình hiện ra một hộp thoại đơn giản với một ô nhập serial. Nhập thử một chuỗi bất kỳ rồi bấm Check, chương trình lập tức báo lỗi:

![CrackMe 1 báo lỗi Wrong serial key]({{ '/images/crackme-reversing/01-crackme1-wrong-key.png' | relative_url }})

Thông báo lỗi "Wrong serial key. Try again." chính là manh mối. Trong phần mềm đã biên dịch, chuỗi thông báo hiển thị cho người dùng bắt buộc phải nằm trong bộ nhớ. Lần ra vị trí đoạn text đó được gọi trong mã Assembly sẽ đưa ta đến đúng khối lệnh kiểm tra bản quyền.

### Tìm vết chuỗi trong x32dbg

Kéo file `CrackMe1.exe` vào `x32dbg`. Tại màn hình CPU, click chuột phải, chọn Search for -> All User Modules -> String References.

Gõ lọc từ khóa `Wrong serial key`:

![Tìm chuỗi thông báo lỗi trong danh sách String references]({{ '/images/crackme-reversing/02-crackme1-string-references.png' | relative_url }})

Double-click vào dòng tìm được, debugger sẽ nhảy thẳng đến địa chỉ `00401159`:

```assembly
00401137 | 85C0             | test eax, eax
00401139 | 75 19            | jne crackme1.401154
0040113B | 68 E81A4100      | push crackme1.411AE8      ; "Well done!"
00401140 | 68 F41A4100      | push crackme1.411AF4      ; "Cr4cked"
00401145 | 50               | push eax
00401146 | FF15 18D14000    | call dword ptr [<&MessageBoxA>]
...
00401154 | 68 001B4100      | push crackme1.411B00      ; "Cr4cked"
00401159 | 68 081B4100      | push crackme1.411B08      ; "Wrong serial key. Try again."
0040115E | 6A 00            | push 0
00401160 | FF15 18D14000    | call dword ptr [<&MessageBoxA>]
```

Để ý lệnh rẽ nhánh tại `00401139`: `jne crackme1.401154`. Nếu kết quả kiểm tra `eax` khác 0, chương trình sẽ nhảy cóc qua khối "Well done!" để lao thẳng xuống thông báo lỗi.

Cuộn ngược lên vài dòng trước `00401137`, ta thấy đoạn so sánh chuỗi nhập vào với vùng nhớ tại `00411AD8`:

![Mã hợp ngữ thực hiện so sánh chuỗi serial]({{ '/images/crackme-reversing/03-crackme1-cmp-jump.png' | relative_url }})

Tại địa chỉ `00411AD8` chứa sẵn chuỗi cố định: `cr4ckingL3ssons`.

Đến đây ta có hai cách vượt qua:
- Nhập key hợp lệ: điền thẳng `cr4ckingL3ssons` vào ô nhập.
- Patch file nhị phân: double-click vào dòng `00401139`, sửa lệnh `jne` (`75 19`) thành `je` (`74 19`), hoặc sửa `test eax, eax` thành `xor eax, eax`.

Lưu file đã vá qua menu File -> Patch file. Chạy thử file đã patch với một key bất kỳ, chương trình lập tức hiện thông báo thành công:

![Bẻ khóa thành công CrackMe 1]({{ '/images/crackme-reversing/04-crackme1-success.png' | relative_url }})

---

## Challenge 2: bản quyền qua file giấy phép (Keyfile)

`CrackMe2.exe` đưa ra một mô hình cấp phép quen thuộc khác: sử dụng file bản quyền riêng biệt (keyfile). Khi khởi chạy ứng dụng mà chưa có file giấy phép, cửa sổ hiển thị thông báo chưa đăng ký:

![CrackMe 2 thông báo phần mềm chưa đăng ký]({{ '/images/crackme-reversing/05-crackme2-unregistered.png' | relative_url }})

Hộp thoại ghi rõ "Unregistered Software. Please crack me." và hoàn toàn không có ô nhập serial key nào trên giao diện.

### Phân tích hàm kiểm tra file trong x32dbg

Nạp `CrackMe2.exe` vào `x32dbg`, nhấn `F9` để chạy qua breakpoint hệ thống đến mã nguồn chính của chương trình. Tìm kiếm chuỗi (String References), ta thấy ngay một tên file đáng ngờ: `keyfile.txt`.

![Phân tích điểm gọi keyfile.txt trong x32dbg]({{ '/images/crackme-reversing/06-crackme2-x32dbg.png' | relative_url }})

Đi tới địa chỉ gọi chuỗi tại `0040103E`, ta thấy rõ quy trình gọi các Win32 API xử lý file:

```assembly
0040103E | 68 281B4100      | push crackme2.411B28      ; "keyfile.txt"
00401043 | FF15 00D04000    | call dword ptr [<&CreateFileA>]
00401049 | 8BF0             | mov esi, eax              ; Lưu handle trả về
0040104B | 83FE FF          | cmp esi, -1               ; So sánh với INVALID_HANDLE_VALUE (-1)
0040104E | 74 51            | je crackme2.4010A1        ; Không tìm thấy file -> nhảy sang nhánh Unregistered
00401050 | 6A 00            | push 0
00401052 | 68 04434100      | push crackme2.414304
00401057 | 6A 1F            | push 1F                   ; nNumberOfBytesToRead = 31 bytes
00401059 | 68 E4424100      | push crackme2.4142E4      ; Bộ đệm lưu nội dung đọc được
0040105E | 56               | push esi                  ; Handle của file
0040105F | FF15 08D04000    | call dword ptr [<&ReadFile>]
...
0040109B | FF15 04D04000    | call dword ptr [<&CloseHandle>]
```

Quy trình kiểm tra diễn ra theo ba bước:
1. `CreateFileA` cố gắng mở file `keyfile.txt` ngay trong thư mục chứa chương trình.
2. Nếu file không tồn tại, hàm trả về `-1` (`INVALID_HANDLE_VALUE`), cờ nhảy `je crackme2.4010A1` kích hoạt đưa luồng thực thi xuống nhánh "Unregistered Software".
3. Nếu file tồn tại, `ReadFile` đọc tối đa 31 byte nội dung vào bộ đệm tại `004142E4`, sau đó đóng file bằng `CloseHandle` và hiển thị chuỗi đọc được sau tiền tố `Registered to: `. Chương trình không hề có thuật toán mã hóa hay kiểm tra chữ ký của file.

### Tạo file keyfile.txt hợp lệ

Biết được quy luật, ta chỉ cần tạo một file văn bản tên `keyfile.txt` nằm cùng thư mục với `CrackMe2.exe`. Mở Notepad, nhập tên người dùng mong muốn:

![Tạo file keyfile.txt chứa tên người dùng bằng Notepad]({{ '/images/crackme-reversing/07-crackme2-notepad.png' | relative_url }})

Lưu file với định dạng ANSI chuẩn. Khởi chạy lại `CrackMe2.exe`:

![CrackMe 2 mở khóa thành công với tên người dùng]({{ '/images/crackme-reversing/08-crackme2-registered.png' | relative_url }})

Tiêu đề cửa sổ lập tức đổi thành `Registered to: khanh1916`. Thử thách được giải quyết hoàn toàn mà không cần sửa bất kỳ byte nào trong file thực thi.

---

## Challenge 3: gỡ bỏ nag screen và vá lệnh bằng NOP

`CrackMe3.exe` mô phỏng dạng phần mềm thường xuyên hiển thị các cửa sổ làm phiền (nag screen) lúc mở và lúc tắt ứng dụng, đồng thời ô About chỉ ghi trạng thái chưa đăng ký. Thử thách đặt ra ba mục tiêu cần xử lý:
1. Gỡ màn hình nag lúc mở phần mềm ("Opening Nag").
2. Gỡ màn hình nag lúc tắt phần mềm ("Closing Nag").
3. Chuyển trạng thái trong hộp About từ "Unregistered" sang "REGISTERED".

![Các màn hình nag và hộp thoại About của CrackMe 3]({{ '/images/crackme-reversing/09-crackme3-nags-composite.png' | relative_url }})

### Mục tiêu 1: Bỏ qua Opening Nag

Mở `CrackMe3.exe` trong `x32dbg`, quét String references và tìm chuỗi "Opening Nag":

![Tìm vị trí Opening Nag trong x32dbg]({{ '/images/crackme-reversing/10-crackme3-opening-nag.png' | relative_url }})

Double-click để nhảy tới địa chỉ `0040102D`:

```assembly
0040101D | 833D A0424100 00 | cmp dword ptr [4142A0], 0
00401024 | A3 A4424100      | mov dword ptr [4142A4], eax
00401029 | 75 19            | jne crackme3.401044
0040102B | 6A 00            | push 0
0040102D | 68 D81A4100      | push crackme3.411AD8      ; "Opening Nag"
00401032 | 68 E41A4100      | push crackme3.411AE4      ; "I am a nag screen"
00401037 | 6A 00            | push 0
00401039 | FF15 14D14000    | call dword ptr [<&MessageBoxA>]
0040103F | A1 A4424100      | mov eax, dword ptr [4142A4]
00401044 | 56               | push esi
```

Tại dòng `00401029`, lệnh `jne crackme3.401044` nhảy cóc qua lệnh gọi `MessageBoxA` nếu thỏa mãn điều kiện. Ta đảo lệnh này bằng cách sửa `jne` thành `je` (`74 19`). Khi khởi động, chương trình sẽ luôn nhảy qua hộp thoại nag đầu tiên.

### Mục tiêu 2: Triệt tiêu Closing Nag bằng NOP

Tìm kiếm chuỗi "Closing Nag" sẽ dẫn ta tới hàm xử lý đóng chương trình quanh địa chỉ `00401107`. Khác với lúc khởi động, tại đây không có bất kỳ lệnh nhảy điều kiện nào để rẽ nhánh; lệnh gọi `MessageBoxA` được thực thi trực tiếp:

```assembly
00401107 | 6A 00            | push 0
00401109 | 68 D81A4100      | push crackme3.411AD8      ; "Closing Nag"
0040110E | 68 E41A4100      | push crackme3.411AE4      ; "I am a nag screen"
00401113 | 6A 00            | push 0
00401115 | FF15 14D14000    | call dword ptr [<&MessageBoxA>]
```

Khi không có cờ nhảy để đảo, ta dùng kỹ thuật lấp lệnh bằng NOP (`0x90` - No Operation). Ta bôi đen toàn bộ dải lệnh từ `00401107` đến `0040111A` (tổng cộng 15 bytes), click chuột phải, chọn Fill with NOPs:

![Lấp các lệnh gọi Closing Nag bằng byte NOP]({{ '/images/crackme-reversing/11-crackme3-patch-nops.png' | relative_url }})

Khi gặp 15 byte NOP này, CPU chỉ bỏ qua mà không thực thi bất kỳ thao tác nào, nhờ đó hộp thoại thông báo khi tắt ứng dụng hoàn toàn bị vô hiệu hóa.

### Mục tiêu 3: Đổi trạng thái trong About

Trong hàm hiển thị hộp thoại About:

```assembly
004010D0 | 74 1A            | je crackme3.4010EC        ; nhảy xuống chuỗi "Unregistered"
004010D2 | 6A 40            | push 40
004010D4 | 68 D81A4100      | push crackme3.411AD8      ; "About"
004010D9 | 68 F81A4100      | push crackme3.411AF8      ; "REGISTERED"
...
004010EC | 6A 40            | push 40
004010EE | 68 D81A4100      | push crackme3.411AD8      ; "About"
004010F3 | 68 041B4100      | push crackme3.411B04      ; "Unregistered"
```

Tại `004010D0`, lệnh đang là `je 004010EC`. Ta sửa `je` thành `jne`, ép luồng thực thi đi thẳng vào chuỗi `REGISTERED`.

Lưu file đã vá và mở lại: cả hai màn hình nag biến mất hoàn toàn, mục About hiển thị trạng thái `REGISTERED`:

![CrackMe 3 sau khi được patch hoàn chỉnh với trạng thái REGISTERED]({{ '/images/crackme-reversing/12-crackme3-registered.png' | relative_url }})

---

## Challenge 4: nới hạn dùng thử qua phân tích phép toán

Rất nhiều phần mềm thương mại áp dụng chính sách dùng thử 30 ngày. `CrackMe4.exe` tạo dựng lại đúng cơ chế này. Khi mở app, một hộp thoại cảnh báo số ngày dùng thử còn lại:

![Hộp thoại hiển thị số ngày dùng thử còn lại]({{ '/images/crackme-reversing/13-crackme4-trial-dialog.png' | relative_url }})

### Phân tích logic đồng hồ hệ thống

Tìm chuỗi `%d days trial period remaining` dẫn ta đến địa chỉ `00401056`:

```assembly
00401036 | 0FB705 EE424100  | movzx eax, word ptr [4142EE] ; Lấy ngày trong tháng
0040103D | B9 1E000000      | mov ecx, 1E                  ; ECX = 30 (0x1E)
00401042 | 2BC8             | sub ecx, eax                 ; ECX = 30 - ngày_hiện_tại
00401044 | 890D A0424100    | mov dword ptr [4142A0], ecx  ; Lưu số ngày còn lại
0040104A | 85C9             | test ecx, ecx
0040104C | 7F 07            | jg crackme4.401055
0040104E | 68 E81A4100      | push crackme4.411AE8         ; "Trial Period has expired"
00401053 | EB 19            | jmp crackme4.40106E
00401055 | 51               | push ecx                     ; Đẩy số ngày vào tham số
00401056 | 68 041B4100      | push crackme4.411B04         ; "%d days trial period remaining"
```

Nhìn kỹ đoạn lệnh từ `00401036` đến `00401042`:
1. Chương trình gọi hàm `GetLocalTime`, trả về cấu trúc thời gian `SYSTEMTIME` tại vùng nhớ `004142E0`.
2. Offset `+0xE` (`004142EE`) chính là trường `wDay` (ngày trong tháng). Lệnh `movzx eax, word ptr [4142EE]` nạp con số ngày này vào thanh ghi `eax`.
3. Lệnh `mov ecx, 1E` gán giá trị hex `1E` (tức 30 trong hệ thập phân) vào `ecx`.
4. Lệnh `sub ecx, eax` lấy 30 trừ đi ngày hiện tại.
5. Nếu hôm nay là ngày 3, thì `30 - 3 = 27 ngày còn lại`. Nếu `ecx <= 0`, chương trình nhảy sang báo "Trial Period has expired".

![Các lệnh Assembly tính toán số ngày dùng thử]({{ '/images/crackme-reversing/14-crackme4-ecx-math.png' | relative_url }})

### Vá mốc thời gian dùng thử

Muốn nới hạn dùng thử, ta không cần tắt đoạn so sánh, mà chỉ cần tăng mốc giới hạn ban đầu.
Tại địa chỉ `0040103D`, ta sửa:

```assembly
mov ecx, 1E   ; 30 ngày
```

thành:

```assembly
mov ecx, 32   ; 50 ngày (trong hệ thập phân)
```

Với `ecx` đặt thành `0x32` (50), lấy `50 - 3 = 47 ngày còn lại`. Lưu file patch và mở lại:

![Hạn dùng thử được gia hạn thành công lên 47 ngày]({{ '/images/crackme-reversing/15-crackme4-extended-trial.png' | relative_url }})

Hạn dùng thử đã được kéo dài. Chỉ một byte duy nhất (`1E` thành `32`) đã làm thay đổi hoàn toàn logic nghiệp vụ của ứng dụng.

---

## Challenge 5: giải mã thuật toán sinh serial và viết Keygen

`CrackMe5.exe` nâng độ khó lên một mức mới: serial key không còn nằm sẵn dưới dạng văn bản tĩnh trong file, mà được tính toán động ngay lúc chạy dựa trên tên người dùng nhập vào kết hợp với ngày tháng của hệ thống.

Khởi chạy ứng dụng, nhập thử tên (`khanh`) và một serial ngẫu nhiên, chương trình lập tức từ chối và báo lỗi:

![CrackMe 5 từ chối serial key ngẫu nhiên]({{ '/images/crackme-reversing/16-crackme5-wrong-serial.png' | relative_url }})

### Bóc tách thuật toán sinh mã

Quét danh sách String references, ta bắt gặp chuỗi định dạng tại `00411AE8`:

```text
"%s-%d%d%d"
```

Xem đoạn code đẩy tham số vào định dạng này quanh địa chỉ `00401146`:

```assembly
00401146 | 0FB705 A6424100  | movzx eax, word ptr [4142A6] ; wDay (ví dụ ngày 10)
0040114D | 50               | push eax
0040114E | 0FB705 A2424100  | movzx eax, word ptr [4142A2] ; wMonth (ví dụ tháng 6)
00401155 | 50               | push eax
00401156 | 0FB705 A0424100  | movzx eax, word ptr [4142A0] ; wYear (ví dụ năm 2025)
0040115D | 05 D2040000      | add eax, 4D2                 ; eax = wYear + 0x4D2 (1234)
00401162 | 50               | push eax
00401163 | 8D45 D0          | lea eax, [ebp-30]            ; Con trỏ chuỗi Username ("khanh")
00401166 | 50               | push eax
00401167 | 8D45 90          | lea eax, [ebp-70]            ; Bộ đệm lưu kết quả
0040116A | 68 E81A4100      | push crackme5.411AE8         ; "%s-%d%d%d"
0040116F | 50               | push eax
00401170 | FF15 0CD14000    | call dword ptr [<&wsprintfA>]
```

![Đoạn hợp ngữ định dạng serial key bằng wsprintfA]({{ '/images/crackme-reversing/17-crackme5-disasm-date.png' | relative_url }})

Đoạn mã hợp ngữ cho thấy rõ công thức tính toán:
1. Gọi `GetLocalTime` lấy các thành phần ngày tháng: Năm (`wYear`), Tháng (`wMonth`), và Ngày (`wDay`).
2. Lấy `wYear` cộng thêm giá trị hex `0x4D2` (tương đương 1234 trong hệ thập phân).
   - Với năm 2025: `2025 + 1234 = 3259`.
   - Với năm 2026: `2026 + 1234 = 3260`.
3. Gọi hàm `wsprintfA` với mẫu `"%s-%d%d%d"`:
   - Tham số `%s` đầu tiên: chuỗi Username bạn gõ vào.
   - Tham số `%d` thứ hai: `wYear + 1234`.
   - Tham số `%d` thứ ba: `wMonth`.
   - Tham số `%d` thứ tư: `wDay`.

Nếu Username là `khanh`, ngày chạy là 10/06/2025:
* Serial hợp lệ là: `khanh-3259610`.

Nếu ngày chạy là 05/09/2025:
* Serial hợp lệ là: `khanh-325995`.

### Tự viết trình sinh key (Keygen bằng Python)

Thay vì vá mã nhị phân, ta viết một script Python ngắn để tự tạo serial chuẩn cho bất kỳ ai vào bất kỳ ngày nào:

```python
import datetime

def generate_key(username: str, date: datetime.date = None) -> str:
    if date is None:
        date = datetime.date.today()
    transformed_year = date.year + 1234
    return f"{username}-{transformed_year}{date.month}{date.day}"

if __name__ == "__main__":
    name = "khanh"
    key = generate_key(name)
    print(f"Serial hợp lệ cho '{name}': {key}")
```

Nhập key vừa sinh vào `CrackMe5.exe`, hộp thoại báo thành công hiện lên ngay lập tức:

![Bẻ khóa CrackMe 5 thành công bằng Keygen]({{ '/images/crackme-reversing/18-crackme5-keygen-success.png' | relative_url }})

---

## Remediation

Cả năm thử thách trên cho thấy các điểm yếu cố hữu khi đặt toàn bộ cơ chế bảo vệ ở phía client (máy người dùng). Mỗi điểm yếu đều có biện pháp khắc phục chuẩn mực từ góc nhìn của lập trình viên:

| Điểm yếu trong CrackMe | Cách thức bị khai thác | Cách khắc phục chuẩn mực |
|---|---|---|
| Chuỗi cố định để lộ dạng text | Tìm string reference trong debugger | Mã hóa chuỗi nhạy cảm khi biên dịch hoặc dùng stack string; giải mã động trong runtime. |
| Chỉ kiểm tra qua một lệnh nhảy đơn | Đảo `JNE` thành `JE` chỉ với 1 byte | Kiểm tra tính toàn vẹn của phân vùng code (`.text` hash checksum / chữ ký số); xác thực bản quyền qua server. |
| Nag screen chạy cục bộ | Lấp lệnh gọi `MessageBoxA` bằng NOP | Không phụ thuộc vào giao diện hiển thị; gắn logic nghiệp vụ cốt lõi với khóa giải mã thay vì hiển thị popup. |
| Lấy giờ từ đồng hồ máy tính cá nhân | Sửa phép toán `mov ecx, 1E` | Đồng bộ thời gian qua server NTP có chứng thực hoặc kiểm tra token từ license server. |
| Thuật toán sinh key đối xứng dễ đoán | Dịch ngược phép cộng trong `wsprintfA` | Áp dụng mật mã bất đối xứng (RSA / Ed25519): phần mềm chỉ lưu public key để xác thực chữ ký của license; private key nằm an toàn ở server nhà phát triển. |

---

> File mẫu thực hành: [github.com/tiendungdo12/crackmes-crackinglessons.com](https://github.com/tiendungdo12/crackmes-crackinglessons.com)  
> Công cụ phân tích: [x64dbg / x32dbg](https://x64dbg.com/)

</div>
