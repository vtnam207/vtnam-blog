---
title: "W1 Recruit 2026"
published: 2026-09-13
description: "Write-up Rev_easy_rev và Cookies: anti-debug, payload giải mã lúc chạy và VM."
ctf: "W1 Recruit 2026"
category: "Reverse Engineering"
tags: ['CTF', 'Reverse Engineering', 'Linux', 'Windows', 'Anti-Debug', 'VM']
lang: vi
draft: false
---

> Bản gốc: [HackMD](https://hackmd.io/@vtnam207/SyopL57tGg)

## Overview
Đề tuyển quân năm nay có 3 bài và mình thì làm được 1 bài, sau khi được các a hint.



## Rev_easy_rev
![image](/assets/posts/w1-recruit-2026/SJId0RQtzg.png)
> Hint:A hidden function was modified when using debug mode, try to bypass

Chall duy nhất mình làm được (và firstblood) trong giải.
### **1. Phân tích**
Check file và chạy thử thì thấy chall này là 1 flag checker:
```
file challenge
challenge: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), static-pie linked, stripped

./challenge
== Vaulted Flag Checker ==
flag> abcde
Wrong flag.
```

Đưa vào IDA để phân tích sâu hơn:
![image](/assets/posts/w1-recruit-2026/H10UZJNKfe.png)
Chương trình chỉ có 2 hàm mà 1 hàm là start cho nên chắc chắn hàm còn lại sẽ là hàm main thực thi chương trình.


#### Pseudo code

```cpp
_BOOL8 sub_7FFFF7FFB020()
{
  size_t count; // rdx
  signed __int64 v1; // rax
  __int64 v2; // rbx
  char *v3; // rsi
  __int64 v4; // rax
  __int64 v5; // rax
  int n73; // ecx
  char n102; // dl
  __int64 i; // rax
  char v9; // dl
  int n91; // ecx
  char n15; // dl
  __int64 j; // rax
  char v13; // dl
  __int64 fd; // rax
  unsigned int fd_1; // edi
  unsigned __int64 n9; // r13
  signed __int64 v17; // rax
  struct timespec *buf_1; // rdx
  __int64 v19; // rcx
  __int64 k; // rax
  _BOOL8 v21; // r13
  signed __int64 v22; // rax
  __syscall_slong_t v23; // rdx
  __syscall_slong_t v24; // rbp
  __int64 v25; // rcx
  __int64 m; // rdx
  signed __int64 v27; // rax
  unsigned __int64 off; // r9
  __syscall_slong_t v29; // rdx
  __int64 v30; // rbp
  unsigned __int64 v31; // rbp
  unsigned __int64 v32; // rbp
  __int64 (__fastcall *addr)(_QWORD); // rbx
  unsigned __int64 v34; // r8
  __int64 n92; // rsi
  __int64 n90; // rdx
  char v37; // r9
  unsigned __int64 v38; // rdi
  char *v39; // r10
  unsigned __int64 n92_1; // rax
  unsigned __int64 v42; // rax
  int v43; // r12d
  signed __int64 v44; // rax
  size_t count_2; // rdx
  const char *Correct__n; // rsi
  signed __int64 v47; // rax
  unsigned __int64 n9_1; // rax
  char n32; // dl
  signed __int64 v50; // rax
  size_t count_1; // rdx
  signed __int64 v52; // rax
  _BYTE v53[11]; // [rsp+5h] [rbp-3D3h]
  char filename[32]; // [rsp+10h] [rbp-3C8h] BYREF
  char v55[128]; // [rsp+30h] [rbp-3A8h] BYREF
  struct timespec buf[50]; // [rsp+B0h] [rbp-328h] BYREF

  count = 0LL;
  do
    ++count;
  while ( ::buf[count] );
  v1 = sys_write(1u, "== Vaulted Flag Checker ==\nflag> ", count);
  v2 = 0LL;
LABEL_4:
  v3 = &v55[v2];
  v4 = sys_read(0, &v55[v2], 127 - v2);
  if ( v4 > 0 )
  {
    v5 = v2 + v4;
    while ( *v3 != 10 && *v3 != 13 )
    {
      ++v2;
      ++v3;
      if ( v5 == v2 )
      {
        if ( (unsigned __int64)(v5 + 1) <= 127 )
          goto LABEL_4;
        v55[v5] = 0;
        goto LABEL_11;
      }
    }
  }
  *v3 = 0;
  if ( !v2 )
    return 1LL;
LABEL_11:
  n73 = 73;
  n102 = 102;
  for ( i = 0LL; ; n102 = byte_7FFFF7FFC050[i] )
  {
    v9 = n73 ^ n102;
    n73 += 29;
    filename[i++] = v9;
    if ( i == 17 )
      break;
  }
  filename[17] = 0;
  n91 = 91;
  n15 = 15;
  for ( j = 0LL; ; n15 = byte_7FFFF7FFC040[j] )
  {
    v13 = n91 ^ n15;
    n91 += 29;
    v53[j++] = v13;
    if ( j == 10 )
      break;
  }
  v53[10] = 0;
  fd = sys_openat(-100, filename, 0, 0);
  fd_1 = fd;
  if ( fd >= 0 )
  {
    n9 = sys_read(fd, (char *)buf, 0x300uLL);
    v17 = sys_close(fd_1);
    if ( (__int64)n9 > 0 )
    {
      buf_1 = buf;
      v19 = 0LL;
      if ( n9 > 9 )
      {
LABEL_20:
        for ( k = 0LL; k != 10; ++k )
        {
          if ( *((_BYTE *)&buf_1->tv_sec + k) != v53[k] )
          {
            ++v19;
            buf_1 = (struct timespec *)((char *)buf_1 + 1);
            if ( n9 - 9 != v19 )
              goto LABEL_20;
            goto LABEL_24;
          }
        }
        if ( (int)v19 >= 0 )
        {
          n9_1 = (int)v19 + 10LL;
          if ( n9_1 < n9 )
          {
            while ( 1 )
            {
              n32 = *((_BYTE *)&buf[0].tv_sec + n9_1);
              if ( n32 != 32 && n32 != 9 )
                break;
              if ( ++n9_1 >= n9 )
                goto LABEL_24;
            }
            if ( n9_1 < n9 )
            {
              v21 = (unsigned int)*((unsigned __int8 *)&buf[0].tv_sec + n9_1) - 49 <= 8;
              goto LABEL_25;
            }
          }
        }
      }
    }
  }
LABEL_24:
  v21 = 0LL;
LABEL_25:
  v22 = sys_clock_gettime(1, buf);
  v24 = buf[0].tv_nsec + 1000000000 * buf[0].tv_sec;
  v25 = 0x123456789ABCDEF0LL;
  if ( v22 )
    v24 = v23;
  for ( m = -7046029254386353131LL; m != -7046029254386213131LL; ++m )
    v25 = (((v25 ^ (unsigned __int64)(v25 << 7)) >> 9) ^ v25 ^ (v25 << 7)) + m;
  qword_7FFFF7FFE808 = v25;
  v27 = sys_clock_gettime(1, buf);
  v29 = buf[0].tv_nsec + 1000000000 * buf[0].tv_sec;
  if ( v27 )
    v29 = 0LL;
  v30 = v21 | (2LL * ((unsigned __int64)(v29 - v24) > 0x11E1A300));
  v31 = (__ROL8__(0xD6E8FEB86659FD93LL * v30, 17) ^ (0xD6E8FEB86659FD93LL * v30)) - 0x5A5CA9B1D80E6393LL * v30;
  v32 = (__ROL8__(v31, 9) + __ROR8__(v31, 23)) ^ v31;
  addr = (__int64 (__fastcall *)(_QWORD))sys_mmap(0LL, 0x1000uLL, 3uLL, 0x22uLL, 0xFFFFFFFFFFFFFFFFLL, off);
  if ( (unsigned __int64)addr >= 0xFFFFFFFFFFFFF001LL )
  {
LABEL_59:
    count_1 = 0LL;
    do
      ++count_1;
    while ( aWrongFlag[count_1] );
    v52 = sys_write(1u, "Wrong flag.\n", count_1);
    return 1LL;
  }
  v34 = 0LL;
  n92 = 92LL;
  n90 = 0LL;
  v37 = 0xC3;
  v38 = 0xAFBA1A4D97780E2FLL;
  v39 = (char *)&unk_7FFFF7FFE000 + (((unsigned __int16)dword_7FFFF7FFE800 ^ 014705) & 0x7FF);
  while ( 1 )
  {
    v38 ^= v32 & (((n90 ^ 0x40 | (unsigned __int64)-(n90 ^ 0x40)) >> 63) - 1);
    if ( (n90 & 7) == 0 )
    {
      v38 -= 0x61C8864680B583EBLL;
      v42 = 0x94D049BB133111EBLL
          * ((0xBF58476D1CE4E5B9LL * (v38 ^ (v38 >> 30))) ^ ((0xBF58476D1CE4E5B9LL * (v38 ^ (v38 >> 30))) >> 27));
      v34 = v42 ^ (v42 >> 31);
    }
    *((_BYTE *)addr + n90) = v37 ^ (v34 >> (8 * ((unsigned __int8)n90 & 7u)));
    if ( n90 == 90 )
      break;
    n92_1 = n92 + 73;
    v37 = v39[n92];
    n92 -= 184LL;
    if ( n92_1 <= 0x100 )
      n92 = n92_1;
    ++n90;
  }
  if ( sys_mprotect((unsigned __int64)addr, 0x1000uLL, 5uLL) )
  {
    v50 = sys_munmap((unsigned __int64)addr, 0x1000uLL);
    goto LABEL_59;
  }
  if ( !addr )
    goto LABEL_59;
  v43 = addr(v55);
  v44 = sys_munmap((unsigned __int64)addr, 0x1000uLL);
  count_2 = 0LL;
  if ( v43 )
  {
    Correct__n = "Correct!\n";
    do
      ++count_2;
    while ( aCorrect[count_2] );
  }
  else
  {
    Correct__n = "Wrong flag.\n";
    do
      ++count_2;
    while ( aWrongFlag[count_2] );
  }
  v47 = sys_write(1u, Correct__n, count_2);
  return v43 == 0;
}
```
Nếu đọc hết hàm sub_7FFFF7FFB020, ta sẽ thấy nó không chứa logic thực sự để kiểm tra flag.
Hàm này nó là một packer: Phát hiện Debugger, tự động decrypt một đoạn shellcode vào memory, và sau đó thực thi đoạn mã đó để kiểm tra flag.

Mình sẽ phân tích từng phần để hiểu logic cách hàm này hoạt động ra sao:
![image](/assets/posts/w1-recruit-2026/BkPy8JNYMe.png)
Từ đoạn đầu sys_write cho đến return:
Đơn giản là in ra chuỗi `"== Vaulted Flag Checker == \nflag>"`, chờ người dùng nhập và dùng sysread để đọc tối đa 127 bytes từ người dùng và lưu vào mảng v55.

Tiếp đến từ labbel_11 đến label_24
```cpp
LABEL_11:
  n73 = 73;
  n102 = 102;
  for ( i = 0LL; ; n102 = byte_7FFFF7FFC050[i] )
  {
    v9 = n73 ^ n102;
    n73 += 29;
    filename[i++] = v9;
    if ( i == 17 )
      break;
  }
  filename[17] = 0;
  n91 = 91;
  n15 = 15;
  for ( j = 0LL; ; n15 = byte_7FFFF7FFC040[j] )
  {
    v13 = n91 ^ n15;
    n91 += 29;
    v53[j++] = v13;
    if ( j == 10 )
      break;
  }
  v53[10] = 0;
  fd = sys_openat(-100, filename, 0, 0);
  fd_1 = fd;
  if ( fd >= 0 )
  {
    n9 = sys_read(fd, (char *)buf, 0x300uLL);
    v17 = sys_close(fd_1);
    if ( (__int64)n9 > 0 )
    {
      buf_1 = buf;
      v19 = 0LL;
      if ( n9 > 9 )
      {
LABEL_20:
        for ( k = 0LL; k != 10; ++k )
        {
          if ( *((_BYTE *)&buf_1->tv_sec + k) != v53[k] )
          {
            ++v19;
            buf_1 = (struct timespec *)((char *)buf_1 + 1);
            if ( n9 - 9 != v19 )
              goto LABEL_20;
            goto LABEL_24;
          }
        }
        if ( (int)v19 >= 0 )
        {
          n9_1 = (int)v19 + 10LL;
          if ( n9_1 < n9 )
          {
            while ( 1 )
            {
              n32 = *((_BYTE *)&buf[0].tv_sec + n9_1);
              if ( n32 != 32 && n32 != 9 )
                break;
              if ( ++n9_1 >= n9 )
                goto LABEL_24;
            }
            if ( n9_1 < n9 )
            {
              v21 = (unsigned int)*((unsigned __int8 *)&buf[0].tv_sec + n9_1) - 49 <= 8;
              goto LABEL_25;
            }
          }
        }
      }
    }
  }
LABEL_24:
  v21 = 0LL;
```
Nếu đọc kĩ sẽ thấy đây là 1 hàm anti-debug (sau giải mình có research thì biết đây là anti-debug bằng filesystem (TracerPid)).

Hàm này là một cơ chế anti-debug trên Linux, sử dụng thông tin trong filesystem /proc để kiểm tra process hiện tại có đang bị debugger theo dõi hay không.

Trước tiên, chương trình không ghi trực tiếp chuỗi /proc/self/status vào binary mà tự tính toán từng ký tự rồi lưu vào filename. Đây là một cách làm rối (obfuscation) để tránh việc nhìn vào binary là thấy ngay đường dẫn cần mở.

Sau khi tạo xong, filename chính là đường dẫn tới file chứa thông tin trạng thái của process, sau đó chương trình gọi sys_openat() để mở file và sys_read() để đọc nội dung của nó vào buffer.

Tổng quan đoạn code
> 1.  Đoạn code trên chạy vòng lặp tính toán và gán `filename[i++] = v9; và v53[j++] = v13;`
> 2.  Sau đó nó sẽ dùng `sys_openat` để mở lại cái filename vừa tính toán đó (file này dài 17 kí tự )
> 3.  Rồi dùng `sys_read(fd, (char *)buf, 0x300uLL);` để đọc nội dung file và rồi tìm chuỗi 10 byte trong file
> 4. Ngay sau chuỗi đó, nó bỏ qua tất cả các kí tự space (space = 32) và  Tab (Tab = 9).
> 5. Cuối cùng, nó đọc ký tự liền kề sau khoảng trắng đó, và kiểm tra xem ký tự này có phải là một chữ số lớn hơn 0 (từ 1 đến 9) hay không.
>
Để dễ hình dung hơn thì mình sẽ tóm gọn code lại
```cpp
    ...
  fd = sys_openat(-100, filename, 0, 0); //Mở chuỗi 17 bytes ("/proc/self/status") như một File
  n9 = sys_read(fd, (char *)buf, 0x300uLL); // Đọc nội dung file
  //
    ...
        //Tìm chuỗi 10 byte trong file, chuỗi đó là "TracerPid:"
        for ( k = 0LL; k != 10; ++k )
        {
          if ( *((_BYTE *)&buf_1->tv_sec + k) != v53[k] )
          {
            ++v19;
            buf_1 = (struct timespec *)((char *)buf_1 + 1);
            if ( n9 - 9 != v19 )
              goto LABEL_20;
            goto LABEL_24;
          }
        }
    ...
            while ( 1 )
            {
              n32 = *((_BYTE *)&buf[0].tv_sec + n9_1);
              // Bỏ qua space và tab
              if ( n32 != 32 && n32 != 9 )
                break;
              if ( ++n9_1 >= n9 )
                goto LABEL_24;
            }
            if ( n9_1 < n9 )
            {
               // Kiểm tra xem ký tự tiếp theo có phải từ 1 -> 9 không
              v21 = (unsigned int)*((unsigned __int8 *)&buf[0].tv_sec + n9_1) - 49 <= 8;
              goto LABEL_25;
            }
    LABEL_24:
      v21 = 0LL;
 // Sau cùng lưu kết quả vào v21

```
Trên Linux,nếu `TracerPid: 0` nghĩa là process không bị process khác trace hay debug. Ngược lại, nếu `TracerPid != 0` thì process đang bị một process khác theo dõi. Vì vậy, điều kiện kiểm tra 1 -> 9 chính là dấu hiệu cho thấy chương trình phát hiện đang bị debug.

Tới đoạn logic tiếp theo
   ![image](/assets/posts/w1-recruit-2026/ry3GQHVKzg.png)

Ở đây ta lại thấy có xuất hiện thêm 1 hàm anti-debug nữa, đây là anti-debug timming.

Khi process bị debug, thì thời gian bị delay giữa các instructions là khá lớn so với lúc bình thường.Và vì nó có thể đo thời gian thực thi theo thời gian thực, nên nếu thời gian quá lâu thì sẽ bị chương trình phát hiện là đang debug.

```cpp
// Lấy thời gian lần 1
v22 = sys_clock_gettime(1, buf);
v24 = buf[0].tv_nsec + 1000000000 * buf[0].tv_sec;
 ....
// lấy thời gian lần 2
v27 = sys_clock_gettime(1, buf);
v29 = buf[0].tv_nsec + 1000000000 * buf[0].tv_sec;

// Đo tổng thời gian chạy từ lần 1 sang lần 2 (nếu lớn hơn 0x11E1A300 thì sẽ bị dính anti-debug)
(2LL * ((unsigned __int64)(v29 - v24) > 0x11E1A300))
```
```cpp
v30 = v21 | (2LL * ((unsigned __int64)(v29 - v24) > 0x11E1A300));
```
> Có thể thấy nếu :
> * v30 = 0 thì không có debug nào cả
> * v30 = 1 bị phát hiện bởi file
> * v30 = 2 bị phát hiện bởi time
> * v30 = 3 bị phát hiện bới cả 2

Sau khi thực hiện anti-debug check, chương trình không thoát ngay khi phát hiện môi trường bất thường. Thay vào đó, kết quả của check được sử dụng để làm thay đổi quá trình sinh khóa và giải mã payload.
![image](/assets/posts/w1-recruit-2026/BJup9BVtzl.png)

Cụ thể, giá trị v30 được biến đổi qua một chuỗi phép toán gồm XOR, rotate và multiplication:

```cpp
v31 = (__ROL8__(0xD6E8FEB86659FD93LL * v30, 17) ^ (0xD6E8FEB86659FD93LL * v30)) - 0x5A5CA9B1D80E6393LL * v30;
v32 = (__ROL8__(v31, 9) + __ROR8__(v31, 23)) ^ v31;
```

Với `v30 = 0, ta có v31 = 0 và v32 = 0`. Khi `v30` thay đổi, chuỗi phép biến đổi này tạo ra một giá trị `v32` phụ thuộc vào trạng thái của `v30`, từ đó ảnh hưởng đến quá trình giải mã payload.

Tiếp theo, chương trình sử dụng sys_mmap() để cấp phát một vùng nhớ mới tại addr.
```cpp
addr = (__int64 (__fastcall *)(_QWORD))sys_mmap(0LL, 0x1000uLL, 3uLL, 0x22uLL, 0xFFFFFFFFFFFFFFFFLL, off);
```
Vùng nhớ này ban đầu có quyền đọc/ghi. Chương trình tiếp tục dùng một vòng lặp để giải mã payload từng byte:

![image](/assets/posts/w1-recruit-2026/BJswRD4Kfl.png)



Vòng lặp chạy từ n90 = 0 đến 90, tức tổng cộng 91 byte payload được giải mã và ghi vào: `addr[0] -> addr[90]`

Đồng thời `v37` là byte ciphertext được lấy từ `v39`, còn các byte được trích xuất từ `v34` được dùng làm keystream để XOR.

Quan trọng hơn, 2 biến `v34 và v32` đều có ảnh hưởng trực tiếp đến `v38`:

```cpp
v38 ^= v32 & (((n90 ^ 0x40 | (unsigned __int64)-(n90 ^ 0x40)) >> 63) - 1);

// Sau đó v38 tiếp tục được đưa qua một chuỗi phép toán để tạo ra v34

v38 -= 0x61C8864680B583EBLL;

v42 = 0x94D049BB133111EBLL
    * ((0xBF58476D1CE4E5B9LL * (v38 ^ (v38 >> 30)))
    ^ ((0xBF58476D1CE4E5B9LL * (v38 ^ (v38 >> 30))) >> 27));

v34 = v42 ^ (v42 >> 31);
```
Vì giá trị `v32` ảnh hưởng trực tiếp đến `v38`, từ đó ảnh hưởng đến `v34` và keystream dùng để giải mã payload.

Payload sai có thể trở thành các đoạn machine code sai hoặc lỗi. Khi chương trình cố thực thi nó, có thể sẽ trả về kết quả sai dẫn đến "Wrong flag".

Do đó, cơ chế anti-debug ở đây sẽ làm thay đổi trạng thái giải mã, khiến payload checker chỉ được giải mã đúng khi chương trình chạy trong trạng thái bình thường.

![image](/assets/posts/w1-recruit-2026/SJdqJLVYzx.png)

Sau khi giải mã xong, chương trình thay đổi quyền của vùng nhớ bằng:

```cpp
sys_mprotect((unsigned __int64)addr, 0x1000uLL, 5uLL);
```
Sau đó chương trình gọi trực tiếp vùng nhớ vừa giải mã: `v43 = addr(v55);`
Đây chính là payload checker được giải mã và thực thi tại runtime.

Cuối cùng, chương trình dựa vào v43 để xác định kết quả:

```cpp
if (v43)
    Correct__n = "Correct!\n";
else
    Correct__n = "Wrong flag.\n";
```
### **2.**    Flow chương trình
Sau 1 tràng phân tích dài dòng như vậy thì tổng kết lại ta có flow chương trình sẽ chạy như sau:
```
 Read Input (v55)
       │
       ▼
Anti-Debug TracerPid
       │
       ▼
Anti-Debug Timing
       │
       ▼
      v30
       │
       ▼
      v31
       │
       ▼
      v32
       │
       ▼
      v38
       │
       ▼
      v34
       │
       ▼
   Keystream
       │
       ▼
Decrypt Payload
       │
       ▼
    mprotect
       │
       ▼
   addr(v55)
       │
       ▼
   Flag Check
       │
   ┌───┴───┐
   ▼       ▼
Correct   Wrong
```
### 3. Solve
Vì chương trình sử dụng hai cơ chế anti-debug, nên mục tiêu là bypass cả hai để đưa chương trình vào trạng thái không bị debug. Khi đó quá trình sinh v32 và giải mã payload sẽ đúng, giúp payload tại addr được giải mã chính xác. Sau đó có thể reverse payload trong vùng addr, phân tích logic của flag checker và tìm ra flag cuối cùng.
1. Bypass Anti-Debug TracerPid (set v21 = 0)
2. Bypass Anti-Debug Timing (set timming_check = 0)
=> set v30 = 0
```cpp
v30 = v21 | (2LL * ((unsigned __int64)(v29 - v24) > 300000000)); // or rbp, r13
```
Ta có `v30` kiểm tra xem chương trình có dính debug không bằng cách `set rbp = rbp or r13`, mà khi debug chắc chắn `r13` sẽ mang một giá trị khác 0 , nên chỉ cần đặt breakpoint và khi chạy thì set giá trị của `r13` về 0 là sẽ bypass được

![image](/assets/posts/w1-recruit-2026/B1PZ5IEKzg.png)


Sau khi bypass được 2 hàm anti-debug thì payload tại addr sẽ chính xác, nên ta đặt thêm 1 breakpoint tại đó để phân tích logic
```cpp
if ( !addr )
    goto LABEL_59;
  v43 = addr(v55); // call rbx
  v44 = sys_munmap((unsigned __int64)addr, 0x1000uLL);
  count_2 = 0LL;
```
![image](/assets/posts/w1-recruit-2026/B1SCy_NYzg.png)

Dump ra được 91 byte payload
```cpp
debug001:00007FFFF7FF3000                 db  31h ; 1
debug001:00007FFFF7FF3001                 db 0C0h
debug001:00007FFFF7FF3002                 db  48h ; H
debug001:00007FFFF7FF3003                 db  8Dh
debug001:00007FFFF7FF3004                 db  35h ; 5
debug001:00007FFFF7FF3005                 db  37h ; 7
debug001:00007FFFF7FF3006                 db    0
debug001:00007FFFF7FF3007                 db    0
debug001:00007FFFF7FF3008                 db    0
debug001:00007FFFF7FF3009                 db  41h ; A
debug001:00007FFFF7FF300A                 db 0B8h
debug001:00007FFFF7FF300B                 db  6Dh ; m
debug001:00007FFFF7FF300C                 db    0
debug001:00007FFFF7FF300D                 db    0
debug001:00007FFFF7FF300E                 db    0
debug001:00007FFFF7FF300F                 db  83h
debug001:00007FFFF7FF3010                 db 0F8h
debug001:00007FFFF7FF3011                 db  1Bh
debug001:00007FFFF7FF3012                 db  74h ; t
debug001:00007FFFF7FF3013                 db  14h
debug001:00007FFFF7FF3014                 db  8Ah
debug001:00007FFFF7FF3015                 db  14h
debug001:00007FFFF7FF3016                 db    7
debug001:00007FFFF7FF3017                 db  44h ; D
debug001:00007FFFF7FF3018                 db  30h ; 0
debug001:00007FFFF7FF3019                 db 0C2h
debug001:00007FFFF7FF301A                 db  3Ah ; :
debug001:00007FFFF7FF301B                 db  14h
debug001:00007FFFF7FF301C                 db    6
debug001:00007FFFF7FF301D                 db  75h ; u
debug001:00007FFFF7FF301E                 db  15h
debug001:00007FFFF7FF301F                 db  41h ; A
debug001:00007FFFF7FF3020                 db  80h
debug001:00007FFFF7FF3021                 db 0C0h
debug001:00007FFFF7FF3022                 db  17h
debug001:00007FFFF7FF3023                 db  48h ; H
debug001:00007FFFF7FF3024                 db 0FFh
debug001:00007FFFF7FF3025                 db 0C0h
debug001:00007FFFF7FF3026                 db 0EBh
debug001:00007FFFF7FF3027                 db 0E7h
debug001:00007FFFF7FF3028                 db  80h
debug001:00007FFFF7FF3029                 db  3Ch ; <
debug001:00007FFFF7FF302A                 db    7
debug001:00007FFFF7FF302B                 db    0
debug001:00007FFFF7FF302C                 db  75h ; u
debug001:00007FFFF7FF302D                 db    6
debug001:00007FFFF7FF302E                 db 0B8h
debug001:00007FFFF7FF302F                 db    1
debug001:00007FFFF7FF3030                 db    0
debug001:00007FFFF7FF3031                 db    0
debug001:00007FFFF7FF3032                 db    0
debug001:00007FFFF7FF3033                 db 0C3h
debug001:00007FFFF7FF3034                 db  31h ; 1
debug001:00007FFFF7FF3035                 db 0C0h
debug001:00007FFFF7FF3036                 db 0C3h
debug001:00007FFFF7FF3037                 db  66h ; f
debug001:00007FFFF7FF3038                 db  0Fh
debug001:00007FFFF7FF3039                 db  1Fh
debug001:00007FFFF7FF303A                 db  84h
debug001:00007FFFF7FF303B                 db    0
debug001:00007FFFF7FF303C                 db    0
debug001:00007FFFF7FF303D                 db    0
debug001:00007FFFF7FF303E                 db    0
debug001:00007FFFF7FF303F                 db    0
debug001:00007FFFF7FF3040                 db  3Ah ; :
debug001:00007FFFF7FF3041                 db 0B5h
debug001:00007FFFF7FF3042                 db 0E0h
debug001:00007FFFF7FF3043                 db 0C6h
debug001:00007FFFF7FF3044                 db 0A1h
debug001:00007FFFF7FF3045                 db 0D1h
debug001:00007FFFF7FF3046                 db  84h
debug001:00007FFFF7FF3047                 db  51h ; Q
debug001:00007FFFF7FF3048                 db  14h
debug001:00007FFFF7FF3049                 db  4Fh ; O
debug001:00007FFFF7FF304A                 db  0Ch
debug001:00007FFFF7FF304B                 db  0Ch
debug001:00007FFFF7FF304C                 db 0E8h
debug001:00007FFFF7FF304D                 db 0F6h
debug001:00007FFFF7FF304E                 db  9Bh
debug001:00007FFFF7FF304F                 db 0AAh
debug001:00007FFFF7FF3050                 db  82h
debug001:00007FFFF7FF3051                 db  92h
debug001:00007FFFF7FF3052                 db  67h ; g
debug001:00007FFFF7FF3053                 db  43h ; C
debug001:00007FFFF7FF3054                 db  5Eh ; ^
debug001:00007FFFF7FF3055                 db  37h ; 7
debug001:00007FFFF7FF3056                 db    0
debug001:00007FFFF7FF3057                 db  5Fh ; _
debug001:00007FFFF7FF3058                 db 0B4h
debug001:00007FFFF7FF3059                 db  8Dh
debug001:00007FFFF7FF305A                 db 0BEh
debug001:00007FFFF7FF305B                 db    0
```
Sau khi dump thành công 91 bytes và dùng tính năng Make Code và Create Function trong IDA, ta thu được đoạn asm hoàn chỉnh.
```cpp
debug001:00007FFFF7FF3000 sub_7FFFF7FF3000 proc near
debug001:00007FFFF7FF3000                 xor     eax, eax
debug001:00007FFFF7FF3002                 lea     rsi, byte_7FFFF7FF3040
debug001:00007FFFF7FF3009                 mov     r8d, 6Dh ; 'm'
debug001:00007FFFF7FF300F
debug001:00007FFFF7FF300F loc_7FFFF7FF300F:                       ; CODE XREF: sub_7FFFF7FF3000+26↓j
debug001:00007FFFF7FF300F                 cmp     eax, 1Bh
debug001:00007FFFF7FF3012                 jz      short loc_7FFFF7FF3028
debug001:00007FFFF7FF3014                 mov     dl, [rdi+rax]
debug001:00007FFFF7FF3017                 xor     dl, r8b
debug001:00007FFFF7FF301A                 cmp     dl, [rsi+rax]
debug001:00007FFFF7FF301D                 jnz     short loc_7FFFF7FF3034
debug001:00007FFFF7FF301F                 add     r8b, 17h
debug001:00007FFFF7FF3023                 inc     rax
debug001:00007FFFF7FF3026                 jmp     short loc_7FFFF7FF300F
debug001:00007FFFF7FF3028 ; ---------------------------------------------------------------------------
debug001:00007FFFF7FF3028
debug001:00007FFFF7FF3028 loc_7FFFF7FF3028:                       ; CODE XREF: sub_7FFFF7FF3000+12↑j
debug001:00007FFFF7FF3028                 cmp     byte ptr [rdi+rax], 0
debug001:00007FFFF7FF302C                 jnz     short loc_7FFFF7FF3034
debug001:00007FFFF7FF302E                 mov     eax, 1
debug001:00007FFFF7FF3033                 retn
```

Compile ra C, ta được hàm:
```cpp
_BOOL8 __fastcall sub_7FFFF7FF3000(__int64 a1)
{
  __int64 n27; // rax
  char n109; // r8

  n27 = 0LL;
  n109 = 0x6D;
  while ( (_DWORD)n27 != 27 )
  {
    if ( ((unsigned __int8)n109 ^ *(_BYTE *)(a1 + n27)) != byte_7FFFF7FF3040[n27] )
      return 0LL;
    n109 += 23;
    ++n27;
  }
  return !*(_BYTE *)(a1 + n27);
}
```
![image](/assets/posts/w1-recruit-2026/S1WvbwEKzg.png)


Tới đây thì không còn gì để phân tích nữa rồi.
                                                                             Solve script:
```py
byte_arr = [0x3a, 0xb5, 0xe0, 0xc6, 0xa1, 0xd1, 0x84, 0x51, 0x14, 0x4f, 0xc, 0xc, 0xe8, 0xf6, 0x9b, 0xaa, 0x82, 0x92, 0x67, 0x43, 0x5e, 0x37, 0x0, 0x5f, 0xb4, 0x8d, 0xbe]
flag =""
r8d= 0x6d
for i in range (27):
    flag += (chr(((byte_arr[i] ^ r8d) & 0xff)))
    r8d += 23
print(flag)
#W1{th1s_1s_fin4l_flaggg!!!}
```


## Cookies

![Screenshot 2026-09-14 013239](/assets/posts/w1-recruit-2026/ByzlFjy5Mx.png)
> Hint: The challenge implemented a VM but where is it??
### 1. Phân tích
Check file và chạy thử thì chall này cũng là flag checker
```
file 5070.exe
5070.exe: PE32+ executable (console) x86-64, for MS Windows, 7 sections

./5070.exe
Welcome to the Cookie Checker version 6.7, generated by Cookie Lovers
Enter your favourite cookie: cokkie
Uh oh, this is a wrong cookie.
```

Nên ta vào IDA để phân tích thôi:
![image](/assets/posts/w1-recruit-2026/BkmDsjk9fg.png)
File chứa khá nhiều hàm nên ban đầu mình thử trace từ hàm start để lần theo luồng thực thi tìm main. Tuy nhiên, nếu đi theo từng lời gọi hàm thì sẽ tốn khá nhiều thời gian vì phần đầu của chương trình chủ yếu là các đoạn mã khởi tạo do compiler chèn vào.
Nên mình nghĩ ra cách là tìm string xuất hiện lúc chương trình chạy và xref tới đó thì sẽ dễ để tìm ra hàm main hơn.
![image](/assets/posts/w1-recruit-2026/B13Lask5fx.png)
![image](/assets/posts/w1-recruit-2026/H1QdTjy9ze.png)
```cpp
__int64 sub_140002760()
{
  char n4; // [rsp+84h] [rbp+64h]
  int i; // [rsp+A4h] [rbp+84h]
  FILE *Stream; // [rsp+178h] [rbp+158h]

  sub_140002AF0(&unk_14000A152);
  if ( IsDebuggerPresent() )
    return 1LL;
  sub_1400029A0("Welcome to the Cookie Checker version 6.7, generated by Cookie Lovers\n");
  sub_1400029A0("Enter your favourite cookie: ");
  Str = (char *)malloc(0x100uLL);
  if ( !Str )
    return sub_140002150();
  memset(Str, 0, 0x100uLL);
  Stream = _acrt_iob_func(0);
  if ( fgets(Str, 256, Stream) )
  {
    n32 = strlen(Str);
    if ( Str[n32 - 1] == 10 )
      Str[--n32] = 0;
    n4 = 0;
    if ( n32 != 32 || *(_WORD *)Str != 12631 || Str[n32 - 1] != 125 )
      goto LABEL_18;
    for ( i = 0; i < 32; i += 8 )
    {
      if ( sub_1400025A0(*(_QWORD *)&Str[i], &unk_1400053D8) == qword_1400053E8[i / 8] )
        ++n4;
    }
    if ( n4 == 4 )
    {
      sub_1400029A0("Congratulation!?\n");
      return 0LL;
    }
    else
    {
LABEL_18:
      sub_1400029A0("Uh oh, this is a wrong cookie.\n");
      return 1LL;
    }
  }
  else
  {
    sub_1400029A0("An error occurred!\n");
    return 1LL;
  }
}
```
Vậy là đã tìm ra hàm main của chương trình, giờ thì rev lại để đúng nhánh "Congratulation!?"  thôi.
Đầu hàm chương trình gọi IsDebuggerPresent() để phát hiện debugger. Sau đó cấp phát 256 byte để đọc chuỗi nhập từ người dùng.

```cpp
if ( n32 != 32 || *(_WORD *)Str != 12631 || Str[n32 - 1] != 125 )
```
Tiếp đến chương trình input phải có `length = 32`, so sánh input với `12631(0x3157)` chuyển sang little endian là `0x57(W) 0x31(1)`, vậy là 2 ký tự đầu của input phải là W1 và ký tự cuối phải bằng `125(dấu '}')`

```cpp
for ( i = 0; i < 32; i += 8 )
    {
      if ( sub_1400025A0(*(_QWORD *)&Str[i], &unk_1400053D8) == qword_1400053E8[i / 8] )
        ++n4;
    }
```
Tiếp theo, chương trình duyệt chuỗi đầu vào theo từng đoạn 8 byte. Mỗi đoạn được ép kiểu thành một giá trị uint64_t rồi truyền vào hàm `sub_1400025A0 `để thực hiện phép biến đổi. Kết quả trả về sẽ được so sánh với giá trị tương ứng trong mảng `qword_1400053E8`

Vô hàm `sub_1400025A0` để xem logic biến đổi:
![image](/assets/posts/w1-recruit-2026/rJGZVh1cfl.png)
Hàm `sub_1400025A0` thực hiện quá trình biến đổi trên từng dữ liệu 64-bit. Thuật toán sử dụng 32 vòng lặp, chia dữ liệu thành hai đoạn 32-bit và liên tục cập nhật chúng bằng các phép cộng, XOR và dịch bit.
Trong mỗi vòng lặp, chương trình sử dụng một giá trị hằng `v5` kết hợp với các số trong bảng `unk_1400053D8` để tính toán giá trị mới cho hai nửa dữ liệu. Sau khi hoàn thành biến đổi, hàm trả về dữ liệu 64-bit đã được xử lý để so sánh với `qword_1400053E8`
### 2.Solve (fake flag)
![image](/assets/posts/w1-recruit-2026/H18KOhJqGe.png)
```cpp
MASK = 0xFFFFFFFF
CONST= 0x61C88647
//unk_1400053D8
KEY = [0x67C79767,0x12345678,0xEBECED12,0x27720071]
//qword_1400053E8
DATA = [0x56B8533736365297,0x659D9753715B9377,0x32E434DE823D6049,0x2F443866385683D0]

def decrypt(block):
    v2 = block
    v5 = 0
    for _ in range(32):
        v5 = (v5 - CONST) & MASK
    for _ in range(32):
        low = v2 & MASK
        high = (v2 >> 32) & MASK
        tmp = ((low << 4) ^ (low >> 5)) + low
        high = (high - ((KEY[(v5 >> 11) & 3] + v5) ^ tmp)) & MASK
        v5 = (v5 + CONST) & MASK
        tmp = ((high << 4) ^ (high >> 5)) + high
        low = (low - ((KEY[v5 & 3] + v5) ^ tmp)) & MASK
        v2 = (high << 32) | low
    return v2

flag = b""
for i, block in enumerate(DATA):
    plain = decrypt(block)
    flag += plain.to_bytes(8, "little")
print(flag)

//W1{Th1s_1s_n0t_a_C0rr3t_Fl4g!!!}
```
![image](/assets/posts/w1-recruit-2026/Bk68Y2kqfg.png)
### 3. Phân tích lại
Mặc dù đã chạy đúng nhánh congrat, nhưng đây lại là 1 fake flag. Vậy thì flag thực sự ở đâu ?
Nhìn vào hint mà tác giả đã cho `The challenge implemented a VM but where is it??`, có thể suy đoán rằng chương trình đã cài một VM để thực hiện việc kiểm tra input và mình nghĩ nó đã được imple ở đâu đó trong hàm main này.
![image](/assets/posts/w1-recruit-2026/BJXzqhkcGx.png)
Sau một hồi mày mò đọc lại asm code của hàm main này thì mình thấy ở nhánh sai có một lệnh rất đặc biệt là  `idiv [rbp+180h+var_15C]`. Có thể thấy toán hạng của idiv được gán bằng 0 ngay trước khi thực hiện phép chia. Điều này khiến chương trình phát sinh `DivideByZeroException` mỗi khi đi vào nhánh này.
Ta thấy author cố tình tạo ra lỗi chia cho 0, khi chạy chương trình sẽ chuyển luồng thực thi sang một đoạn code khác.
Do đó, bước tiếp theo là tìm exception handler xử lý lỗi này.
> Theo mình research được: Ở trên Windows lỗi chia cho 0 tương ứng với exception code [0xC0000094](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55?utm_source=chatgpt.com).

Trong IDA, ta dùng `Search -> Immediate value` và tìm giá trị `0xC0000094`. Từ đó sẽ thấy hàm `sub_140020D0` là hàm exeption handler.
![image](/assets/posts/w1-recruit-2026/rkRBipyqze.png)
![image](/assets/posts/w1-recruit-2026/ry6OoTkqzx.png)
Trong handler, sau khi xác nhận exception là `EXCEPTION_INT_DIVIDE_BY_ZERO`, chương trình gọi `sub_140001000(a1)`. Sau đó, handler cộng `6` vào `RIP` để bỏ qua instruction `idiv` vừa gây lỗi và trả về `0xFFFFFFFF`, giúp cho chương trình tiếp tục thực thi thay vì crash.
Sau đó vào hàm `sub_140001000(a1)` xem thử
![image](/assets/posts/w1-recruit-2026/H1uQu0yczg.png)
Hàm này khá ngắn. Nó chỉ gọi `sub_140002AF0(&byte_14000A0AC)` rồi trả về `sub_140001030()`.


![image](/assets/posts/w1-recruit-2026/SkMn8elqGl.png)
Coi hàm sub_140002AF0 ta thấy chỉ trả về GetCurrentThreadId() để lấy ID của thread hiện tại hoặc trả về giá trị đó nên có thể bỏ qua
Vậy logic chính sẽ nằm trong hàm `sub_140001030()`

```cpp
__int64 sub_140001030()
{
  char *v0; // rdi
  __int64 i; // rcx
  char v2; // al
  _BYTE v4[32]; // [rsp+0h] [rbp-20h] BYREF
  char v5; // [rsp+20h] [rbp+0h] BYREF
  unsigned __int8 v6; // [rsp+24h] [rbp+4h]
  char v7; // [rsp+44h] [rbp+24h]
  int v8; // [rsp+64h] [rbp+44h]
  int n2; // [rsp+84h] [rbp+64h]
  int v10; // [rsp+A4h] [rbp+84h]
  unsigned __int64 v11; // [rsp+C8h] [rbp+A8h]
  unsigned __int64 v12; // [rsp+E8h] [rbp+C8h]
  __int64 v13; // [rsp+108h] [rbp+E8h]
  unsigned __int8 *v14; // [rsp+128h] [rbp+108h]
  char v15; // [rsp+144h] [rbp+124h]
  __int16 v16; // [rsp+164h] [rbp+144h]
  int v17; // [rsp+184h] [rbp+164h] BYREF
  int v18; // [rsp+254h] [rbp+234h]
  __int64 v19; // [rsp+258h] [rbp+238h]

  v0 = &v5;
  for ( i = 98LL; i; --i )
  {
    *(_DWORD *)v0 = 0xCCCCCCCC;
    v0 += 4;
  }
  sub_140002AF0(byte_14000A0AC);
  qword_140007000[10] = qword_140007000;
  sub_140001AD0();
  v6 = BYTE3(qword_1400088B0) + BYTE2(qword_1400088B0) + BYTE1(qword_1400088B0) + qword_1400088B0;
  v7 = 1;
  while ( v7 )
  {
    v8 = dword_140008104;
    n2 = ::n2;
    v10 = byte_1400082B0[dword_140008104];
    v8 = dword_140008104 + 1;
    v10 ^= v6;
    v18 = v10;
    switch ( v10 )
    {
      case 0:
        if ( n2 >= 2 )
        {
          v11 = qword_140007100[--n2 - 1];
          v12 = qword_140007100[n2];
          qword_140007100[n2 - 1] -= qword_140007100[n2];
          if ( qword_140007100[n2 - 1] )
            dword_140008108 &= ~1u;
          else
            dword_140008108 |= 1u;
          if ( qword_140007100[n2 - 1] >= 0 )
            dword_140008108 &= ~2u;
          else
            dword_140008108 |= 2u;
          if ( v11 >> 63 == v12 >> 63 || v11 >> 63 == (unsigned __int64)qword_140007100[n2 - 1] >> 63 )
            dword_140008108 &= ~4u;
          else
            dword_140008108 |= 4u;
        }
        else
        {
          v7 = 0;
        }
        break;
      case 1:
        if ( n2 >= 2 )
        {
          v11 = qword_140007100[--n2 - 1];
          v12 = qword_140007100[n2];
          qword_140007100[n2 - 1] += qword_140007100[n2];
          if ( qword_140007100[n2 - 1] )
            dword_140008108 &= ~1u;
          else
            dword_140008108 |= 1u;
          if ( qword_140007100[n2 - 1] >= 0 )
            dword_140008108 &= ~2u;
          else
            dword_140008108 |= 2u;
          if ( v11 >> 63 != v12 >> 63 || v11 >> 63 == (unsigned __int64)qword_140007100[n2 - 1] >> 63 )
            dword_140008108 &= ~4u;
          else
            dword_140008108 |= 4u;
        }
        else
        {
          v7 = 0;
        }
        break;
      case 2:
        if ( n2 >= 2 )
        {
          --n2;
          qword_140007100[n2 - 1] &= qword_140007100[n2];
          dword_140008108 &= ~4u;
          if ( qword_140007100[n2 - 1] )
            dword_140008108 &= ~1u;
          else
            dword_140008108 |= 1u;
          if ( qword_140007100[n2 - 1] >= 0 )
            dword_140008108 &= ~2u;
          else
            dword_140008108 |= 2u;
        }
        else
        {
          v7 = 0;
        }
        break;
      case 3:
        if ( n2 >= 2 )
        {
          --n2;
          qword_140007100[n2 - 1] |= qword_140007100[n2];
          dword_140008108 &= ~4u;
          if ( qword_140007100[n2 - 1] )
            dword_140008108 &= ~1u;
          else
            dword_140008108 |= 1u;
          if ( qword_140007100[n2 - 1] >= 0 )
            dword_140008108 &= ~2u;
          else
            dword_140008108 |= 2u;
        }
        else
        {
          v7 = 0;
        }
        break;
      case 4:
        if ( n2 >= 2 )
        {
          --n2;
          qword_140007100[n2 - 1] ^= qword_140007100[n2];
          dword_140008108 &= ~4u;
          if ( qword_140007100[n2 - 1] )
            dword_140008108 &= ~1u;
          else
            dword_140008108 |= 1u;
          if ( qword_140007100[n2 - 1] >= 0 )
            dword_140008108 &= ~2u;
          else
            dword_140008108 |= 2u;
        }
        else
        {
          v7 = 0;
        }
        break;
      case 5:
        if ( n2 >= 2 )
        {
          --n2;
          qword_140007100[n2 - 1] *= qword_140007100[n2];
        }
        else
        {
          v7 = 0;
        }
        break;
      case 6:
        v16 = *(_WORD *)&byte_1400082B0[v8];
        if ( (dword_140008108 & 1) != 0 )
          v8 += 2;
        else
          v8 += v16 + 2;
        break;
      case 7:
        v16 = *(_WORD *)&byte_1400082B0[v8];
        v8 += v16 + 2;
        break;
      case 8:
        v16 = *(_WORD *)&byte_1400082B0[v8];
        if ( (dword_140008108 & 1) == 0 && ((dword_140008108 >> 1) & 1LL) == ((dword_140008108 >> 2) & 1LL) )
          v8 += 2;
        else
          v8 += v16 + 2;
        break;
      case 9:
        if ( n2 >= 1 )
        {
          LOBYTE(v18) = byte_1400082B0[v8++];
          v15 = v18;
          qword_140007000[(unsigned __int8)v18] = qword_140007100[--n2];
        }
        else
        {
          v7 = 0;
        }
        break;
      case 10:
        LOBYTE(v18) = byte_1400082B0[v8++];
        v15 = v18;
        qword_140007100[n2++] = qword_140007000[(unsigned __int8)v18];
        break;
      case 12:
        sub_140001DB0();
        v7 = 0;
        break;
      case 13:
        v13 = *(_QWORD *)&byte_1400082B0[v8];
        v8 += 8;
        qword_140007100[n2++] = v13;
        break;
      case 14:
        --n2;
        break;
      case 15:
        if ( n2 >= 2 )
        {
          v2 = qword_140007100[--n2] & 0x3F;
          v19 = n2 - 1;
          qword_140007100[v19] = (unsigned __int64)qword_140007100[v19] >> v2;
        }
        else
        {
          v7 = 0;
        }
        break;
      case 16:
        v14 = (unsigned __int8 *)qword_140007100[n2 - 1];
        LOBYTE(v18) = byte_1400082B0[v8++];
        v15 = v18;
        v13 = 0LL;
        try
        {
          switch ( v15 )
          {
            case 1:
              v13 = *v14;
              break;
            case 2:
              v13 = *(unsigned __int16 *)v14;
              break;
            case 4:
              v13 = *(unsigned int *)v14;
              break;
            default:
              v13 = *(_QWORD *)v14;
              break;
          }
        }
        catch ( int v17 )
        {
          v13 = -1LL;
          v7 = 0;
        }
        qword_140007100[n2 - 1] = v13;
        break;
      default:
        v7 = 0;
        break;
    }
    dword_140008104 = v8;
    ::n2 = n2;
  }
  return sub_140002A80(v4, &unk_1400053C0);
}
```
Tiếp tục trace vào `sub_140001030`, mình thấy hàm này có cấu trúc rất giống một VM dispatcher.

```c
__int64 sub_140001AD0()
{
  char *v0; // rdi
  __int64 i; // rcx
  _BYTE v3[32]; // [rsp+0h] [rbp-20h] BYREF
  char v4; // [rsp+20h] [rbp+0h] BYREF
  _BYTE v5[44]; // [rsp+28h] [rbp+8h] BYREF
  int j; // [rsp+54h] [rbp+34h]
  __int64 (__fastcall *v7)(_QWORD); // [rsp+78h] [rbp+58h]
  __int64 v8; // [rsp+98h] [rbp+78h]
  __int64 v9; // [rsp+B8h] [rbp+98h]
  __int64 v10; // [rsp+D8h] [rbp+B8h]
  unsigned __int8 *v11; // [rsp+F8h] [rbp+D8h]
  __int64 v12; // [rsp+118h] [rbp+F8h]
  int k; // [rsp+134h] [rbp+114h]
  __int64 n307; // [rsp+158h] [rbp+138h]
  unsigned __int8 v15; // [rsp+174h] [rbp+154h]
  __int64 (__fastcall *v16)(_QWORD, _QWORD); // [rsp+248h] [rbp+228h]

  v0 = &v4;
  for ( i = 98LL; i; --i )
  {
    *(_DWORD *)v0 = -858993460;
    v0 += 4;
  }
  sub_140002AF0(byte_14000A0AC);
  v5[0] = 18;
  v5[1] = 48;
  v5[2] = 33;
  v5[3] = 24;
  v5[4] = 58;
  v5[5] = 49;
  v5[6] = 32;
  v5[7] = 57;
  v5[8] = 48;
  v5[9] = 29;
  v5[10] = 52;
  v5[11] = 59;
  v5[12] = 49;
  v5[13] = 57;
  v5[14] = 48;
  v5[15] = 20;
  v5[16] = 85;
  for ( j = 0; (unsigned __int64)j < 0x11; ++j )
    v5[j] ^= 0x55u;
  v16 = qword_1400089F8;
  v7 = (__int64 (__fastcall *)(_QWORD))qword_1400089F8(qword_1400089E8, v5);
  if ( v7 )
  {
    v16 = (__int64 (__fastcall *)(_QWORD, _QWORD))v7;
    qword_140008110 = v7(0LL);
    if ( qword_140008110 )
    {
      v8 = qword_140008110;
      v9 = *(int *)(qword_140008110 + 60) + qword_140008110;
      v10 = v9 + *(unsigned __int16 *)(v9 + 20) + 24;
      v11 = 0LL;
      v12 = 0LL;
      for ( k = 0; k < *(unsigned __int16 *)(v9 + 6); ++k )
      {
        if ( *(_QWORD *)(v10 + 40LL * k) == 0x747865742ELL )
        {
          v11 = (unsigned __int8 *)(*(unsigned int *)(v10 + 40LL * k + 12) + qword_140008110);
          v12 = *(unsigned int *)(v10 + 40LL * k + 8);
          break;
        }
      }
      if ( v11 && v12 )
      {
        n307 = 307LL;
        while ( v12 )
        {
          v15 = *v11;
          qword_1400088B0 = v15 + n307 * qword_1400088B0;
          qword_1400088B0 %= 0x3B800001uLL;
          ++v11;
          --v12;
        }
      }
      else
      {
        qword_1400088B0 = 0x1234567890LL;
      }
    }
  }
  return sub_140002A80(v3, &unk_140005360);
}
```
Trước khi VM bắt đầu đọc bytecode, chương trình gọi `sub_140001AD0()`. Hàm này có nhiệm vụ tạo ra một giá trị hash từ section `.text` của chính binary, sau đó lưu kết quả vào `qword_1400088B0`.

Đầu tiên, hàm tạo chuỗi `"GetModuleHandleA"` bằng cách XOR từng byte với `0x55`. Sau đó chương trình dùng API này để lấy base address của chính module đang chạy.

```c
for (j = 0; j < 0x11; ++j)
    v5[j] ^= 0x55;
```

```c
qword_140008110 = v7(0LL);
```
`GetModuleHandleA(NULL)` trả về địa chỉ base của executable hiện tại. Từ địa chỉ này, chương trình đọc PE header để tìm section .text

```c
if (*(_QWORD *)(v10 + 40LL * k) == 0x747865742ELL)
```
Giá trị `0x747865742E` khi đọc theo little-endian tương ứng với chuỗi: `.text`
Sau khi tìm được section `.text`, chương trình duyệt từng byte trong section này và tính hash bằng công thức:

```c
qword_1400088B0 = byte + 307 * qword_1400088B0;
qword_1400088B0 %= 0x3B800001;
// hash = (byte + 307 * hash) % 0x3B800001;
```
Sau đó giá trị hash này sau đó được dùng trong `sub_140001030()` để tạo key giải mã opcode của VM:

```c
v6 = BYTE3(qword_1400088B0)
   + BYTE2(qword_1400088B0)
   + BYTE1(qword_1400088B0)
   + qword_1400088B0;
```
Sau khi khởi tạo các giá trị cần thiết,chương trình bắt đầu chạy VM bằng vòng lặp:
```c
v7 = 1;
  while ( v7 )
  {
    v8 = dword_140008104;
    n2 = ::n2;
    v10 = byte_1400082B0[dword_140008104];
    v8 = dword_140008104 + 1;
    v10 ^= v6;
    v18 = v10;
    {
    ...
     }
  }
```
Nếu v7 = 0 thì vòng lặp sẽ dừng, với mỗi đầu vòng lặp ta có
```c
v8 = dword_140008104;
v10 = byte_1400082B0[dword_140008104];
v8 = dword_140008104 + 1;
v10 ^= v6;
// với byte_1400082B0 = bytecode
// dword_140008104 = instruction pointer (ip)
// v6 = key xor
```
Dễ hiểu hơn thì
```
opcode = bytecode[ip] ^ v6;
```
Bên cạnh đó có biến `qword_140007100` làm stack với `n2` là stack pointer
Ta bắt đầu phân tích các opcode của VM
```c
case 0:
        if ( n2 >= 2 )
        {
          v11 = qword_140007100[--n2 - 1];
          v12 = qword_140007100[n2];
          qword_140007100[n2 - 1] -= qword_140007100[n2];
         ....
        }
// CASE 0 là hàm SUB
```
```c
 case 1:
        if ( n2 >= 2 )
        {
          v11 = qword_140007100[--n2 - 1];
          v12 = qword_140007100[n2];
          qword_140007100[n2 - 1] += qword_140007100[n2];
          ....
        }
// CASE 1 là opcode ADD
```
```c
case 2:
        if ( n2 >= 2 )
        {
          --n2;
          qword_140007100[n2 - 1] &= qword_140007100[n2];
          ...
        }
// CASE 2 là opcode AND
```
```c
case 3:
        if ( n2 >= 2 )
        {
          --n2;
          qword_140007100[n2 - 1] |= qword_140007100[n2];
          ...
        }
// CASE 3 là opcode OR
```
```c
case 4:
        if ( n2 >= 2 )
        {
          --n2;
          qword_140007100[n2 - 1] ^= qword_140007100[n2];
          ...
        }
// CASE 4 là opcode XOR
```
```c
case 5:
        if ( n2 >= 2 )
        {
          --n2;
          qword_140007100[n2 - 1] *= qword_140007100[n2];
        }
// CASE 5 là opcode MUL
```
```c
case 6:
        v16 = *(_WORD *)&byte_1400082B0[v8];
        if ( (dword_140008108 & 1) != 0 )
          v8 += 2;
        else
          v8 += v16 + 2;
        break;
// CASE 6 là opcode JNZ
```
```c
case 7:
        v16 = *(_WORD *)&byte_1400082B0[v8];
        v8 += v16 + 2;
        break;
// CASE 7 là opcode JMP
```
```c
case 8:
        v16 = *(_WORD *)&byte_1400082B0[v8];
        if ( (dword_140008108 & 1) == 0 && ((dword_140008108 >> 1) & 1LL) == ((dword_140008108 >> 2) & 1LL) )
          v8 += 2;
        else
          v8 += v16 + 2;
        break;
// CASE 8 là opcode JLE
```
```c
case 9:
        if ( n2 >= 1 )
        {
          LOBYTE(v18) = byte_1400082B0[v8++];
          v15 = v18;
          qword_140007000[(unsigned __int8)v18] = qword_140007100[--n2];
        }
// CASE 9 là opcode POP register
```
```c
case 10:
        LOBYTE(v18) = byte_1400082B0[v8++];
        v15 = v18;
        qword_140007100[n2++] = qword_140007000[(unsigned __int8)v18];
        break;
// CASE 10 là opcode PUSH register
```
```c
case 12:
        sub_140001DB0();
        v7 = 0;
        break;
// CASE 12 gọi sub_140001DB0() rồi kết thúc VM.
```
```c
case 13:
        v13 = *(_QWORD *)&byte_1400082B0[v8];
        v8 += 8;
        qword_140007100[n2++] = v13;
        break;
// CASE 13 là opcode PUSH immediate
```
```c
case 14:
        --n2;
        break;
// CASE 14 là opcode POP
```
```c
case 15:
        if ( n2 >= 2 )
        {
          v2 = qword_140007100[--n2] & 0x3F;
          v19 = n2 - 1;
          qword_140007100[v19] = (unsigned __int64)qword_140007100[v19] >> v2;
        }
// CASE 15 là opcode SHR
```
```c
case 16:
        v14 = (unsigned __int8 *)qword_140007100[n2 - 1];
        LOBYTE(v18) = byte_1400082B0[v8++];
        v15 = v18;
        v13 = 0LL;
        try
        {
          switch ( v15 )
          {
            case 1:
              v13 = *v14;
              break;
            case 2:
              v13 = *(unsigned __int16 *)v14;
              break;
            case 4:
              v13 = *(unsigned int *)v14;
              break;
            default:
              v13 = *(_QWORD *)v14;
              break;
          }
        }
        catch ( int v17 )
        {
          v13 = -1LL;
          v7 = 0;
        }
        qword_140007100[n2 - 1] = v13;
        break;
    }
// CASE 16 là opcode LOAD memory
```
```c
 default:
        v7 = 0;
        break;
// CASE default là opcode không hợp lệ thì VM dừng.
```
### Opcode table
Tóm tắt lại ta có:

| Opcode | Tên        | Chức năng                   |
| ------ | ---------- | --------------------------- |
| 0x00   | SUB        | Trừ 2 giá trị trên stack    |
| 0x01   | ADD        | Cộng 2 giá trị              |
| 0x02   | AND        | Bitwise AND                 |
| 0x03   | OR         | Bitwise OR                  |
| 0x04   | XOR        | Bitwise XOR                 |
| 0x05   | MUL        | Nhân                        |
| 0x06   | JNZ        | Jump nếu ZF = 0             |
| 0x07   | JMP        | Jump không điều kiện        |
| 0x08   | JLE        | Jump nếu ZF=1 hoặc SF != OF |
| 0x09   | POP_REG    | Stack -> register            |
| 0x0A   | PUSH_REG   | Register -> stack            |
| 0x0C   | CALL_CHECK | Gọi sub_140001DB0 rồi dừng  |
| 0x0D   | PUSH_IMM64 | Push immediate 64-bit       |
| 0x0E   | POP        | Bỏ phần tử đầu stack        |
| 0x0F   | SHR        | Shift right                 |
| 0x10   | LOAD_MEM   | Đọc dữ liệu từ địa chỉ      |

Bên cạnh đó phép ADD, SUB, AND, OR, XOR còn cập nhật `dword_140008108`.Mà biến `dword_140008108` có 3 bit thấp đóng vai trò như là CPU flags: `bit 0 = ZF` `bit 1 = SF` `bit 2 = OF`

Và ở case 12, có hàm `sub_140001DB0`
![image](/assets/posts/w1-recruit-2026/HkPxHQxqMl.png)
Mình sẽ đổi tên `__u__u_&u4u6:__06_u3942yu = str1 và _2_4__t_U =str2`  để dễ gọi và làm hơn.
Đoạn đầu chương trình khởi tạo Stack Frame.Sau đó copy 25 byte từ chuỗi  `!u<!u<&u4u6:''06!u3942yu` vào str, sau đó gán byte thứ 26 = 22. Tiếp tục copy 10 byte từ chuỗi `:;2'4!/t_U` vào str2
> Chú ý ở đây n23 có địa chỉ [rsp+28h], str1 đ/c là [rsp+29h] và str2 đ/c là [rsp+43h] -->các biến n23,str1,str2 này nằm liên tiếp trên stack và tạo thành một buffer dài 37 byte = 0x25

Sau đó toàn bộ buffer được XOR với 0x55:
```c
for (j = 0; j < 0x25; ++j)
    str1[j - 1] ^= 0x55;
```
Decode chuỗi này ta được:
```c
data = (bytes([23]) + b" !u<!u<&u4u6:''06!u3942yu"
    + bytes([22])+ b":;2'4!/t_U")
decode = bytes(i ^ 0x55 for i in data)
print(decode)
//b'But it is a correct flag, Congratz!\n\x00'
```
Điều này cho thấy hàm này liên quan trực tiếp đến nhánh kiểm tra thành công của chương trình.
```c
v9 = (char *)sub_140001DB0 + 0xBF0 * (dword_140008108 & 1);
  v10 = v9;
  ((void (__fastcall *)(void *, char *))v9)(&::n23, &n23);
```
Như mình phân tích, hàm dword_140008108 là ZF thì `v9 = sub_140001DB0 + 0xBF0 * ZF`. Nếu `ZF = 0` thì sẽ gọi lại `sub_140001DB0`, `ZF = 1` thì  `v9 = sub_140001DB0 + 0xBF0 = sub_1400029A0`
Nhảy tới `sub_1400029A0` để xem hàm đó làm gì:
![image](/assets/posts/w1-recruit-2026/HyGVIVl9fg.png)
Hàm này chỉ đơn giản là hàm print ra chuỗi string, với `vfprintf` được gọi từ hàm `sub_1400026F0`
Trong `sub_140001DB0()`, khi ZF = 1, chương trình chọn địa chỉ của hàm này và truyền chuỗi đã XOR-decode vào, từ đó in thông báo "But it is a correct flag, Congratz!". Do đó để vượt qua VM cuối cùng phụ thuộc vào việc Zero Flag (ZF) có được set hay không.
### Decode opcode
Vậy bước tiếp theo là decode bytecode của VM để xác định instruction nào thay đổi ZF, cũng như điều kiện nào khiến ZF = 1.
Ta có:
```c
opcode = bytecode[ip] ^ v6;
và
v6 = BYTE3(qword_1400088B0) + BYTE2(qword_1400088B0)
    + BYTE1(qword_1400088B0) + qword_1400088B0;
tương đương
key = ((hash) & 0xff + (hash >>  8) & 0xff
    + (hash >> 16) & 0xff + (hash >> 24) & 0xff) & 0xff;
Suy ra
    opcode = bytecode[ip] ^ key
```
Để có `key` xor ngược tìm opcode thì mình sẽ debug để lấy giá trị của v6 tại runtime.
Do chương trình có cơ chế check quét qua section .text, nên khi đặt softwarebreakpoint  (int 3 / 0xCC) trong .text sẽ làm sai lệch hash. Nên cần phải đặt hardwarebp
![image](/assets/posts/w1-recruit-2026/rJETiLl9ze.png)
Chạy debug, ta thấy giá trị v6 = al = 0xD7
Script decode opcode
```python
KEY = 0xD7

bytecode = bytes([0xDD, 0x0A, 0xDA, 0xE0, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD6, 0xC7, 0x08,
    0xDE, 0x02, 0xDD, 0x02, 0xDA, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD7,
    0xD9, 0xDF, 0x03, 0x00, 0xD0, 0x54, 0x01, 0xDA, 0xEF, 0xBE, 0xAD, 0xDE, 0x00, 0x00,
    0x00, 0x00, 0xDE, 0x03, 0xDA, 0xBE, 0xBA, 0xFE, 0xCA, 0x00, 0x00, 0x00, 0x00, 0xDE,
    0x04, 0xDA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0x05, 0xDA, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0x06, 0xDA, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xDE, 0x07, 0xDD, 0x02, 0xDA, 0x0F, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0xD5, 0xDA, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD4,
    0xDE, 0x08, 0xDD, 0x08, 0xDD, 0x08, 0xD5, 0xD1, 0x03, 0x00, 0xD0, 0x34, 0x00, 0xDD,
    0x07, 0xDD, 0x03, 0xDD, 0x04, 0xD3, 0xD6, 0xDE, 0x07, 0xDD, 0x03, 0xDD, 0x04, 0xD7,
    0xDE, 0x05, 0xDD, 0x03, 0xDD, 0x04, 0xD6, 0xDE, 0x06, 0xDD, 0x05, 0xDD, 0x06, 0xD3,
    0xDE, 0x03, 0xDD, 0x05, 0xDE, 0x04, 0xDD, 0x08, 0xDA, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0xD7, 0xDE, 0x08, 0xD0, 0xC1, 0xFF, 0xDA, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xDE, 0x09, 0xDD, 0x02, 0xDE, 0x08, 0xDD, 0x08, 0xDD, 0x08,
    0xD5, 0xD1, 0x03, 0x00, 0xD0, 0x9B, 0x00, 0xDD, 0x07, 0xDD, 0x03, 0xD2, 0xDD, 0x04,
    0xD6, 0xDE, 0x07, 0xDD, 0x07, 0xDA, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xD5, 0xDD, 0x07, 0xDA, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD8, 0xDA,
    0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD5, 0xD6, 0xDA, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0xD4, 0xDA, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0xD6, 0xDA, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD5, 0xDE, 0x0B,
    0xDD, 0x0A, 0xDA, 0xD8, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD6, 0xC7, 0x08,
    0xDD, 0x02, 0xDD, 0x08, 0xD7, 0xD6, 0xC7, 0x01, 0xDD, 0x0B, 0xD3, 0xDD, 0x0A, 0xDA,
    0x20, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD6, 0xDD, 0x02, 0xDD, 0x08, 0xD7,
    0xDA, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD2, 0xD6, 0xC7, 0x04, 0xD3,
    0xDD, 0x09, 0xD6, 0xDE, 0x09, 0xDD, 0x08, 0xDA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xD7, 0xDE, 0x08, 0xD0, 0x5A, 0xFF, 0xDD, 0x09, 0xDA, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0xD7, 0xD9, 0xD1, 0x01, 0x00, 0xDB, 0xDC])

ip = 0
total_len = len(bytecode)
while ip < total_len:
    addr = ip
    raw_op = bytecode[ip]
    op = raw_op ^ KEY
    ip += 1
    if op == 0:
        print(f"{addr:04X}:SUB")
    elif op == 1:
        print(f"{addr:04X}:ADD")
    elif op == 2:
        print(f"{addr:04X}:AND")
    elif op == 3:
        print(f"{addr:04X}:OR")
    elif op == 4:
        print(f"{addr:04X}:XOR")
    elif op == 5:
        print(f"{addr:04X}:MUL")
    elif op == 6:
        offset = int.from_bytes(bytecode[ip:ip+2], "little")
        ip += 2
        target = ip + offset
        print(f"{addr:04X}:JNZ 0x{target:04X}")
    elif op == 7:
        offset = int.from_bytes(bytecode[ip:ip+2], "little")
        ip += 2
        target = ip + offset
        print(f"{addr:04X}:JMP 0x{target:04X}")
    elif op == 8:
        offset = int.from_bytes(bytecode[ip:ip+2], "little")
        ip += 2
        target = ip + offset
        print(f"{addr:04X}:JLE 0x{target:04X}")
    elif op == 9:
        reg = bytecode[ip]
        ip += 1
        print(f"{addr:04X}:POP R{reg}")
    elif op == 10:
        reg = bytecode[ip]
        ip += 1
        print(f"{addr:04X}:PUSH R{reg}")
    elif op == 12:
        print(f"{addr:04X}:CHECK_FLAG")
        break
    elif op == 13:
        imm64 = int.from_bytes(bytecode[ip:ip+8], "little")
        ip += 8
        print(f"{addr:04X}:PUSH 0x{imm64:2X}")
    elif op == 14:
        print(f"{addr:04X}:POP")
    elif op == 15:
        print(f"{addr:04X}:SHR")
    elif op == 16:
        size = bytecode[ip]
        ip += 1
        print(f"{addr:04X}:LOAD_MEM ({size})")

```
 Decode ra được:
```c
0000:PUSH R10
0002:PUSH 0x19E0
000B:ADD
000C:LOAD_MEM (8)
000E:POP R2
0010:PUSH R2
0012:PUSH 0x43
001B:SUB
001C:POP
001D:JLE 0x0023
0020:JMP 0x0177
0023:PUSH 0xDEADBEEF
002C:POP R3
002E:PUSH 0xCAFEBABE
0037:POP R4
0039:PUSH 0x0
0042:POP R5
0044:PUSH 0x0
004D:POP R6
004F:PUSH 0x0
0058:POP R7
005A:PUSH R2
005C:PUSH 0xF
0065:AND
0066:PUSH 0xA
006F:OR
0070:POP R8
0072:PUSH R8
0074:PUSH R8
0076:AND
0077:JNZ 0x007D
007A:JMP 0x00B1
007D:PUSH R7
007F:PUSH R3
0081:PUSH R4
0083:XOR
0084:ADD
0085:POP R7
0087:PUSH R3
0089:PUSH R4
008B:SUB
008C:POP R5
008E:PUSH R3
0090:PUSH R4
0092:ADD
0093:POP R6
0095:PUSH R5
0097:PUSH R6
0099:XOR
009A:POP R3
009C:PUSH R5
009E:POP R4
00A0:PUSH R8
00A2:PUSH 0x1
00AB:SUB
00AC:POP R8
00AE:JMP 0x10072
00B1:PUSH 0x0
00BA:POP R9
00BC:PUSH R2
00BE:POP R8
00C0:PUSH R8
00C2:PUSH R8
00C4:AND
00C5:JNZ 0x00CB
00C8:JMP 0x0166
00CB:PUSH R7
00CD:PUSH R3
00CF:MUL
00D0:PUSH R4
00D2:ADD
00D3:POP R7
00D5:PUSH R7
00D7:PUSH 0xFF
00E0:AND
00E1:PUSH R7
00E3:PUSH 0x8
00EC:SHR
00ED:PUSH 0xFF
00F6:AND
00F7:ADD
00F8:PUSH 0x1
0101:OR
0102:PUSH 0xFF
010B:ADD
010C:PUSH 0xFF
0115:AND
0116:POP R11
0118:PUSH R10
011A:PUSH 0x19D8
0123:ADD
0124:LOAD_MEM (8)
0126:PUSH R2
0128:PUSH R8
012A:SUB
012B:ADD
012C:LOAD_MEM (1)
012E:PUSH R11
0130:XOR
0131:PUSH R10
0133:PUSH 0x1120
013C:ADD
013D:PUSH R2
013F:PUSH R8
0141:SUB
0142:PUSH 0x4
014B:MUL
014C:ADD
014D:LOAD_MEM (4)
014F:XOR
0150:PUSH R9
0152:ADD
0153:POP R9
0155:PUSH R8
0157:PUSH 0x1
0160:SUB
0161:POP R8
0163:JMP 0x100C0
0166:PUSH R9
0168:PUSH 0x0
0171:SUB
0172:POP
0173:JNZ 0x0177
0176:CHECK_FLAG
```
Mình sẽ chuyển thành pseudo code để đọc dễ hơn.
```c
    uint64_t R2, R3, R4, R5, R6;
    uint64_t R7, R8, R9, R10, R11;

    R10 = (uint64_t)qword_140007000;
    R2 = *(uint64_t *)(R10 + 0x19E0);
    if ((int64_t)R2 > 0x43)
        goto fail;
    R3 = 0xDEADBEEF;
    R4 = 0xCAFEBABE;
    R5 = 0;
    R6 = 0;
    R7 = 0;
    R8 = (R2 & 0xF) | 0xA;
    while (R8 != 0)
    {
        R7 = R7 + (R3 ^ R4);
        R5 = R3 - R4;
        R6 = R3 + R4;
        R3 = R5 ^ R6;
        R4 = R5;
        R8--;
    }
    R9 = 0;
    R8 = R2;
    while (R8 != 0)
    {
        uint64_t index;
        uint8_t input_byte;
        uint32_t table_value;

	R7 = R7 * R3 + R4;
	R11 = R7 & 0xFF;
        R11 += (R7 >> 8) & 0xFF;
        R11 |= 1;
        R11 += 0xFF;
        R11 &= 0xFF;
	index = R2 - R8;
	input_byte =*(uint8_t *)(*(uint64_t *)(R10 + 0x19D8)+ index);
        input_byte ^= (uint8_t)R11;
        table_value =*(uint32_t *)(R10+ 0x1120+ index * 4);
        R9 += ((uint64_t)input_byte ^ table_value);
        R8--;
    }
    if (R9 != 0)
        goto fail;
    CHECK_FLAG();
    return;
fail:
    return;

```
Sau khi chuyển bytecode của VM thành pseudocode, ta thấy phần kiểm tra chính nằm ở vòng lặp thứ hai.
Ban đầu:
```c
R9 = 0;
R8 = R2;
```
Trong đó `R2` là độ dài input, còn `R9` được dùng như một biến tích lũy kết quả kiểm tra.
Mỗi vòng lặp, chương trình trước tiên cập nhật `R7`:
```c
R7 = R7 * R3 + R4;
```

Sau đó từ `R7`, chương trình tạo ra một giá trị 8-bit `R11`:

```c
R11 = R7 & 0xFF;
R11 += (R7 >> 8) & 0xFF;
R11 |= 1;
R11 += 0xFF;
R11 &= 0xFF;
```

Có thể xem `R11` là key được tạo riêng cho từng ký tự của input.
Tiếp theo, chương trình lấy một byte từ input:

```c
input_byte =*(uint8_t *)(*(uint64_t *)(R10 + 0x19D8)+ index);
```
Trong đó:
```c
index = R2 - R8;
```
Vì `R8` giảm dần sau mỗi vòng lặp nên `index` lần lượt tăng
Sau đó byte input được XOR với `R11`:
```c
input_byte ^= R11;
```
Chương trình tiếp tục lấy một giá trị 32-bit từ bảng dữ liệu nằm tại offset `0x1120`:
```c
table_value =*(uint32_t *)(R10 + 0x1120 + index * 4 );
```
Cuối cùng, kết quả được cộng vào `R9`:
```c
R9 += input_byte ^ table_value;
```
Nếu viết gọn lại, ta có:
```c
R9 += (input[i] ^ key[i]) ^ table[i];
```
Sau khi xử lý hết input, chương trình kiểm tra:
```c
if (R9 != 0)
    goto fail;
CHECK_FLAG();
```
Do đó để đi vào `CHECK_FLAG()`, ta cần:
```c
R9 == 0;
```
Vì mỗi giá trị được cộng vào `R9` đều là số không âm, tổng chỉ có thể bằng `0` khi từng giá trị đều bằng `0`:
```c
(input[i] ^ key[i]) ^ table[i] == 0;
```
Suy ra:
```c
input[i] ^ key[i] = table[i];
```
và cuối cùng:
```c
input[i] = table[i] ^ key[i];
```
Như vậy ta chỉ cần mô phỏng lại quá trình sinh `key[i]`, lấy các giá trị trong `table[i]`, rồi XOR hai giá trị với nhau để khôi phục input ban đầu.
### Solve
Ta chỉ cần:
    1. Dump bảng dữ liệu tại offset `0x1120`.
2. Mô phỏng lại quá trình sinh `key[i]`.
3. Lấy `table[i] ^ key[i]` để khôi phục từng byte input ban đầu.
4. Thử độ dài từ `1` đến `67`, vì key phụ thuộc vào độ dài input.

```python
mask = 0xffffffffffffffff
table = [0x3B, 0x9F, 0x3B, 0x4C, 0x8C, 0xFE, 0x5B, 0x8F,
    0x25, 0x3E, 0xB7, 0xB5, 0xD6, 0xEB, 0x71, 0xDF,
    0xC5, 0xAB, 0xF2, 0xF3, 0xC9, 0xC5, 0xF9, 0xF2,
    0xAE, 0xF6, 0xF6, 0xA9, 0xF4, 0xDD, 0xA9, 0xB6,
    0xF2, 0xA9, 0xEA, 0xCA, 0xE3, 0xC5, 0xE8, 0xA9,
    0xEC, 0xA9, 0xE8, 0xE9, 0xA9, 0xFF, 0xFF, 0xE7,
    0x4D, 0x8E, 0xD5, 0x5B, 0x0C, 0xCC, 0x21, 0xB0,
    0x37, 0xF1, 0x6C, 0x13, 0xA5, 0x52, 0xED, 0x2C,
    0x77, 0xC6, 0x1B]
def solve(length):
    R2 = length
    R3 = 0xDEADBEEF
    R4 = 0xCAFEBABE
    R7 = 0
    R8 = (R2 & 0xF) | 0xA
    while R8 != 0:
        R7 = (R7 + (R3 ^ R4)) & mask
        R5 = (R3 - R4) & mask
        R6 = (R3 + R4) & mask
        R3 = (R5 ^ R6) & mask
        R4 = R5
        R8 -= 1
    flag = []
    R8 = R2
    while R8 != 0:
        R7 = (R7 * R3 + R4) & mask
        R11 = R7 & 0xFF
        R11 += (R7 >> 8) & 0xFF
        R11 |= 1
        R11 += 0xFF
        R11 &= 0xFF
        index = R2 - R8
        ch = table[index] ^ R11
        flag.append(ch)
        R8 -= 1
    return bytes(flag)

flag = b""
for i in range(1, 0x43 + 1):
    x = solve(i)
    if all(32 <= y <= 126 for y in x):
        flag = x
print(flag)
#b'W1{h0p3_y0U_l1kE_1hiS_ch4ll3nG3,h3pPy_r3v3rs3ee}'
```
