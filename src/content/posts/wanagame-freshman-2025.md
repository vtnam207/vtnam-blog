---
title: "Wanagame Freshman 2025"
published: 2026-09-27
description: "Write-up SuperEasy_crackme, Shy_crackme và TRACE_ME."
ctf: "Wanagame Freshman 2025"
category: "Reverse Engineering"
tags: ['CTF', 'Reverse Engineering', 'Windows', 'Python']
lang: vi
draft: false
---

> Bản gốc: [HackMD](https://hackmd.io/@vtnam207/Hy9oNhgebg)

## SuperEasy_crackme

Source code file challenge

```python
add = b'ZC\xc2\xf8'
sbox = [0] * 16
cmp_bytes = b'\x83\xec"uk\x92\xcf?\x85T\x0e\xd9\x0e\xd9\x0e\xd9\x99\x89H\xb7~\xbaH\xb7~\xba`\x03!\x83\x03\x84-\x82~\xba`\x03\xc0\xa7q\xbf\xef\xf5b9\xf2MT\xbf\xff\xec\xa54\x86x\xdb|8\x85\xdb|8\x85\xdb|8\x85\x0b\xefEz\xa54\xc1T\x9d\xbag\x9e\x0b\xef\x17C\r\x1cE\xd5<;7\xfc#\xab\xa0azW\r\x1c98#\xab\r\x1cE\xd5\xca4\xc1T\x9d\xba=s\x0e\x9e\x0e\x9e\xdc\x7f\x9d\xba\xb5M'
sbox[0] = 14
sbox[1] = 3
sbox[2] = 11
sbox[3] = 8
sbox[4] = 1
sbox[5] = 2
sbox[6] = 13
sbox[7] = 4
sbox[8] = 8
sbox[9] = 10
sbox[10] = 6
sbox[11] = 12
sbox[12] = 5
sbox[13] = 9
sbox[14] = 7
sbox[15] = 15
def encrypt(inp: bytes) -> bytes:
    res = [0] * len(inp)
    for i in range(0, len(inp), 2):
        a = inp[i]
        b = inp[i + 1]
        for k in range(6):
            x = (add[k & 3] + (sbox[b & 0xf] | (sbox[b >> 4] << 4))) & 0xff
            y = ((x >> 5) | (x << 3)) ^ x ^ a
            y &= 0xff
            a = b
            b = y

        res[i] = a
        res[i + 1] = b

    return bytes(res)


inp = input("Input flag: ").encode()
if encrypt(inp) == cmp_bytes:
    print("Correct")
else:
    print("Wrong")
```
* Đọc file code trên ta thấy code lấy 2 byte đầu vào `a` và `b`
* Qua mỗi vòng, nó tính toán một giá trị `y` mới
* Sau đó, nó hoán đổi vị trí: `a mới = b cũ`, và `b mới = y`
Để giải mã, chúng ta phải đảo ngược quá trình này:
Chúng ta cũng xử lý theo từng khối 2-byte của cmp_bytes.
Chúng ta phải chạy các vòng lặp theo thứ tự ngược lại, tức là từ k = 5 xuống k = 0.
Tại mỗi vòng, chúng ta có 2 byte a và b là kết quả sau khi mã hóa. Dựa trên phân tích:
```
a = old_b
b = y
```
Chúng ta cần tìm lại old_a và old_b (là a và b của vòng trước đó).
old_b đã có sẵn, chính là a.
y đã có sẵn, chính là b.
`y = (ROR(x) ^ x) ^ old_a`
Chúng ta có thể tính x vì nó chỉ phụ thuộc vào old_b (tức a) và khóa vòng k:`x = (add[k & 3] + (sbox[a & 0xf] | (sbox[a >> 4] << 4))) & 0xff`
Sau khi có x, chúng ta có thể tìm old_a bằng cách đảo phép XOR: `old_a = y ^ (ROR(x) ^ x) old_a = b ^ (((x >> 5) | (x << 3)) & 0xff) ^ x`
Sau khi chạy 6 vòng ngược,`a` và `b` cuối cùng chính là 2 byte plaintext ban đầu.
> decrypt code
```python
add = b'ZC\xc2\xf8'
sbox = [0] * 16
cmp_bytes = b'\x83\xec"uk\x92\xcf?\x85T\x0e\xd9\x0e\xd9\x0e\xd9\x99\x89H\xb7~\xbaH\xb7~\xba`\x03!\x83\x03\x84-\x82~\xba`\x03\xc0\xa7q\xbf\xef\xf5b9\xf2MT\xbf\xff\xec\xa54\x86x\xdb|8\x85\xdb|8\x85\xdb|8\x85\x0b\xefEz\xa54\xc1T\x9d\xbag\x9e\x0b\xef\x17C\r\x1cE\xd5<;7\xfc#\xab\xa0azW\r\x1c98#\xab\r\x1cE\xd5\xca4\xc1T\x9d\xba=s\x0e\x9e\x0e\x9e\xdc\x7f\x9d\xba\xb5M'
sbox[0] = 14
sbox[1] = 3
sbox[2] = 11
sbox[3] = 8
sbox[4] = 1
sbox[5] = 2
sbox[6] = 13
sbox[7] = 4
sbox[8] = 8
sbox[9] = 10
sbox[10] = 6
sbox[11] = 12
sbox[12] = 5
sbox[13] = 9
sbox[14] = 7
sbox[15] = 15

# --- Hàm giải mã ---
def decrypt(enc: bytes) -> bytes:
    res = [0] * len(enc)
    for i in range(0, len(enc), 2):
        # Lấy 2 byte cipher
        a = enc[i]
        b = enc[i + 1]

        # Chạy 6 vòng ngược (từ k=5 xuống k=0)
        for k in range(5, -1, -1):
            # Trạng thái (a, b) là (old_b, y) của vòng k

            # 1. Lấy y và old_b
            y = b
            old_b = a

            # 2. Tính lại x (dựa trên old_b, tức là 'a')
            sbox_val = (sbox[old_b & 0xf] | (sbox[old_b >> 4] << 4))
            x = (add[k & 3] + sbox_val) & 0xff

            # 3. Tính lại bit_mix
            bit_mix = ((x >> 5) | (x << 3)) & 0xff

            # 4. Đảo ngược phép XOR cuối cùng để tìm old_a
            # y = bit_mix ^ x ^ old_a
            # => old_a = y ^ bit_mix ^ x
            old_a = y ^ bit_mix ^ x
            old_a &= 0xff # Đảm bảo là 1 byte

            # 5. Cập nhật (a, b) về trạng thái của vòng trước đó
            a = old_a
            b = old_b

        # Sau 6 vòng ngược, (a, b) là plaintext
        res[i] = a
        res[i + 1] = b

    return bytes(res)

# --- Chạy giải mã ---
try:
    decrypted_flag = decrypt(cmp_bytes)
    print(f"[*] Ciphertext: {cmp_bytes.hex()}")
    print(f"[*] Flag: {decrypted_flag.decode('utf-8')}")
except Exception as e:
    print(f"[!] Lỗi: {e}")
    print(f"[*] Dữ liệu đã giải mã (raw): {decrypted_flag}")
// W1{sup3rshyyyyyy_meowmeowmewomweoewmew_dogdog_brakrbrak_tungtungtungsahurasdasddsa_1221291232132112201212212_asdasdadsdsadass}
```
## Shy_crackme
![image](/assets/posts/wanagame-freshman-2025/BJisE2gw-x.png)
Đọc file thì thấy đây là file PE 32 bits
Thử check strings file thì ta thấy
![image](/assets/posts/wanagame-freshman-2025/BJlzBhxPZg.png)
Đây là chương trình nhập vào flag và kiểm tra xem coi flag có đúng không
Đồng thời strings file này còn cung cấp cho ta một số thông tin hữu ích về việc giải bài. Ví dụ như phần stack ` memory was corupted ` thì có thể khai thác lỗi Stack Buffer Overflow.
Ta bắt đầu dùng IDA để phân tích file. Khi vô mình thử tìm kiếm hàm `main` nhưng lại không thấy có lẽ đã bị đổi tên thành 1 hàm khác.
![image](/assets/posts/wanagame-freshman-2025/S1nTInewbl.png)
Nên mình bắt đầu tìm kiếm trong hàm `start`
![image](/assets/posts/wanagame-freshman-2025/HyC1DhgPWx.png)
Có thể thấy hàm `start` này trả về 1 hàm start khác là `start_0()`
![image](/assets/posts/wanagame-freshman-2025/HJDGv2xv-g.png)
Trong hàm `start_0()` này lại trả về 1 hàm `sub_412D60()`
![image](/assets/posts/wanagame-freshman-2025/BygCv2xDWg.png)
Lại tiếp tục là trả về hàm, click tiếp vào hàm `sub_412D80()`
```cpp
int sub_412D80()
{
  int Code; // [esp+28h] [ebp-2Ch]
  _tls_callback_type *v2; // [esp+30h] [ebp-24h]
  _DWORD *v3; // [esp+34h] [ebp-20h]
  char v4; // [esp+3Ah] [ebp-1Ah]
  char v5; // [esp+3Bh] [ebp-19h]

  if ( !(unsigned __int8)sub_4112DA(1) )
    sub_4111F9(7);
  v5 = 0;
  v4 = sub_41130C();
  if ( dword_41B5FC == 1 )
  {
    sub_4111F9(7);
  }
  else if ( dword_41B5FC )
  {
    v5 = 1;
  }
  else
  {
    dword_41B5FC = 1;
    if ( j__initterm_e((_PIFV *)&First, (_PIFV *)&Last) )
      return 255;
    j__initterm((_PVFV *)&dword_418000, (_PVFV *)&dword_418208);
    dword_41B5FC = 2;
  }
  sub_411195(v4);
  v3 = (_DWORD *)sub_411050();
  if ( *v3 && (unsigned __int8)sub_411145(v3) )
    ((void (__thiscall *)(_DWORD, _DWORD, int, _DWORD))*v3)(*v3, 0, 2, 0);
  v2 = (_tls_callback_type *)sub_411037();
  if ( *v2 && (unsigned __int8)sub_411145(v2) )
    j__register_thread_local_exe_atexit_callback(*v2);
  Code = sub_413060();
  if ( !(unsigned __int8)sub_411325() )
    j_exit(Code);
  if ( !v5 )
    j__cexit();
  sub_4111A4(1, 0);
  return Code;
}
```
Nhìn qua thì đây chỉ là một hàm khởi tạo để gọi hàm main. Để ý sẽ thấy có một dòng `Code = sub_413060()`
 Click vào vẫn là hàm gọi các biến môi trường để return hàm khác
 ![image](/assets/posts/wanagame-freshman-2025/SktbFhlPWe.png)
 ![image](/assets/posts/wanagame-freshman-2025/H1YIF3lw-g.png)
 Bấm vô tiếp thì thấy hàm return về 1 hàm `sub_4122B0()`. Đây chính là hàm main mà ta cần tìm
 ![image](/assets/posts/wanagame-freshman-2025/rJxqK2lPbl.png)
 Phân tích thấy nhận từ người dùng nhập vào tối đa 31 ký tự tính cả null nữa là 32 và sau đó nó tính độ dài mà người dùng nhập.
Để có được flag thì ta cần thỏa 2 điều kiện
1.   v4==22 tức là flag mà người dùng nhập vào phải đúng bằng 22 ký tự
2. Hàm `sub_411069()` phải trả về giá trị true

 Vậy ta cần phân tích sâu hàm `sub_411069()` làm gì để có thể trả về true
 ![image](/assets/posts/wanagame-freshman-2025/SkLuh2xDbx.png)
 Trong hàm `sub_411069()` trả về 1 hàm `sub_411840()` , click vô xem thì đây là 1 hàm so sánh và tính toán
 ![image](/assets/posts/wanagame-freshman-2025/BkCohhgvWe.png)
For hàm a1[i] từ 1 đến 21, mỗi ký tự được XOR với 0x5Au , sau đó chuyển kết quả XOR sang dạng chuỗi Hex in hoa rồi đẩy đần vào str1. Sau đó hàm j_strcmp so sánh hàm `Str1` và `Str2:"0D6B21292F2A3F2829322334233B3434233B34686827" `
Vì vậy để lấy được flag thì ta cần làm ngược lại
1. Lấy chuỗi Hex đích chia thành từng cặp 2 ký tự (mỗi cặp đại diện cho 1 ký tự sau khi đã XOR)
2. Chuyển từng cặp Hex đó về lại giá trị số nguyên
3. XOR giá trị đó với 0x5A
4. Chuyển kết quả sang dạng ký tự (ASCII)
```python
hex = "0D6B21292F2A3F2829322334233B3434233B34686827"
flag = ""
for i in range(0, len(hex), 2):
    hex_pair = hex[i:i+2]
    vallue = int(hex_pair, 16)
    first = vallue ^ 0x5A
    flag += chr(first)
print(flag)
```
FLAG: W1{supershynyannyan22}
## TRACE_ME
https://drive.google.com/drive/folders/1kG1sn3TgTyyoWmwWEDhA_LWsLvXrd4bK?hl=vi
Đây là một file khá lớn và đọc hết khá tốn thời gian. File này đang code một chương trình bằng Assembly và rất dài nên mình sẽ chuyển sang code C++ để có thể đọc dễ hiểu và giải nhanh hơn
```cpp
#include <iostream>
#include <vector>
#include <cstdint>
#include <string>

// Thuật toán PRNG (Xorshift + Multiplier) dựa trên trace 0x401023
uint64_t next_state(uint64_t& state) {
    uint64_t x = state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    state = x; // Cập nhật state trước khi nhân hoặc sau tùy theo cấu trúc thực tế
    return x * 0x2545F4914F6CDD1DULL;
}

int main() {
    // 1. Khởi tạo Seed (tương ứng 0x401084)
    uint64_t state = 0x41424344; // "ABCD"

    // 2. Sinh mảng dữ liệu ngẫu nhiên (tương ứng vòng lặp 0x800 lần tại 0x40108e)
    std::vector<uint8_t> random_pool;
    random_pool.reserve(0x800);

    for (int i = 0; i < 0x800; ++i) {
        uint64_t val = next_state(state);
        // Trace cho thấy byte thấp (al) được lưu vào mảng [r15+0x402008]
        random_pool.push_back(static_cast<uint8_t>(val & 0xFF));
    }

    // 3. Logic xử lý chuỗi nhập (tương ứng 0x4010b6)
    // Giả sử đầu vào là chuỗi cần kiểm tra
    std::string input;
    std::cout << "Enter string: ";
    std::cin >> input;

    std::string result = "";
    for (size_t i = 0; i < input.length(); ++i) {
        uint8_t target = static_cast<uint8_t>(input[i]);

        // Vòng lặp tìm kiếm byte trong pool (tương ứng 0x401110)
        // Trace cho thấy chương trình duyệt pool để so sánh al (byte pool) với bl (byte input)
        for (size_t j = 0; j < random_pool.size(); ++j) {
            if (random_pool[j] == target) {
                // Tùy vào đề bài CTF, đây có thể là bước kiểm tra flag
                // hoặc mã hóa dựa trên vị trí index j.
                // Ở đây mô phỏng việc tìm thấy giá trị.
                break;
            }
        }
    }

    return 0;
}
```
Script giải mã
```python
def solve():
    # 1. Tái tạo lại random_pool (Xorshift64*)
    seed = 0x41424344
    state = seed
    mask = 0xFFFFFFFFFFFFFFFF
    pool = []

    for _ in range(2048):
        state ^= (state >> 12) & mask
        state ^= (state << 25) & mask
        state ^= (state >> 27) & mask
        val = (state * 0x2545F4914F6CDD1D) & mask
        pool.append(val & 0xFF)
    # 2. Đọc file trace và xử lý
    indices = []
    current_index_count = 0
    in_search_loop = False
    try:
        with open('trace_me.txt', 'r') as f:
            for line in f:
                # Tối ưu: Chỉ check 8 ký tự đầu (thường là địa chỉ hex)
                # Giả sử format: "0x40110d: ..."
                addr = line[:8]

                if addr == "0x40110d":
                    current_index_count = 0
                    in_search_loop = True
                elif addr == "0x401110":
                    if in_search_loop:
                        current_index_count += 1
                elif addr == "0x401126":
                    if in_search_loop:
                        # Index thực tế thường là số lần so sánh trừ đi 1
                        indices.append(current_index_count - 1)
                        in_search_loop = False
    except FileNotFoundError:
        print("[-] Không tìm thấy file trace_me.txt")
        return
    # 3. Khôi phục flag
    flag = "".join(chr(pool[i]) for i in indices if i < len(pool))
    print(f"[+] Flag tìm được: {flag}")
if __name__ == "__main__":
    solve()
```
FLAG:W1{do_you_know_how_to_trace?}
