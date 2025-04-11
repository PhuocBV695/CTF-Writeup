# anti1.exe  
hàm main:  
![image](https://github.com/user-attachments/assets/03fa72aa-1946-4642-be98-1b2f2509267e)  
ở đây ta bắt gặp hàm `RaiseException()`, hàm này đăng ký 1 ngoại lệ, nếu handler không xử lý được ngoại lệ thì sẽ tiếp tục chương trình, ngược lại thì sẽ báo exception  
  
![image](https://github.com/user-attachments/assets/802609d7-6dc2-4aa4-80a5-2ee86cb8ed44)  

hàm `sub_A31220` lấy input xor với `BKSEECCCC!!!`
![image](https://github.com/user-attachments/assets/bb7ce964-c6e0-4fc4-80e7-18407ad10276)

tiếp tục debug, ta bắt gặp 1 antidebug khác là `PEB!BeingDebugged`:  
![image](https://github.com/user-attachments/assets/6cf09342-1369-4f76-871e-5ead1e76ef4f)  
ta cần đổi `ZF` thành 0x1 hoặc patch chương trình để nhảy qua luồng đúng  
script solve:  
```python
n=[0,0,0,0,0x6,0x38, 0x26, 0x77, 0x30, 0x58, 0x7E, 0x42, 0x2A, 0x7F, 0x3F, 0x29, 0x1A, 0x21, 0x36, 0x37, 0x1C, 0x55, 0x49, 0x12, 0x30, 0x78, 0x0C, 0x28, 0x30, 0x30, 0x37, 0x1C, 0x21, 0x12, 0x7E, 0x52, 0x2D, 0x26, 0x60, 0x1A, 0x24, 0x2D, 0x37, 0x72, 0x1C, 0x45, 0x44, 0x43, 0x37, 0x2C, 0x6C, 0x7A, 0x38]
a=b'BKSEECCCC!!!'
for i in range(len(n)): print(chr(n[i]^a[i%len(a)]),end='')
```
Flag: `BKSEC{e4sy_ch4ll_but_th3r3_must_b3_som3_ant1_debug??}`  
nếu không bypass `PEB!BeingDebugged` thì ta sẽ nhận được fakeflag như sau:  
![image](https://github.com/user-attachments/assets/19cdf4d3-0359-448b-9cab-0a18f33e9fa4)  

# Replace.exe  
![image](https://github.com/user-attachments/assets/a1ee5750-91d4-441a-aed5-a0d5c35d40d8)  
chương trình thực hiện mã hóa input bằng hàm `sub_401180()` với key là `VdlKe9upfBFkkO0L`  
`sub_401180()`:  
```c
int __fastcall sub_401180(_DWORD *a1, _DWORD *a2)
{
  int result; // eax

  *a1 ^= a2[1] + *a2;
  result = a1[1] ^ (a2[3] + a2[2]);
  a1[1] = result;
  return result;
}
```
tuy nhiên chương trình từ đầu xuất hiện TLScallback, kiểm tra debugger, thực hiện ghi đè lại hàm `sub_401180()`:  
![image](https://github.com/user-attachments/assets/4098503e-9bd3-4a19-b22a-048fb83ca2bb)  
bypass antidebug bằng cách đặt breakpoint và sửa lại ZF.  
lúc này hàm `sub_401180()` đã bị thay đổi thành:  
```c
int __fastcall sub_401070(unsigned int *a1, _DWORD *a2)
{
  int result; // eax
  unsigned int i; // [esp+14h] [ebp-18h]
  int v4; // [esp+1Ch] [ebp-10h]
  unsigned int v5; // [esp+24h] [ebp-8h]
  unsigned int v6; // [esp+28h] [ebp-4h]

  v6 = *a1;
  v5 = a1[1];
  v4 = 0;
  for ( i = 0; i < 0x20; ++i )
  {
    v4 -= 1640531527;
    v6 += (a2[1] + (v5 >> 5)) ^ (v4 + v5) ^ (*a2 + 16 * v5);
    v5 += (a2[3] + (v6 >> 5)) ^ (v4 + v6) ^ (a2[2] + 16 * v6);
  }
  *a1 = v6;
  result = 4;
  a1[1] = v5;
  return result;
}
```
ta có thể nhận ra đây là mã hóa TEA.  
script decrypt:  
```python
from Crypto.Util.number import*

n=b"\x19\x2C\x30\x2A\x79\xF9\x54\x02\xB3\xA9\x6C\xD6\x91\x80\x95\x04\x29\x59\xE8\xA3\x0F\x79\xBD\x86\xAF\x05\x13\x6C\xFE\x75\xDB\x2B\xAE\xE0\xF0\x5D\x88\x4B\x86\x89\x33\x66\xAC\x45\x9A\x6C\x78\xA6"
m=b'VdlKe9upfBFkkO0L'

v=[]
k=[]
for i in range(0,len(n),4): v.append(bytes_to_long(n[i:i+4][::-1]))
for i in range(0,len(m),4): k.append(bytes_to_long(m[i:i+4][::-1]))

def teadecrypt(v, k):
    v0, v1 = v
    delta = 0x9E3779B9
    sum = (delta * 32) & 0xFFFFFFFF
    for _ in range(32):
        v1 = (v1 - ((v0 << 4) + k[2] ^ v0 + sum ^ (v0 >> 5) + k[3])) & 0xFFFFFFFF
        v0 = (v0 - ((v1 << 4) + k[0] ^ v1 + sum ^ (v1 >> 5) + k[1])) & 0xFFFFFFFF
        sum = (sum - delta) & 0xFFFFFFFF

    return v0, v1
p=b''
for i in range(0,len(v),2):
    a=(teadecrypt(v[i:i+2],k))
    p+=long_to_bytes(a[0])[::-1]
    p+=long_to_bytes(a[1])[::-1]
print(p)
#b'PTITCTF{bdc90e23aa0415e94d0ac46a938efcf3}\n\n\n\n\n\n'
```
Flag: `PTITCTF{bdc90e23aa0415e94d0ac46a938efcf3}`  
![image](https://github.com/user-attachments/assets/0f2bcd4a-3ab1-48ae-8704-dc9a8717a6fc)  

# ThitNhi  
hàm main:  
![image](https://github.com/user-attachments/assets/aeb8e9a4-0489-4331-8d36-e8acaadd2154)  
ta xem hàm `sub_A51080(main)`:  
![image](https://github.com/user-attachments/assets/ae8cc097-839a-4f5c-bd5e-80729d874226)  
ta thấy hàm này đếm số opcodes của hàm main cho đến khi gặp `ret` (tức 0xc3).  
hàm `sub_A510C0(main, v4)`:  
![image](https://github.com/user-attachments/assets/89680993-5f08-44e0-b2d2-4f8aee14ae45)  
hàm này duyệt tất cả các opcodes trong `main`, nếu gặp 0xCC tức `int 3` thì dừng và trả về 19, còn nếu không có thì trả về 55.  
mục đích của hàm này là tìm breakpoint trong main nhằm phát hiện debugger  
Tuy nhiên không phải lúc nào 0xCC cũng là breakpoint:  
![image](https://github.com/user-attachments/assets/617a3800-78cf-4340-b27b-8e39db9d235a)  
vậy kết quả đúng của `v7` là 0xDEADBEEF^19.  
ta vào hàm `sub_A51120((int)Buffer, 13, (int *)&v7, 4, (int)v9);`:  
![image](https://github.com/user-attachments/assets/1f6f34e7-f82b-4f64-92a4-fbaf6a9ca03a)  
ta thấy hàm này thực hiện mã hóa RC4 và tiếp tục sử dụng kỹ thuật anti-debug trên để khởi tạo key  
Khác là lần này hàm `sub_A51120` không có opcode 0xCC nên key chính xác là  (0xDEADBEEF^19)+55 = 0xdeadbf33.  
Ta cũng có thể đặt hardware breakpoint để bypass kỹ thuật này.  
script solve:  
```python=
from Crypto.Cipher import ARC4
enc = bytes([0x7D, 0x08, 0xED, 0x47, 0xE5, 0x00, 0x88, 0x3A, 0x7A, 0x36, 0x02, 0x29, 0xE4])
key = (0xDEADBF33).to_bytes(4, byteorder='little')
cipher = ARC4.new(key)
decrypted = cipher.decrypt(enc)
print(decrypted) 
#b'D1t_m3_H4_N41'
```

# antidebug_3.exe
hàm main:  
![image](https://github.com/user-attachments/assets/87f702d9-d391-4dda-8d62-6c78c46558b6)  
mã giả:  
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter; // [esp+0h] [ebp-8h]

  lpTopLevelExceptionFilter = SetUnhandledExceptionFilter(TopLevelExceptionFilter);
  SetUnhandledExceptionFilter(lpTopLevelExceptionFilter);
  return 0;
}
```
ta bắt gặp hàm `SetUnhandledExceptionFilter(TopLevelExceptionFilter)`, có nghĩa là đăng ký hàm `TopLevelExceptionFilter`, nếu chương trình gặp 1 ngoại lệ và không có handle xử lý ngoại lệ, sẽ nhảy vào hàm đã đăng ký.  
ta có thể thấy rằng ngoại lệ là chia 0:  
![image](https://github.com/user-attachments/assets/1471e404-7a83-46c4-baa3-ffd3830e416e)  
ta có thể patch để gọi hàm `TopLevelExceptionFilter` luôn:  
![image](https://github.com/user-attachments/assets/08bc550b-ba34-4024-b3a9-a11dac45d921)  
mã giả trở thành:  
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  struct _EXCEPTION_POINTERS *v3; // eax
  LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter; // [esp+0h] [ebp-8h]

  v3 = (struct _EXCEPTION_POINTERS *)SetUnhandledExceptionFilter(TopLevelExceptionFilter);
  TopLevelExceptionFilter(v3);
  SetUnhandledExceptionFilter(lpTopLevelExceptionFilter);
  return 0;
}
```
tiếp tục vào `TopLevelExceptionFilter`:  
![image](https://github.com/user-attachments/assets/7715cd95-84b7-490e-a2eb-3568db787106)  
có những opcodes thừa khiến cho IDA không convert được sang mã giả và cũng không ảnh nhửng chương trình nên ta sẽ patch những opcodes này thành `nop` đi:  
![image](https://github.com/user-attachments/assets/f20dd55e-ee83-4995-80a3-50d0d6f224b3)  
mã giả:  
![image](https://github.com/user-attachments/assets/b357819e-643d-4617-9bc6-69abb8deb9e9)  
ta thấy `byte_554082 = NtCurrentPeb()->BeingDebugged ^ 0xAB;` kiểm tra PEB!BeingDebugged xem có debugger không, nếu không thì `byte_554082`=0xAB.  
hàm `anti_breakpoint` kiểm tra xem trong `loc_551330` có opcode 0xCC không, nếu không thì trả về `dword_554114`=`0xBEEF`.  
```c
 for ( i = 0; i < 17; ++i )
    Src[i] ^= 1u;
```
đoạn trên lấy 17 ký tự đầu tiên của input xor với 1.  
vào hàm `sub_551460(&unk_554652)`:  
![image](https://github.com/user-attachments/assets/8c383b39-6a3a-4a7c-b6ca-2dddd0a1a3bb)  
hàm `loc_C11330`:  
![image](https://github.com/user-attachments/assets/9362ed1e-d2b5-4c36-99fb-f99d61d549bd)  
ta vào hàm `sub_C111D0`:  
![image](https://github.com/user-attachments/assets/0b5b82d2-3b4e-4273-9d3a-cbcf5bb3ea76)  
ta gặp 1 ngoại lệ là `int 2d`:  
![image](https://github.com/user-attachments/assets/00cad374-8ba0-4fe2-9632-48c0e6effa55)  
khi không có handle xử lý ngoại lệ thì sẽ nhảy vào `loc_C11269` còn nếu ta debug nhảy từng instructions thì sẽ qua `int 2d` và vào `loc_C11221` dẫn đến bị sai luồng.  
tương tự với `int 3`:  
![image](https://github.com/user-attachments/assets/61eced07-e48d-4cd0-b0e2-91c347cfda43)  
vậy ta chỉ cần `nop` và patch `jmp` vào hàm đúng là được.  
mã giả trở thành:  
![image](https://github.com/user-attachments/assets/a9abd129-f4a7-4e06-9bd9-7935190301d9)  
hàm `sub_C11190`:  
```c
int __cdecl sub_C11190(int a1)
{
  int result; // eax
  int i; // [esp+0h] [ebp-4h]

  for ( i = 1; i < 30; ++i )
  {
    *(_BYTE *)(i + a1) ^= *(_BYTE *)(i + a1 - 1);
    result = i + 1;
  }
  return result;
}
```
và hàm `sub_C11100()` là kiểm tra xem tất cả các bytes đã mã hóa có đúng hay không:  
![image](https://github.com/user-attachments/assets/bee8621f-f7fa-4fa0-9ec9-c6c2930eb2a9)  
script:  
```python
from Crypto.Util.number import*
enc=[0x74, 0x6F, 0x69, 0x35, 0x4F, 0x65, 0x6D, 0x32, 0x32, 0x79, 0x42, 0x32, 0x71, 0x55, 0x68, 0x31, 0x6F, 0x5F, 0xDB, 0xCE, 0xC9, 0xEF, 0xCE, 0xC9, 0xFE, 0x92, 0x5F, 0x10, 0x27, 0xBC, 0x09, 0x0E, 0x17, 0xBA, 0x4D, 0x18, 0x0F, 0xBE, 0xAB, 0x5F, 0x9C, 0x8E, 0xA9, 0x89, 0x98, 0x8A, 0x9D, 0x8D, 0xD7, 0xCC, 0xDC, 0x8A, 0xA4, 0xCE, 0xDF, 0x8F, 0x81, 0x89, 0x5F, 0x69, 0x37, 0x1D, 0x46, 0x46, 0x5F, 0x5E, 0x7D, 0x8A, 0xF3, 0x5F, 0x59, 0x01, 0x57, 0x67, 0x06, 0x41, 0x78, 0x01, 0x65, 0x2D, 0x7B, 0x0E, 0x57, 0x03, 0x68, 0x5D, 0x07, 0x69, 0x23, 0x55, 0x37, 0x60, 0x14, 0x7E, 0x1D, 0x2F, 0x62, 0x5F, 0x62, 0x5F]
for i in range(17):
    print(chr(enc[i]^1),end='')
print(chr(enc[17]),end='')
for i in range(18,26):
    print(chr(enc[i]^0xab),end='')
print(chr(enc[26]),end='')
k=0
for i in range(27,39):
    print(chr((enc[i]^(k+0xcd))//2),end='')
    k=k+1
print(chr(enc[39]),end='')
for i in range(40,58,2):
    print(chr(enc[i]^0xEF),end='')
    print(chr(enc[i+1]^0xBE),end='')
print(chr(enc[58]),end='')
def rol(val, bits, bit_size):
    return (val << bits % bit_size) & (2 ** bit_size - 1) | \
           ((val & (2 ** bit_size - 1)) >> (bit_size - (bits % bit_size)))
k=0
for i in range(59,64):
    print(chr(rol(enc[i], k,8)),end='')
    k=k+1
print(chr(enc[64]),end='')
xor_key = 0xC0FE1337
n=0
k=0
for i in range(65,69):
    n+=enc[i]*(256**k)
    k=k+1
print(long_to_bytes(n^xor_key).decode()[::-1],end='')
print(chr(enc[69]),end='')
print(chr(enc[70]),end='')
for i in range(71,100):
    print(chr(enc[i]^enc[i-1]),end='')
#unh4Ndl33xC3pTi0n_pebDebU9_nt9lob4Lfl49_s0F7w4r38r34Kp01n7_int2d_int3_YXV0aG9ydHVuYTk5ZnJvbWtjc2M===
```
# Heavensdoor.exe  
main:  
![image](https://github.com/user-attachments/assets/19f32b9a-b498-4066-b6b0-c1a62679266e)  
![image](https://github.com/user-attachments/assets/a21cc327-4ad4-47bc-baac-e5d043ee5d6b)  
ta thấy push 0x33 vào stack
tiếp theo `call $+5` push `eip` vào stack  
cộng thêm 5 vào giá trị vừa push vào  
gọi retf  
retfar thực hiện chức năng như `ret` và thay đổi thanh ghi `CS` thành 0x33 (tức 64 bit) và chuyển sang môi trường 64bit.  
tiếp theo:  
![image](https://github.com/user-attachments/assets/f8cbb426-113b-4c8c-b766-f95b528333ea)  

chương trình lea 1 địa chỉ chứa eax và gọi hàm tại địa chỉ đó.  
ta trỏ vào eax:  
chương trình thực hiện xor từng input và kiểm tra điều kiện.  
sau khi call thành công eax, chương trinh lại push 0x23 (tức 32) và eip, retfar đưa chương trình về lại 32 bit  
![image](https://github.com/user-attachments/assets/82c02fb1-bf15-4995-8295-66bce86a0638)  
nếu hàm kiểm tra điều kiện vừa rồi đúng thì báo Correct và in ra flag, ngược lại thì báo incorrect.  
vậy ta phải nhập input đúng để thỏa mãn điều kiện.  
script:  
```python
import idc
import ida_bytes

ea = 0x01180403 #giá trị eax lúc call eax
xor_key=[]
enc=[]
for i in range(0,400,size):
    size = ida_bytes.get_item_size(ea+i)
    op = ida_bytes.get_bytes(ea+i, size)
    op2 = ida_bytes.get_bytes(ea+i+size, size)
    if op[0]==0x34 or op[0]==0x80:
        xor_key.append(op[-1])
        enc.append(op2[-1])
        print(chr((op[-1]^op2[-1])),end='')
print(xor_key,enc,len(xor_key),len(enc))
#h33d_t0_th3_c4ll_0f_th3_h34ven!!
```

# anti3  
main:  
![image](https://github.com/user-attachments/assets/3f8c9124-94b1-48a1-9835-dc5916207706)  
ta kiểm tra import thấy xuất hiện `TLSCallback`:  
![image](https://github.com/user-attachments/assets/d465872e-cd42-41db-bbe8-a5c2f2e20115)  

hàm `GetModuleAddressCRC((void *)0x2489AAB)`:  
![image](https://github.com/user-attachments/assets/0be5b8df-af6c-4e55-ae3f-8f4130b9e7ed)  
mình đã comment các dòng code như trong hình, cơ bản hàm này duyệt từng tên các module đã được load vào process, đưa về lowercase và tính CRC32, nếu bằng với CRC đã cho thì trả về địa chỉ của module  
hàm `GetProcAddressCRC((int)LibraryCRC, 0x3200C39D);`:  
![image](https://github.com/user-attachments/assets/19b7243e-e9e3-40cb-a4c9-8a777b7daa36)  
hàm trên duyệt tên các API trong DLL, nếu có CRC32 trùng khớp với CRC32 đã cho thì trả về address của API đấy.  
ta có thể biết chương trình đã resolve hàm gì bằng cách đặt breakpoint:  
![image](https://github.com/user-attachments/assets/56762f5d-5a00-4169-a1f0-3063b40bbf1a)  
![image](https://github.com/user-attachments/assets/d7255f4e-02a6-4174-b560-3e24f444660b)  
vậy ta biết chương trình đã resolve hàm `NtQueryInformationProcess` với `ProcessInformationClass` = 0x7 tức `ProcessDebugPort`  
đây là 1 kỹ thuật nhằm phát hiện antidebug, ta có thể bypass bằng cách đổi ZF flag  

hàm xử lý chính của chương trình:  
![image](https://github.com/user-attachments/assets/202aa723-05fe-4c54-91ba-eaa01823cd6a)  
Chương trình xử lý input và kiểm tra điều kiện, nếu đúng thì gọi messagebox in `OK`, sai thì báo `Wrong`  
đi vào `sub_F31B40`:  
![image](https://github.com/user-attachments/assets/1ac3cefe-d3d5-4555-8363-c6a23630289f)  
kiểm tra độ dài input, check flag từng kí tự  
thứ tự các case: `dword_F332C8=[6, 1, 7, 1, 3, 2, 4, 3, 6, 3, 7, 6, 1, 4, 7, 4, 1, 5, 7, 6, 7, 5, 6, 4, 5, 1, 7, 5, 2, 3, 1, 2, 3, 2, 1, 6, 2, 4]`  
vậy ta phân tích từ case 6  
CASE 6:  
![image](https://github.com/user-attachments/assets/c3b017b3-0002-49c1-a63c-256bb407b077)  
mình đã rename các hàm dựa trên các chức năng của nó.  
ta xem chương trình đã resolve gì:  
![image](https://github.com/user-attachments/assets/8dbd5557-9677-45f4-8173-b52387509cc7)  
![image](https://github.com/user-attachments/assets/a13a49be-b61c-4263-bdb6-e83bb1b08522)  
vậy case này gọi API [BlockInput](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-blockinput).  
https://anti-debug.checkpoint.com/techniques/interactive.html#blockinput  
hàm này BlockInput từ user, nếu block thành công thì trả về nonzero, nếu gọi BlockInput lần nữa mà vẫn trả về nonzero thì chứng tỏ có debugger đang hoạt động  
![image](https://github.com/user-attachments/assets/2f93e061-e782-4083-9eda-2efcc10cced2)  

cách bypass: 
nếu không có debugger, lần đầu check sẽ là v7!=0, v8=0, tuy nhiên do switchcase gọi nhiều lần nên chương trình đầu tiên đặt cờ `byte_3355B8`=0, sau khi check thì gán `byte_3355B8`=1 để kiểm tra theo cách khác, vì lần sau thì v7 và v8 đều bằng 0  
để bypass thì ta patch sao cho chương trình luôn nhảy vào LABEL3:  
![image](https://github.com/user-attachments/assets/19248605-f542-4898-9bd8-ea10c321bae9)  
mã giả:  
![image](https://github.com/user-attachments/assets/e43d754e-c646-44a0-9313-0aa494a67241)  

CASE 1:  
![image](https://github.com/user-attachments/assets/d28e3b78-dcf2-4a21-990b-1729aec3b8eb)  
ta có thể thấy chương trình phát hiện debug bằng cách kiểm tra giá trị trường `NtGlobalFlag` trong PEB:  
![image](https://github.com/user-attachments/assets/e0d20bf2-a4c4-47c2-bb57-646ad1899594)  
ta có thể bypass bằng cách đổi ZF hoặc patch  
  
CASE 7:  
![image](https://github.com/user-attachments/assets/ef53e263-6819-4181-84fe-97225e70b5fb)  
kiểm tra xem resolve hàm gì:  
![image](https://github.com/user-attachments/assets/cc19b284-35dd-4a22-b135-d8f45ad4d9b6)  
vậy case này antidebug bằng cách kiểm tra giá trị tại `NtQueryInformationProcess`(0x1f) tức `ProcessDebugFlags`  
patch:  
![image](https://github.com/user-attachments/assets/0985926b-bcbb-4716-88a5-4d191afe767a)  
  
CASE3:  
![image](https://github.com/user-attachments/assets/a8b44750-bcd0-41b5-8ece-4bf9758895e5)  
có vẻ là kiểm tra tổng 1 số trường `Heap Flags`  
mình không rõ kỹ thuật anti-debug này lắm nhưng ta có thể patch để bypatch như sau:  
![image](https://github.com/user-attachments/assets/bee798dc-8460-47b1-b56b-115f1f566038)  

CASE 2:  
![image](https://github.com/user-attachments/assets/f1bc511c-f039-4e92-9f9a-3b206b5fcb48)  
tương tự như case 3 và tắt block input    
CASE 4:  
![image](https://github.com/user-attachments/assets/4d2b2eac-5e0f-4953-8705-11271dd45730)  
cơ chế antidebug: nếu HEAP_TAIL_CHECKING_ENABLED flag được bật thì 0xABABABAB sẽ được thêm vào cuối khối heap đã cấp phát.  
https://anti-debug.checkpoint.com/techniques/debug-flags.html#manual-checks-heap-protection  
![image](https://github.com/user-attachments/assets/f8d0a68b-44ab-48dd-9b52-7253d5cc2318)  
bypass:  
![image](https://github.com/user-attachments/assets/2d9cd3d6-70d1-464d-b78a-ea06175ec07b)  

CASE 5:  
![image](https://github.com/user-attachments/assets/30c9a7a6-47b1-4d55-8d7a-01cb4d9c9b7a)  
lấy tên handle chạy chương trình, tuy nhiên không thấy ảnh hưởng đến quá trình debug nên không cần bypass.  

đã bypass hết các antidebug, ta chỉ cần nhặt các flag theo thứ tự là được.  
`I_10v3-y0U__wh3n Y0u=c411..M3 Senor1t4`  
flag:  
![image](https://github.com/user-attachments/assets/1cd07c11-95b5-4433-877f-d4c32ebd9e04)  







