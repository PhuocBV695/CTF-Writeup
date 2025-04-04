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

