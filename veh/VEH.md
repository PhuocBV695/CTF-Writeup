# sneaky_veh  
main:  
![image](https://github.com/user-attachments/assets/d740b7ff-ee0c-4a61-8688-85ba0e9b40dd)  
![image](https://github.com/user-attachments/assets/b3175e1c-1659-47be-b6eb-73de41c2de62)  
![image](https://github.com/user-attachments/assets/de4cc9e9-57cd-4c1b-a2ba-b17d2aaad02a)  
Bài yêu cầu nhập vào 4 passcode.  
phân tích:  
ta có thể thấy:  
![image](https://github.com/user-attachments/assets/66995a67-9870-434c-aa99-b01740f14482)  
đây là mã asm của việc xử lý khối try/except, để có thể hiểu hơn, ta có thể test thử:  
mã C:  
![image](https://github.com/user-attachments/assets/02226564-7a75-4fbb-9be7-a2f223df1017)  
asm IDA:  
![image](https://github.com/user-attachments/assets/7d235742-2e66-43c8-9aa1-7399278687b6)  
Đây là phần đăng ký Exception Registration Record trên SEH, dùng để định danh các khối try/except.  
với `offset stru_BDA240` là con trỏ đến scope table.  
![image](https://github.com/user-attachments/assets/57d13d4a-9d31-46bf-af43-d6f4f3bda79b)  
ta thấy `$LN7` là khối in chữ `hoho` và `$LN10` in chữ `hehe` vậy từ đây ta có thể suy ra thứ tự xử lý exception bài sneaky_veh.  
trở về bài sneaky_veh:  
![image](https://github.com/user-attachments/assets/430e238c-0f05-4304-a0a6-fe62233caa31)  
ta có thể suy ra khối try/except như sau:  
```c
int main() {
    __try {
        //exception
        __try {
            //exception
            __try {
                //exception
                __try {
                    //exception
                }
                __except (loc_AC1FAA(GetExceptionInformation())) {  //except filter
                    loc_AC1FB4();                                   //except handler
                }
            }
            __except (loc_AC1F5D(GetExceptionInformation())) {
                loc_AC1F67();
            }
        }
        __except (loc_AC1F19(GetExceptionInformation())) {
            loc_AC1F23();
        }
    }
    __except (loc_AC1EAE(GetExceptionInformation())) {
        loc_AC1EB8();
    }

    return 0;
}
```
ta đi vào khối `__try/__except` ngoài cùng:  
![Screenshot 2025-04-18 171637](https://github.com/user-attachments/assets/d966b38a-c9c8-4d56-883c-934ae086dee4)  
![image](https://github.com/user-attachments/assets/9366a928-5923-452b-92bc-3b29081aa092)  

phần mũi tên màu vàng (bao gồm loc_651EB8 và loc_651E8D) là khối try, nếu gặp 1 ngoại lệ mà handler không xử lý được, thanh ghi EIP sẽ gọi except filter(loc_141EAE) để xử lý xem có nhảy vào khối except (loc_141EB8) hay không.  
phân code này có vẻ là cấp phát bộ nhớ thất bại thành ra gọi memset(NULL, 0, 0x1000) gây ra ngoại lệ:  
![image](https://github.com/user-attachments/assets/9dea7565-1c11-4039-8461-e11e82d969f2)  
EIP sẽ nhảy vào except filter:  
![image](https://github.com/user-attachments/assets/3f5d1e59-b82d-4648-be99-c7933b4e1ecc)  
hàm `sub_BA1B50`:  
![image](https://github.com/user-attachments/assets/58bc40d4-6baf-4032-b52f-2823598085cd)  
mình đã comment chức năng các dòng code như trên  
hàm này kiểm tra xem exception bắt được có nằm trong các exception được filter hay không và nếu có thì thực thi các chức năng như mã hóa lại shellcode...  
ta xem `off_BA4020`:  
![image](https://github.com/user-attachments/assets/a5d09308-08e3-457f-8aed-7ed09c4879a1)  
do hiện tại `dword_BA746C` đang là 0 nên ta trỏ đến `offset sub_BA4148`:  
![image](https://github.com/user-attachments/assets/6866a895-bf1b-40bf-ab9c-c2f213c3074b)   
ta lấy các opcode ra được v4_1=`[0xD4, 0x4D, 0x91, 0xFD, 0x7C, 0xB9, 0x28, 0x18, 0x18, 0x18, 0x93, 0x58, 0x14, 0x93, 0x58, 0x0C, 0x93, 0x18, 0x93, 0x58, 0x08, 0x45, 0xDB]`  
tiếp tục phân tích except handler:  
![image](https://github.com/user-attachments/assets/285c43ca-8bf4-4f22-b98a-a7c4ef9d34c5)  
tiếp tục lại là 1 khối try/except khác.  
ta thấy khối try này thực hiện gọi shellcode mà phần opcodes chính là v4_1 đã bị mã hóa xor trước đó.  
do bất kỳ hàm nào được gọi cũng phải có lệnh `ret` tức `0xC3` nên ta có thể đoán rằng `0xDB==0xC3^KEY[0]`  
vậy KEY[0]==0xDB^0xC3==0x18  
ta thay KEY[0]=0x18:  
![image](https://github.com/user-attachments/assets/d70dc0f1-ad25-46a7-8dd8-0b9233550b68)  
đặt breakpoint tại `call lpAddress` và trỏ vào `lpAddress`:  
![image](https://github.com/user-attachments/assets/b6b6a020-c328-4477-89d2-db017f0b8765)  
![image](https://github.com/user-attachments/assets/5b96b1cf-0d41-4321-b1f1-72db4cddac40)  
ta thấy đoạn shellcode đã trở thành code hợp lệ.  
đoạn code này thực hiện gọi 1 exception là `int 3` và có thể là lấy base address của ntdll.  
nếu ta tiếp tục debug bằng debugger thì sẽ dẫn đến luồng bị sai  
do hàm này đã gọi 1 ngoại lệ nên EIP lúc này sẽ nhảy vào exception filter tiếp theo (loc_BA1F19):  
![image](https://github.com/user-attachments/assets/84f66274-ac49-4be1-b9dd-2dc457cdc480)  
do exception code là `0x80000003` nên vẫn thực hiện xor shellcode như lần trước  
vẫn giống như `loc_BA1EAE` tuy nhiên do `dword_BA746C` đã tăng lên 1 nên ta trỏ vào `sub_BA4030`.  
ta được opcodes:  v4_2=`[0xC6, 0x5F, 0x83, 0xEF, 0x89, 0xE6, 0x16, 0x3B, 0xCA, 0x83, 0x4F, 0xF6, 0x83, 0x4F, 0xF2, 0x83, 0x4F, 0xFE, 0x83, 0x4F, 0xFA, 0x83, 0x4F, 0xE6, 0x83, 0x4F, 0xE2, 0x83, 0x4F, 0xEE, 0x62, 0x6F, 0x78, 0x0A, 0x0A, 0x62, 0x6B, 0x64, 0x6E, 0x66, 0x62, 0x63, 0x65, 0x64, 0x42, 0x62, 0x69, 0x6F, 0x7A, 0x7E, 0x62, 0x6F, 0x6E, 0x4F, 0x72, 0x62, 0x69, 0x7E, 0x65, 0x78, 0x62, 0x6E, 0x6E, 0x5C, 0x6F, 0x62, 0x58, 0x7E, 0x66, 0x4B, 0x83, 0x6F, 0xE6, 0x6E, 0xAB, 0x3A, 0x0A, 0x0A, 0x0A, 0x81, 0x4A, 0x06, 0x81, 0x4A, 0x1E, 0x81, 0x0A, 0x81, 0x4A, 0x1A, 0x83, 0xC9, 0x81, 0x49, 0x36, 0x0B, 0xD2, 0x81, 0x4A, 0x72, 0x0B, 0xD2, 0x81, 0x42, 0x1E, 0x83, 0x47, 0xF6, 0x81, 0x42, 0x16, 0x0B, 0xD3, 0x83, 0x47, 0xF2, 0x81, 0x42, 0x2A, 0x0B, 0xD3, 0x83, 0x47, 0xFE, 0x81, 0x42, 0x2E, 0x0B, 0xD3, 0x83, 0x47, 0xFA, 0x3B, 0xCA, 0x3B, 0xC3, 0x81, 0x7F, 0xE6, 0x81, 0x77, 0xFE, 0xF6, 0x81, 0x36, 0x8D, 0x0B, 0xD5, 0x6C, 0xB3, 0x15, 0x0A, 0xF9, 0xAC, 0x7E, 0x0C, 0x4A, 0x31, 0x4F, 0xF6, 0x7F, 0xEC, 0x81, 0x47, 0xFA, 0x81, 0x5F, 0xF2, 0x6C, 0x81, 0x0E, 0x4B, 0x81, 0x0E, 0x88, 0x0B, 0xD2, 0xE1, 0x0A, 0x3B, 0xD8, 0x81, 0x47, 0x02, 0x5B, 0x60, 0x0B, 0xF5, 0xDA, 0x89, 0xCE, 0x16, 0x89, 0xCE, 0x2A, 0x57, 0xC9]`  
tiếp tục xor 0xC9 với 0xC3 như lần trước ta được KEY[1]==0xa  
shellcode trở thành:  
```c
int __cdecl sub_BA4030(int a1)
{
  struct _LIST_ENTRY *Flink; // ebx
  _DWORD *v2; // eax
  int v3; // eax
  int v4; // ecx
  char *v5; // esi
  int v6; // edi
  bool v7; // zf
  _BYTE *v8; // edi
  char v10[32]; // [esp-40h] [ebp-40h] BYREF
  int v11; // [esp-20h] [ebp-20h]
  int v12; // [esp-1Ch] [ebp-1Ch]
  char *v13; // [esp-18h] [ebp-18h]
  char *v14; // [esp-14h] [ebp-14h]
  char *v15; // [esp-10h] [ebp-10h]
  char *v16; // [esp-Ch] [ebp-Ch]
  int v17; // [esp-8h] [ebp-8h]

  __debugbreak();
  v17 = 0;
  v16 = 0;
  v15 = 0;
  v14 = 0;
  v12 = 0;
  v11 = 0;
  v10[31] = 0;
  strcpy(v10, "RtlAddVectoredExceptionHandler");
  v13 = v10;
  Flink = NtCurrentPeb()->Ldr->InMemoryOrderModuleList.Flink->Flink[2].Flink;
  v2 = (struct _LIST_ENTRY **)((char *)&Flink->Flink
                             + *(unsigned int *)((char *)&Flink[15].Flink + (unsigned int)Flink[7].Blink));
  v17 = v2[5];
  v16 = (char *)Flink + v2[7];
  v15 = (char *)Flink + v2[8];
  v14 = (char *)Flink + v2[9];
  v3 = 0;
  HIWORD(v4) = 0;
  do
  {
    v5 = v13;
    v6 = *(_DWORD *)&v15[4 * v3];
    v7 = (struct _LIST_ENTRY *)((char *)Flink + v6) == 0;
    v8 = (char *)Flink + v6;
    LOWORD(v4) = 31;
    do
    {
      if ( !v4 )
        break;
      v7 = *v5++ == *v8++;
      --v4;
    }
    while ( v7 );
    if ( v7 )
      break;
    ++v3;
  }
  while ( v3 != v17 );
  LOWORD(v3) = *(_WORD *)&v14[2 * v3];
  return ((int (__stdcall *)(int, int))((char *)Flink + *(_DWORD *)&v16[4 * v3]))(1, a1);    //gọi AddVectoredExceptionHandle(1, a1)
}
```
shellcode này thực hiện gọi exception `int 3` và thực hiện kỹ thuật PEB traversal để gọi `AddVectoredExceptionHandle(1, a1)`  
ta tiếp tục phân tích except handler:  
![image](https://github.com/user-attachments/assets/952338c2-648c-4bdc-89c1-406a2c607391)  
chương trình tiếp tục gọi shell code `v4_1`, tuy nhiên lần này đã đẩy EIP lên nên không còn gọi exception nữa.  
tiếp theo là copy toàn bộ shellcode `v4_2` vào lpAddress và gọi shellcode  
do có exception `int 3` nên EIP nhảy vào exception filter (loc_C71F5D):  
![image](https://github.com/user-attachments/assets/876edbfa-799b-45c0-9edc-ec847a05ba24)  
vẫn giống như các filter trước, do `dword_C7746C` đã tăng lên 2 nên ta trỏ vào `offset dword_C74018`:  
![image](https://github.com/user-attachments/assets/dc3c4e5d-859a-4e50-837a-899083dee641)  
do chưa biết chương trình sẽ làm gì với `dword_C74018` nên ta chưa thể đoán được KEY[2] như lần trước.  
tiếp tục vào except handler:  
![image](https://github.com/user-attachments/assets/508acd8f-2548-460d-ad86-d99ddeabe802)  
lần này đẩy `sub_C715D0` vào stack và tiếp tục gọi shellcode v4_2, tuy nhiên EIP đã tăng lên nên không còn gọi exception nữa.  
đồng nghĩa với việc chương trình thực hiện `AddVectoredExceptionHandle(1, sub_C715D0)`.  
hàm này đăng ký `sub_C715D0` với `AddVectoredExceptionHandle` với độ ưu tiên cao nhất `1`, nếu lần tiếp theo bắt được exception, chương trình sẽ nhảy vào `sub_C715D0`.  
ta phân tích `sub_C715D0`:  
![image](https://github.com/user-attachments/assets/5323c2fb-6e3e-446c-a1e4-d0d2e2f38c0a)  
hàm này lọc các exception, và nếu có exception nằm trong filter, gọi hàm `sub_C713B0`.  
ta xem hàm `sub_C713B0`:  
```c
void *__stdcall sub_C713B0(int **a1)
{
  int v2; // [esp+8h] [ebp-30h]
  int v3; // [esp+Ch] [ebp-2Ch]
  _BYTE *v4; // [esp+1Ch] [ebp-1Ch]
  int v5; // [esp+20h] [ebp-18h]
  int j; // [esp+24h] [ebp-14h]
  unsigned int v7; // [esp+28h] [ebp-10h]
  int i; // [esp+2Ch] [ebp-Ch]
  int v9; // [esp+30h] [ebp-8h] BYREF

  v2 = **a1;                                    // exception code
  v3 = 0;
  v7 = 0;
  v5 = 0;
  v9 = 0;
  for ( i = 0; i < 4; ++i )
  {
    v9 = dword_C74138[i];
    v4 = lpAddress;
    if ( v2 == dword_C74118[i] && !dword_C77458[i] )
    {
      for ( j = 0; j < 4; ++j )
        v4[j] ^= *((_BYTE *)&v9 + j);
      switch ( i )
      {
        case 0:
          v7 = byte_C77470[0];                  // KEY[0]
          v5 = byte_C77470[1];                  // KEY[1]
          break;
        case 1:
          v7 = byte_C77470[1];
          v5 = byte_C77470[0];
          break;
        case 2:
          v7 = byte_C77470[2];                  // KEY[2]
          v5 = byte_C77470[3];                  // KEY[3]
          break;
        case 3:
          v7 = byte_C77470[3];
          v5 = byte_C77470[2];
          break;
        default:
          break;
      }
      if ( (v5 ^ ((v7 << 16) | (v7 >> 8) & 0xFF00 | HIBYTE(v7))) == dword_C740F8[i] )// check [0x252D0D17, 0x253F1D15, 0xBEA57768, 0xBAA5756E]
      {
        dword_C77458[i] = 1;
        return lpAddress;
      }
      return (void *)v3;
    }
  }
  return (void *)v3;
}
```
mình đã comment chức năng của 1 số dòng code như trên.  
tiếp tục về phân tích hàm main:  
![image](https://github.com/user-attachments/assets/70a4b655-c32c-406b-8c8d-3414c3343775)  
chương trình gọi hàm `sub_C719A0` và copy 4 bytes từ `dword_C74018` và 1 bytes từ `byte_C7401C` vào shellcode v4_2.  
từ đây, ta có thể đoán được rằng KEY[2] == 0xD1 ^ 0xCC == 0x1d.  
vào hàm `sub_C719A0`:  
```c
int __stdcall sub_C719A0(int a1)
{
  int v2; // [esp+Ch] [ebp-20h]
  unsigned int v3; // [esp+10h] [ebp-1Ch]
  char *Buf1; // [esp+14h] [ebp-18h]
  unsigned int j; // [esp+18h] [ebp-14h]
  unsigned int i; // [esp+1Ch] [ebp-10h]
  unsigned int v7; // [esp+20h] [ebp-Ch] BYREF
  char *v8; // [esp+24h] [ebp-8h] BYREF

  v8 = 0;
  v7 = 0;
  if ( sub_C71820(a1, &v8, &v7) )               // search header
    return 1;
  for ( i = 0; i < 0xD2; ++i )                  // search shellcode
  {
    if ( !dword_C74178[14 * i] )
    {
      Buf1 = v8;
      v3 = v7;
      v2 = 0;
      while ( dword_C74174[14 * i] <= v3 )
      {
        if ( !memcmp(Buf1, (char *)&unk_C74164 + 56 * i, dword_C74174[14 * i]) )
        {
          v2 = (int)Buf1;
          break;
        }
        ++Buf1;
        --v3;
      }
      if ( !v2 )
        return 1;
      dword_C74178[14 * i] = v2;
      for ( j = 0; j < 0xD2; ++j )
      {
        if ( dword_C74174[14 * j] == dword_C74174[14 * i]
          && !memcmp((char *)&unk_C74164 + 56 * j, (char *)&unk_C74164 + 56 * i, dword_C74174[14 * i]) )// trả về sub_C712A0
        {
          dword_C74178[14 * j] = dword_C74178[14 * i];
        }
      }
    }
  }
  return 0;
}
```
ta xem hàm `sub_C712A0`:  
```c
int __stdcall sub_C712A0(_BYTE *a1)
{
  int v2; // [esp+0h] [ebp-18h]
  int v3; // [esp+4h] [ebp-14h]
  int v4; // [esp+8h] [ebp-10h]
  int v5; // [esp+Ch] [ebp-Ch]

  if ( (unsigned __int8)(*a1 ^ LOBYTE(byte_C77470[1])) == 0x99 )// KEY[1]
    v5 = 0;
  else
    v5 = 16;
  if ( (unsigned __int8)(a1[4] ^ LOBYTE(byte_C77470[3])) == 0x4F )// KEY[4]
    v4 = 0;
  else
    v4 = 16;
  if ( (byte_C77470[1] ^ byte_C77470[0]) == *(_DWORD *)a1 )// KEY[1]^KEY[0]
    v3 = 0;
  else
    v3 = 16;
  if ( (byte_C77470[3] ^ byte_C77470[2]) == *((_DWORD *)a1 + 1) )// KEY[3]^KEY[2]
    v2 = 0;
  else
    v2 = 16;
  return v2 | v3 | v4 | v5;
}
```
đến đây thì mình cũng không biết giải thế nào, tham khảo [https://hackmd.io/@BlackFrost/BJeEgqNZR?utm_source=preview-mode&utm_medium=rec#Sneaky-VEH]  
script solve:  
```python
from z3 import *
keyArray = [BitVec(f"x{i}", 32) for i in range(4)]

HIBYTE = lambda x : (x >> 24) & 0xff
HIWORD = lambda x : (x >> 16) & 0xffff
BYTE1 = lambda x : (x >> 8) & 0xff

s = Solver()

s.add((HIBYTE(keyArray[0]) ^ HIWORD(keyArray[0]) ^ BYTE1(keyArray[0]) ^ keyArray[0]) & 0xff == 0x18)
s.add((HIBYTE(keyArray[1]) ^ HIWORD(keyArray[1]) ^ BYTE1(keyArray[1]) ^ keyArray[1]) & 0xff == 0xa)
s.add((HIBYTE(keyArray[2]) ^ HIWORD(keyArray[2]) ^ BYTE1(keyArray[2]) ^ keyArray[2]) & 0xff == 0x1d)
s.add((keyArray[1] ^ (((keyArray[0] << 0x10) & 0xffff0000) | (keyArray[0] >> 8) & 0xFF00 | HIBYTE(keyArray[0]))) == 0x252D0D17)
s.add((keyArray[0] ^ (((keyArray[1] << 0x10) & 0xffff0000) | (keyArray[1] >> 8) & 0xFF00 | HIBYTE(keyArray[1]))) == 0x253F1D15)
s.add((keyArray[2] ^ (((keyArray[3] << 0x10) & 0xffff0000) | (keyArray[3] >> 8) & 0xFF00 | HIBYTE(keyArray[3]))) == 0x0BAA5756E)
s.add((keyArray[3] ^ (((keyArray[2] << 0x10) & 0xffff0000) | (keyArray[2] >> 8) & 0xFF00 | HIBYTE(keyArray[2]))) == 0x0BEA57768)

s.add((keyArray[1] ^ 0x43534341) & 0xff == 0x99)
s.add((keyArray[3] ^ 0x32) & 0xff == 0x4f)
s.add(keyArray[0] ^ keyArray[1] == 0x43534341)
s.add(keyArray[2] ^ keyArray[3] == 0x34323032)

print(s.check())
m = s.model()

for i in keyArray:
    print(i, hex(m[i].as_long()))
#x0 0xcfe7a999
#x1 0x8cb4ead8
#x2 0x15d89f4f
#x3 0x21eaaf7d
```
flag:  
![image](https://github.com/user-attachments/assets/2634a661-58d4-4912-8c24-e8ab919a8b0f)  
# VEH  
main:  
![image](https://github.com/user-attachments/assets/891c5635-e35a-4c60-8f39-8cef3a886ec1)  
`initterm` luôn chạy trước main nên ta kiểm tra `initterm`:  
![image](https://github.com/user-attachments/assets/92518774-afe6-473b-8a73-93080914ef28)  
hàm `sub_7FF731482540`:  
![image](https://github.com/user-attachments/assets/6439b2c0-8ebe-4002-975a-7edcc31b0e49)  
hàm `sub_7FF6D58D11F0`:  
```c
__int64 sub_7FF6D58D11F0()
{
  void (__fastcall *ProcAddressFNV_1a)(_BYTE *); // r14
  __int64 i; // rax
  unsigned int v2; // edx
  __int64 j; // rsi
  __int16 v4; // dx
  char v5; // di
  unsigned int v6; // edx
  __int64 k; // rsi
  __int64 m; // rsi
  __int16 v9; // dx
  char v11; // [rsp+28h] [rbp-40h]
  _BYTE v12[63]; // [rsp+29h] [rbp-3Fh] BYREF

  ProcAddressFNV_1a = (void (__fastcall *)(_BYTE *))GetProcAddressFNV_1a(1102179001, 701355107);// LoadLibraryW
  v11 = 0;
  v12[0] = 24;
  v12[1] = 1;
  v12[2] = 16;
  v12[3] = 1;
  v12[4] = 122;
  v12[5] = 1;
  v12[6] = 69;
  v12[7] = 1;
  v12[8] = 69;
  v12[9] = 1;
  v12[10] = 109;
  v12[11] = 1;
  v12[12] = 37;
  v12[13] = 1;
  v12[14] = 111;
  v12[15] = 1;
  v12[16] = 111;
  v12[17] = 1;
  v12[18] = 1;
  v12[19] = 1;
  for ( i = 1LL; i != 21; ++i )
  {
    v2 = (unsigned __int16)(31 * (unsigned __int8)v12[i - 1]
                          + ((unsigned int)(-32509 * (__int16)(31 * (unsigned __int8)v12[i - 1] - 31)) >> 16)
                          - 31);
    v12[i - 1] = (unsigned __int8)(31 * v12[i - 1] - 127 * ((v2 >> 15) + (v2 >> 6)) - 31 + 127) % 0x7Fu;
  }
  ProcAddressFNV_1a(v12);                       // ntdll.dll
  v11 = 0;
  qmemcpy(v12, ";lcl}lwlhl|lMl\rlklklll", 22);
  for ( j = 1LL; j != 23; ++j )
  {
    v4 = (unsigned __int8)v12[j - 1];
    v5 = 19 * v4;
    v6 = (unsigned __int16)(19 * v4 + ((unsigned int)(-32509 * (__int16)(19 * v4 - 2052)) >> 16) - 2052);
    v12[j - 1] = (unsigned __int8)(v5 - 127 * ((v6 >> 15) + (v6 >> 6)) - 4 + 127) % 0x7Fu;
  }
  ProcAddressFNV_1a(v12);                       // user32.dll
  v11 = 0;
  v12[0] = 12;
  qmemcpy(&v12[1], "K{K|K KWK.K@K\tKyKhKhKKK", 23);
  for ( k = 1LL; k != 25; ++k )
    v12[k - 1] = (unsigned __int8)(7 * v12[k - 1]
                                 - 127
                                 * (((unsigned __int16)(7 * (unsigned __int8)v12[k - 1]
                                                      + ((unsigned int)(-32509
                                                                      * (__int16)(7 * (unsigned __int8)v12[k - 1] - 525)) >> 16)
                                                      - 525) >> 15)
                                  + ((unsigned __int16)(7 * (unsigned __int8)v12[k - 1]
                                                      + ((unsigned int)(-32509
                                                                      * (__int16)(7 * (unsigned __int8)v12[k - 1] - 525)) >> 16)
                                                      - 525) >> 6))
                                 - 13
                                 + 127)
               % 0x7Fu;
  ProcAddressFNV_1a(v12);                       // crypt32.dll
  v11 = 0;
  v12[0] = 17;
  v12[1] = 70;
  v12[2] = 8;
  v12[3] = 70;
  v12[4] = 7;
  qmemcpy(&v12[5], "FrF\\F+F.F'F\vF\bF@F@FFF", 21);
  for ( m = 1LL; m != 27; ++m )
  {
    v9 = 18 * (unsigned __int8)v12[m - 1];
    v12[m - 1] = (unsigned __int8)(((unsigned __int16)((unsigned int)(33027 * (__int16)(1260 - v9)) >> 16) >> 15)
                                 + ((unsigned __int16)((unsigned int)(33027 * (__int16)(1260 - v9)) >> 16) >> 6)
                                 - (v9
                                  + ((((unsigned __int16)((unsigned int)(33027 * (__int16)(1260 - v9)) >> 16) >> 15)
                                    + (unsigned __int8)((unsigned __int16)((unsigned int)(33027 * (__int16)(1260 - v9)) >> 16) >> 6)) << 7))
                                 - 20
                                 + 127)
               % 0x7Fu;
  }
  ProcAddressFNV_1a(v12);                       // Advapi32.dll
  return 0LL;
}
```
tuy hàm `sub_7FF6D58D11F0` bị obfuscate khá phức tạp nhưng ta có thể biết được hàm này làm gì bằng cách debug.  
suy ra hàm này load các thư viện : `ntdll.dll`, `user32.dll`, `crypt32.dll` và `Advapi32.dll`.  
![image](https://github.com/user-attachments/assets/d16fe3b9-2f33-4780-b7f3-8bb870d6dda3)  
chương trình đăng ký hàm `sub_7FF6D58D11A0` với `AddVectoredExceptionHandle` với mức ưu tiên cao nhất `1`.  
khi ta gặp exception, chương trình sẽ chuyển hướng sang `sub_7FF6D58D11A0`, ở đây là exception chia cho 0:  
![image](https://github.com/user-attachments/assets/a3c6005f-ee64-46fe-86a4-c79cf9e54001)  
ta nhảy vào hàm `sub_7FF6D58D11A0`:  
![image](https://github.com/user-attachments/assets/d6fcaca4-7003-48df-80f3-bfc232ab368f)  
chức năng chính của hàm này là tăng EIP lên 4.  
chương trình sẽ nhảy vào:  
![image](https://github.com/user-attachments/assets/594797b1-a8d9-4ef5-a46b-d4b662026a5d)  
ta nhận thấy exception div 0 xuất hiện rất nhiều trong chương trình (26 lần), khiến cho IDA không thể phân tích mã giả:  
![image](https://github.com/user-attachments/assets/e9f90485-7720-4434-826e-4654b71295e1)  
nên ta sẽ patch nop đi sao cho tương ứng với `EIP+=4`  








