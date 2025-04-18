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
đoạn code này thực hiện gọi 1 exception là `int 3` và có thể là lấy base address của kernelbase.  
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






