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

