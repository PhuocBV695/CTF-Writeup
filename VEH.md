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
                __except (loc_AC1FAA(GetExceptionInformation())) {
                    loc_AC1FB4();
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

