import requests
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.alert import Alert
import time

# Đường dẫn tới tệp chứa payloads
file_path = 'xsspayload.txt'

# Đọc payloads từ tệp
with open(file_path, 'r') as file:
    xss_payloads = [line.strip() for line in file.readlines()]

def check_xss(url, dem):
    # Gửi yêu cầu GET tới URL
    response = requests.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')
    
    # Tìm tất cả các thẻ form trên trang
    forms = soup.find_all('form')
    
    if not forms:
        print("Không tìm thấy thẻ form nào trên trang.")
        return
    
    for form in forms:
        action = form.get('action')
        method = form.get('method', 'get').lower()
        
        
        # Xây dựng URL đầy đủ cho form action
        if action:
            form_url = url if action.startswith('/') else url + action
        else:
            form_url = url
        
        # Tìm tất cả các trường đầu vào trong form
        inputs = form.find_all('input')
        data = {}
        
        for input_tag in inputs:
            name = input_tag.get('name')
            input_type = input_tag.get('type', 'text')
            
            if name and (input_type == 'text' or input_type == 'search'):
                data[name] = xss_payloads[dem]  # Sử dụng payload đầu tiên cho kiểm tra
                
        # Gửi yêu cầu với payload
        if method == 'post':
            response = requests.post(form_url, data=data)
        else:
            response = requests.get(form_url, params=data)
        
        # Kiểm tra phản hồi xem payload có xuất hiện không
        if any(payload in response.text for payload in xss_payloads):
            print(f"Payload: {xss_payloads[dem]}")
            print("Kiểm tra xem có bảng thông báo hay không...")
            
            # Khởi tạo trình duyệt với Selenium
            driver = webdriver.Chrome()  # hoặc webdriver.Firefox() nếu dùng Firefox
            driver.get(url)
            
            # Điền dữ liệu vào form và gửi đi
            for input_tag in inputs:
                name = input_tag.get('name')
                if name in data:
                    driver.find_element(By.NAME, name).send_keys(data[name])
            driver.find_element(By.TAG_NAME, 'form').submit()
            
            # Chờ một lúc để form được gửi và bảng thông báo (nếu có) xuất hiện
            time.sleep(2)
            
            try:
                alert = Alert(driver)
                alert_text = alert.text
                alert.accept()
                print(f"Bảng thông báo xuất hiện với nội dung: {alert_text}")
                print(f"Trang {url} có thể dễ bị tấn công XSS.")
            except:
                print("Không có bảng thông báo xuất hiện.")
            
            driver.quit()
            print("---------------------")
            return
        
    print(f"Trang {url} có vẻ an toàn trước các payload XSS thông thường.")

# Ví dụ sử dụng
print("Nhập domain: ", end="")
url = input()
dem = 0
for dem in range(0, len(xss_payloads)):
    check_xss(url, dem)
