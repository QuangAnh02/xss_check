import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import logging
from random import randint

# Cấu hình logging
logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

class XSSChecker:
    def __init__(self, url, payload):
        self.url = url
        self.payload = payload
        self.session = requests.Session()
        
        log.info(f"Checking connection to: {url}")
        try:
            response = self.session.get(url)
            response.raise_for_status()
            self.body = response.text
            log.info(f"Connection established with status code {response.status_code}")
        except requests.RequestException as e:
            log.error(f"Failed to connect to {url}: {str(e)}")
            raise

    def post_method(self):
        bs_obj = BeautifulSoup(self.body, "html.parser")
        forms = bs_obj.find_all("form", method="post")

        for form in forms:
            action = form.get("action", self.url)
            full_url = urljoin(self.url, action)
            log.warning(f"Found form with POST method: {full_url}")
            
            keys = {}
            for input_tag in form.find_all(["input", "textarea"]):
                name = input_tag.get("name")
                if name:
                    value = self.payload if input_tag.get("type") != "submit" else "<Submit Confirm>"
                    keys[name] = value
                    log.info(f"Form key name: {name} value: {value}")
            
            log.info("Sending payload (POST) method...")
            response = self.session.post(full_url, data=keys)
            if self.payload in response.text:
                log.critical(f"Detected XSS (POST) at {response.url}")
                with open("xss.txt", "a") as file:
                    file.write(f"{response.url}\n\n")
                log.critical(f"Post data: {keys}")
            else:
                log.info("Parameter page using (POST) payloads but not 100% yet...")

    def get_method_form(self):
        bs_obj = BeautifulSoup(self.body, "html.parser")
        forms = bs_obj.find_all("form", method="get")

        for form in forms:
            action = form.get("action", self.url)
            full_url = urljoin(self.url, action)
            log.warning(f"Found form with GET method: {full_url}")
            
            keys = {}
            for input_tag in form.find_all(["input", "textarea"]):
                name = input_tag.get("name")
                if name:
                    value = self.payload if input_tag.get("type") != "submit" else "<Submit Confirm>"
                    keys[name] = value
                    log.info(f"Form key name: {name} value: {value}")
            
            log.info("Sending payload (GET) method...")
            response = self.session.get(full_url, params=keys)
            if self.payload in response.text:
                log.critical(f"Detected XSS (GET) at {response.url}")
                with open("xss.txt", "a") as file:
                    file.write(f"{response.url}\n\n")
                log.critical(f"GET data: {keys}")
            else:
                log.info("Parameter page using (GET) payloads but not 100% yet...")

    def get_method(self):
        bs_obj = BeautifulSoup(self.body, "html.parser")
        links = bs_obj.find_all("a", href=True)
        
        for link in links:
            href = link.get("href")
            if not href.startswith(("http://", "https://", "mailto:", "tel:")):
                base_url = urljoin(self.url, href)
                query = urlparse(base_url).query
                if query:
                    log.warning(f"Found link with query: {query}. Maybe a vulnerable XSS point")
                    
                    query_payload = query.replace(query.split("=")[1], self.payload, 1)
                    test_url = base_url.replace(query, query_payload, 1)
                    query_all_payloads = urlencode({key: self.payload for key in parse_qs(query)})
                    query_all_url = base_url.replace(query, query_all_payloads)
                    
                    log.info(f"Query (GET) : {test_url}")
                    log.info(f"Query (GET) : {query_all_url}")

                    try:
                        response = self.session.get(test_url, verify=False)
                        if self.payload in response.text or self.payload in self.session.get(query_all_url).text:
                            log.critical(f"Detected XSS (GET) at {response.url}")
                            with open("xss.txt", "a") as file:
                                file.write(f"{response.url}\n\n")
                        else:
                            log.info("Parameter page using (GET) payloads but not 100% yet...")
                    except requests.RequestException as e:
                        log.error(f"Error during GET request: {str(e)}")
    
    def check_xss(self, method=2):
        if method >= 2:
            self.post_method()
            self.get_method()
            self.get_method_form()
        elif method == 1:
            self.post_method()
        elif method == 0:
            self.get_method()
            self.get_method_form()

def read_payload_from_file(filepath):
    try:
        with open(filepath, 'r') as file:
            return file.read().strip()
    except Exception as e:
        log.error(f"Error reading payload from file: {str(e)}")
        raise

# Example usage:
url = "http://testphp.vulnweb.com/index.php"
payload_filepath = "xsspayload.txt"
payload = read_payload_from_file(payload_filepath)

checker = XSSChecker(url, payload)
checker.check_xss(method=2)
