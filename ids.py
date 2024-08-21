import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup # type: ignore
import re
import colorama
from colorama import Fore, Style

# Renklerin düzgün çalışması için colorama başlatılır
colorama.init()

# Potansiyel path'ler listesi
paths = [
    "/", "/robots.txt", "/sitemap.xml", "/admin/", "/login/", "/.git/", "/.env", "/config.php",
    "/backup/", "/test/", "/staging/", "/old/", "/phpinfo.php", "/server-status", "/server-info",
    "/.htaccess", "/.htpasswd", "/wp-admin/", "/wp-login.php", "/wp-config.php", "/debug/",
    "/api/", "/api/v1/", "/uploads/", "/files/", "/data/", "/log/", "/logs/", "/temp/", "/tmp/",
    "/backup.zip", "/backup.tar.gz", "/.gitignore", "/.git/config", "/crossdomain.xml"
]

# HTTP başlıklarını kontrol etme fonksiyonu
def check_http_headers(url):
    try:
        response = requests.head(url)
        # Sonucu özet olarak yazdır
        print(f"[*] Tarama: {url} - HTTP Başlıkları - {response.status_code}")
        # Information Disclosure check
        for header, value in response.headers.items():
            if re.search(r"(X-Powered-By|Server|X-AspNet-Version|X-AspNetMvc-Version)", header, re.IGNORECASE):
                print(Fore.RED + f"    [!] Information Disclosure Detected in Headers: {header}: {value}" + Style.RESET_ALL)
        return response
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"[-] {url} erişilemedi: {e}" + Style.RESET_ALL)

# robots.txt dosyasını kontrol etme fonksiyonu
def check_robots_txt(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            print(f"[*] Tarama: {url} - robots.txt - {response.status_code}")
            # robots.txt içinde bulunan yolları ekler
            disallowed_paths = re.findall(r"Disallow: (.+)", response.text)
            for path in disallowed_paths:
                paths.append(path.strip())
        else:
            print(Fore.RED + f"[-] {url} robots.txt bulunamadı." + Style.RESET_ALL)
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"[-] {url} erişilemedi: {e}" + Style.RESET_ALL)

# Dizin listelemelerini kontrol etme fonksiyonu
def check_directory_listing(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "html.parser")
            if soup.title and ("Index of" in soup.title.string or "directory listing" in response.text.lower()):
                print(Fore.RED + f"    [!] Dizin Listeleme Açık: {url}" + Style.RESET_ALL)
        else:
            print(f"[*] Tarama: {url} - Dizin Listeleme - {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"[-] {url} erişilemedi: {e}" + Style.RESET_ALL)

# Response içeriğinde bilgi sızdırma kontrolü
def check_information_disclosure(url, response):
    sensitive_keywords = ["password", "secret", "key", "token", "admin", "login", "config", "credential"]
    for keyword in sensitive_keywords:
        if re.search(rf"{keyword}", response.text, re.IGNORECASE):
            print(Fore.RED + f"    [!] Information Disclosure Detected in Response: {url} - Keyword: {keyword}" + Style.RESET_ALL)

# Ana tarama fonksiyonu
def scan_domain(domain):
    for path in paths:
        full_url = urljoin(domain, path)
        if path == "/robots.txt":
            check_robots_txt(full_url)
        else:
            response = check_http_headers(full_url)
            check_directory_listing(full_url)
            if response and response.status_code == 200:
                check_information_disclosure(full_url, response)

if __name__ == "__main__":
    # Kullanıcıdan domain girişi alınır
    domain = input("Tarama yapmak istediğiniz domaini girin (ör: https://example.com): ")
    scan_domain(domain)
