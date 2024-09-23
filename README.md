Web Directory and Information Disclosure Scanner

This script scans a target domain for common web directories, HTTP headers, and information disclosures such as sensitive files, directory listings, or exposed configuration details.
Features:

    Path Scanning: Attempts to access a wide variety of common paths like /admin, /login, /backup, etc.
    robots.txt Scanning: Checks for disallowed paths inside the robots.txt file and adds them to the scan list.
    HTTP Header Check: Detects headers that might reveal information like server technology or powered-by details.
    Directory Listing Check: Detects open directory listings that could expose sensitive files.
    Sensitive Information Check: Searches the response content for keywords like password, secret, config, etc.

Requirements:

    Python 3.x
    requests
    beautifulsoup4
    colorama

Installation:

bash

# Clone the repository
git clone https://github.com/yourusername/web-directory-scanner.git
cd web-directory-scanner

# Install required libraries
pip install -r requirements.txt

How to Use:

    Run the script:

bash

python scanner.py

    Enter the target domain, e.g., https://example.com.
    The script will scan the domain and output any findings such as information disclosures or directory listings.

Example Output:

bash

[*] Scanning: https://example.com/admin/ - HTTP Headers - 200
    [!] Information Disclosure Detected in Headers: X-Powered-By: PHP/7.4.3
    [!] Directory Listing Enabled: https://example.com/admin/
[*] Scanning: https://example.com/.git/ - HTTP Headers - 403

Contribution:

Feel free to fork the repository, make improvements, and submit pull requests. All contributions are welcome!



Web Dizin ve Bilgi Sızdırma Tarayıcı

Bu Python betiği, hedef domain üzerinde yaygın web dizinlerini, HTTP başlıklarını ve potansiyel bilgi sızdırmalarını (gizli dosyalar, açık dizin listeleme, yapılandırma bilgileri) tarar.
Özellikler:

    Dizin Taraması: /admin, /login, /backup gibi yaygın yolları erişmeyi dener.
    robots.txt Taraması: robots.txt dosyasındaki yasaklanan yolları tespit eder ve tarama listesine ekler.
    HTTP Başlık Kontrolü: Sunucu teknolojisi veya kullanılan altyapıyı açığa çıkarabilecek başlıkları kontrol eder.
    Dizin Listeleme Kontrolü: Açık dizin listelemelerini tespit eder.
    Hassas Bilgi Kontrolü: Yanıt içeriğinde password, secret, config gibi anahtar kelimeleri arar.

Gereksinimler:

    Python 3.x
    requests
    beautifulsoup4
    colorama

Kurulum:

bash

# Depoyu klonlayın
git clone https://github.com/yourusername/web-directory-scanner.git
cd web-directory-scanner

# Gerekli kütüphaneleri yükleyin
pip install -r requirements.txt

Kullanım:

    Betiği çalıştırın:

bash

python scanner.py

    Hedef domaini girin, örneğin: https://example.com.
    Betik, domain üzerinde tarama yapacak ve bilgi sızıntıları ya da dizin listelemelerini raporlayacaktır.

Örnek Çıktı:

bash

[*] Tarama: https://example.com/admin/ - HTTP Başlıkları - 200
    [!] Bilgi Sızdırma Tespit Edildi: X-Powered-By: PHP/7.4.3
    [!] Dizin Listeleme Açık: https://example.com/admin/
[*] Tarama: https://example.com/.git/ - HTTP Başlıkları - 403

Katkı:

Depoyu forklayabilir, iyileştirmeler yapabilir ve pull request gönderebilirsiniz. Tüm katkılar memnuniyetle karşılanır!
