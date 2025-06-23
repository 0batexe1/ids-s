Proje Hakkında

Bu Python script'i, hedef web uygulamaları üzerinde kapsamlı bir bilgi toplama (reconnaissance) ve zafiyet keşfi yapmak için tasarlanmıştır. Belirlenmiş potansiyel yolları (path) tarayarak, HTTP başlıklarında, robots.txt dosyasında ve dizin listelemelerinde olası bilgi sızdırmalarını otomatik olarak kontrol eder. Amacı, sızma testleri ve hata ödülü (bug bounty) avcıları için ilk keşif aşamasını otomatikleştirmek ve görünürdeki zafiyetleri veya hassas bilgileri hızlıca ortaya çıkarmaktır.
Amaç ve Hedef Kitle

Bu projenin temel amacı, bir web uygulamasının genel güvenlik duruşunu anlamak için kritik ilk adımları atmaktır. Özellikle şu kitlelere hitap eder:

    Güvenlik Araştırmacıları: Yeni hedefler üzerinde hızlı bir ilk değerlendirme yapmak ve potansiyel zafiyet alanlarını belirlemek için.
    Sızma Testleri Uzmanları: Kapsamlı bir test sürecinin başlangıcında bilgi toplama aşamasını kolaylaştırmak için.
    Bug Bounty Avcıları: Uygulamaların açıkta bıraktığı hassas bilgileri veya varsayılan yapılandırma zafiyetlerini (misconfigurations) tespit etmek için.
    Geliştiriciler: Kendi uygulamalarının dağıtım sonrası maruz kalabileceği bilgi sızdırma risklerini kontrol etmek için.

Özellikler

    Path Taraması: Web sunucularında yaygın olarak bulunan veya hassas bilgi içerebilecek potansiyel dizinleri ve dosyaları (örn. /admin/, /robots.txt, .env) proaktif olarak tarar.
    HTTP Başlık Kontrolü: Sunucu ve uygulama versiyon bilgisi gibi açıklayıcı HTTP başlıklarını tespit ederek bilgi sızdırma (information disclosure) zafiyetlerini kontrol eder.
    robots.txt Analizi: Uygulamanın robots.txt dosyasını çekerek, arama motorlarının dizine eklemesini istemediği (fakat yine de erişilebilir olabilecek) yolları (Disallow direktifleri) otomatik olarak tarama listesine ekler.
    Dizin Listeleme Kontrolü: Belirtilen yollarda dizin listeleme (directory listing) zafiyetinin olup olmadığını kontrol eder. Bu durum, sunucunun hassas dosya ve dizin yapılarını açığa çıkarmasına neden olabilir.
    Yanıt İçeriği Bilgi Sızdırma: HTTP yanıtlarının içeriğinde "password", "secret", "key" gibi hassas anahtar kelimeleri arayarak bilgi sızdırma zafiyetlerini tespit etmeye çalışır.
    Renkli Çıktı: Kullanıcıya daha iyi bir görsel geri bildirim sağlamak ve bulguları vurgulamak için colorama kütüphanesi ile renkli terminal çıktıları sunar.

Gereklilikler

Bu aracı kullanmak için sisteminizde aşağıdaki yazılımların kurulu olması gerekir:

    Python 3.x: Script Python 3 ile uyumludur.
    requests kütüphanesi: HTTP istekleri yapmak için. pip install requests komutu ile kurulabilir.
    colorama kütüphanesi: Terminal çıktılarını renklendirmek için. pip install colorama komutu ile kurulabilir.
    BeautifulSoup4 kütüphanesi: HTML içeriğini ayrıştırmak ve dizin listelemesi kontrolü yapmak için. pip install beautifulsoup4 komutu ile kurulabilir.

Kurulum ve Kullanım

    Gerekli Kütüphaneleri Kurun:
    Script'i çalıştırmadan önce, Python ortamınızda gerekli kütüphanelerin kurulu olduğundan emin olun:
    Bash

pip install requests colorama beautifulsoup4

Script'i İndirin:
Bu projenin GitHub deposundan recon_scanner.py (veya script'inizin adı ne ise) dosyasını indirin veya kopyalayın.

Script'i Çalıştırın:
Terminalinizde script'in bulunduğu dizine gidin ve aşağıdaki komutu çalıştırın. Script sizden hedef domaini isteyecektir.
Bash

    python recon_scanner.py

    İstendiğinde hedef domaini girin:

    Tarama yapmak istediğiniz domaini girin (ör: https://example.com): https://target.com

Bulguları Değerlendirme

Tarama tamamlandığında, terminalde potansiyel bilgi sızdırma zafiyetlerini ve diğer bulguları renkli olarak göreceksiniz.

    [!] Information Disclosure Detected in Headers: mesajı, sunucu veya uygulama hakkında detaylı bilgilerin HTTP başlıkları aracılığıyla sızdırıldığını gösterir. Bu bilgiler, saldırganlar için zafiyet avı sırasında değerli ipuçları sağlayabilir.
    [!] Dizin Listeleme Açık: mesajı, sunucunun bir dizindeki tüm dosya ve alt dizinleri listelediğini belirtir. Bu durum, hassas dosyalara veya uygulama yapısına dair bilgilere yetkisiz erişime yol açabilir.
    [!] Information Disclosure Detected in Response: mesajı, sayfa içeriğinde hassas anahtar kelimelerin bulunduğunu gösterir. Bu, yanlış yapılandırılmış bir hata sayfası, debug modu veya yanlışlıkla herkese açık bırakılan bir yapılandırma dosyası olabilir.

Önemli Not: Bu tarayıcı bir otomatik araç olup, sonuçlar hatalı pozitifler (false positives) içerebilir. Tespit edilen her bulguyu manuel olarak doğrulamanız ve potansiyel etkisini teyit etmeniz kritik öneme sahiptir. Örneğin, bir "password" kelimesi bir blog yazısında da geçebilir; önemli olan, bu kelimenin hassas bir bağlamda (örn. yapılandırma dosyası, hata mesajı) ortaya çıkmasıdır.
Önemli Etik Not

Bu araç, web uygulamalarındaki güvenlik zafiyetlerini tespit etmek için tasarlanmıştır. Bu tür araçların yalnızca yasal ve etik sınırlar içinde kullanılması büyük önem taşımaktadır. Hedef sistemler üzerinde test yapmadan önce kesinlikle sahibinden yazılı izin almalısınız. İzinsiz tarama veya sömürü girişimleri yasa dışıdır ve ciddi hukuki sonuçları olabilir. Bu aracın kötüye kullanımıyla ilgili herhangi bir sorumluluk kabul edilmez.
Geliştirme Önerileri

Bu script, bilgi toplama ve keşif konusunda güçlü bir başlangıç noktası sunar. Gelecekteki geliştirmeler için bazı fikirler:

    Daha Kapsamlı Path Listeleri: Farklı teknolojilere (örneğin Java, Node.js, spesifik CMS'ler) özel daha geniş ve hedefli path listeleri entegre edin. SecLists gibi kaynaklar çok faydalıdır.
    Subdomain Entegrasyonu: Mevcut alt alan adı tarayıcınızla entegre ederek, keşfedilen her alt alan adı üzerinde bu taramayı çalıştırın.
    JavaScript Analizi: JavaScript dosyalarını ayrıştırarak API anahtarları, gizli endpoint'ler veya diğer hassas bilgileri tespit etmeye çalışın.
    Hata Sayfası Analizi: Farklı HTTP hata kodlarını (örn. 401, 403, 500) tetikleyerek, sunucunun varsayılan hata sayfalarında bilgi sızdırması olup olmadığını kontrol edin.
    Versiyon Tespiti: Başlıklardan veya sayfa içeriğinden tespit edilen sunucu/uygulama versiyonlarına göre bilinen zafiyetleri (CVE'ler) kontrol eden bir modül ekleyin.
    Rate Limiting ve Gecikme: Hedef sunucuya aşırı yüklenmeyi önlemek ve tespit edilmemek için istekler arasına gecikmeler ekleyin.
    Gelişmiş Raporlama: Bulguları daha yapılandırılmış bir şekilde (JSON, HTML) raporlama yeteneği ekleyin.

Katkıda Bulunma

Proje daha fazla geliştirmeye açık! Yeni path'ler eklemek, tespit mantığını iyileştirmek, hata yönetimi geliştirmeleri yapmak veya yeni özellikler önermek isterseniz, geri bildirimleriniz, hata raporlarınız ve katkılarınız her zaman açığız. Bir çekme isteği (pull request) göndermeden önce lütfen mevcut sorunları kontrol edin veya yeni bir sorun açın.
Lisans

Bu proje MIT Lisansı altında yayınlanmıştır. Daha fazla bilgi için 'LICENSE' dosyasına bakın.
İletişim

Sorularınız, önerileriniz veya işbirliği talepleriniz için bana github.com/0batexe1 üzerinden ulaşabilirsiniz.


About The Project

This Python script is designed to perform comprehensive reconnaissance and vulnerability discovery on target web applications. It automatically checks for potential information disclosure in HTTP headers, robots.txt files, and directory listings by scanning a predefined list of common and sensitive paths. Its purpose is to automate the initial discovery phase for penetration testers and bug bounty hunters, quickly revealing visible vulnerabilities or sensitive information.
Purpose and Target Audience

The primary goal of this project is to take critical first steps in understanding a web application's overall security posture. It particularly targets the following audiences:

    Security Researchers: For conducting a rapid initial assessment on new targets and identifying potential areas of vulnerability.
    Penetration Testers: For streamlining the information gathering phase at the start of a comprehensive testing process.
    Bug Bounty Hunters: For detecting sensitive information exposed by applications or identifying default configuration vulnerabilities (misconfigurations).
    Developers: For checking their own applications against information disclosure risks that might arise post-deployment.

Features

    Path Scanning: Proactively scans for common and potentially sensitive directories and files on web servers (e.g., /admin/, /robots.txt, .env).
    HTTP Header Control: Detects descriptive HTTP headers, such as server and application version information, to check for information disclosure vulnerabilities.
    robots.txt Analysis: Fetches the application's robots.txt file and automatically adds paths that search engines are disallowed from indexing (but might still be accessible) to the scanning list.
    Directory Listing Check: Verifies whether directory listing vulnerabilities exist on specified paths. This condition can lead to unauthorized access to sensitive files and directory structures.
    Response Content Information Disclosure: Searches for sensitive keywords like "password," "secret," "key," and "token" within the content of HTTP responses to identify information disclosure vulnerabilities.
    Colored Output: Provides colored terminal output using the colorama library to offer better visual feedback to the user and highlight findings.

Requirements

To use this tool, your system needs to have the following software installed:

    Python 3.x: The script is compatible with Python 3.
    requests library: For making HTTP requests. Install it using pip install requests.
    colorama library: For coloring terminal output. Install it using pip install colorama.
    BeautifulSoup4 library: For parsing HTML content and checking for directory listings. Install it using pip install beautifulsoup4.

Installation and Usage

    Install Required Libraries:
    Before running the script, ensure the necessary libraries are installed in your Python environment:
    Bash

pip install requests colorama beautifulsoup4

Download the Script:
Download or copy the recon_scanner.py file (or whatever your script is named) from this project's GitHub repository.

Run the Script:
Navigate to the directory where the script is located in your terminal and run the following command. The script will ask you for the target domain.
Bash

    python recon_scanner.py

    Enter the target domain when prompted:

    Tarama yapmak istediğiniz domaini girin (ör: https://example.com): https://target.com

Evaluating Findings

Once the scan is complete, you'll see potential information disclosure vulnerabilities and other findings highlighted in color in your terminal.

    The message [!] Information Disclosure Detected in Headers: indicates that detailed information about the server or application is being leaked through HTTP headers. This information can provide valuable clues for attackers during vulnerability hunting.
    The message [!] Dizin Listeleme Açık: (Directory Listing Open) indicates that the server is listing all files and subdirectories within a directory. This can lead to unauthorized access to sensitive files or information about the application's structure.
    The message [!] Information Disclosure Detected in Response: indicates that sensitive keywords were found within the page content. This could be due to a misconfigured error page, a debug mode, or a configuration file accidentally left public.

Important Note: This scanner is an automated tool, and results may contain false positives. It's critical to manually verify each detected finding and confirm its potential impact. For instance, the word "password" might appear in a blog post; what matters is whether this word appears in a sensitive context (e.g., a configuration file, an error message).
Important Ethical Note

This tool is designed to identify security vulnerabilities in web applications. It is of utmost importance that such tools are used strictly within legal and ethical boundaries. You must obtain explicit written permission from the owner before conducting any tests on target systems. Unauthorized scanning or exploitation attempts are illegal and can lead to severe legal consequences. No responsibility is assumed for any misuse of this tool.
Improvement Suggestions

This script provides a strong starting point for information gathering and reconnaissance. Here are some ideas for future enhancements:

    More Comprehensive Path Lists: Integrate broader and more targeted path lists specific to different technologies (e.g., Java, Node.js, specific CMSs). Resources like SecLists are very useful here.
    Subdomain Integration: Integrate with your existing subdomain scanner to run this reconnaissance scan on every discovered subdomain.
    JavaScript Analysis: Parse JavaScript files to identify API keys, hidden endpoints, or other sensitive information.
    Error Page Analysis: Trigger different HTTP error codes (e.g., 401, 403, 500) to check if the server's default error pages leak information.
    Version Detection: Add a module to check for known vulnerabilities (CVEs) based on server/application versions identified from headers or page content.
    Rate Limiting and Delay: Introduce delays between requests to prevent overwhelming the target server and to avoid detection.
    Advanced Reporting: Add the ability to report findings in a more structured format (JSON, HTML).

Contributing

The project is open for further development! If you'd like to add new paths, improve detection logic, enhance error handling, or propose new features, your feedback, bug reports, and contributions are always welcome. Please check for existing issues or open a new one before submitting a pull request.
License

This project is licensed under the MIT License. See the 'LICENSE' file for more details.
Contact

For any questions, suggestions, or collaboration inquiries, feel free to reach out to me via github.com/0batexe1.
