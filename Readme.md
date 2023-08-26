# Awesome Bug Bounty Tools [![Awesome](https://awesome.re/badge.svg)](https://awesome.re)

> Çeşitli bug bounty araçlarının Türkçe açıklamaları ile derlenmiş bir listesi

## Contents

- [Recon](#Recon)
    - [Subdomain Enumeration](#Subdomain-Enumeration)
    - [Port Scanning](#Port-Scanning)
    - [Screenshots](#Screenshots)
    - [Technologies](#Technologies)
    - [Content Discovery](#Content-Discovery)
    - [Links](#Links)
    - [Parameters](#Parameters)
    - [Fuzzing](#Fuzzing)

- [Exploitation](#Exploitation)
    - [Command Injection](#Command-Injection)
    - [CORS Misconfiguration](#CORS-Misconfiguration)
    - [CRLF Injection](#CRLF-Injection)
    - [CSRF Injection](#CSRF-Injection)
    - [Directory Traversal](#Directory-Traversal)
    - [File Inclusion](#File-Inclusion)
    - [GraphQL Injection](#GraphQL-Injection)
    - [Header Injection](#Header-Injection)
    - [Insecure Deserialization](#Insecure-Deserialization)
    - [Insecure Direct Object References](#Insecure-Direct-Object-References)
    - [Open Redirect](#Open-Redirect)
    - [Race Condition](#Race-Condition)
    - [Request Smuggling](#Request-Smuggling)
    - [Server Side Request Forgery](#Server-Side-Request-Forgery)
    - [SQL Injection](#SQL-Injection)
    - [XSS Injection](#XSS-Injection)
    - [XXE Injection](#XXE-Injection)

- [Miscellaneous](#Miscellaneous)
    - [Passwords](#Passwords)
    - [Secrets](#Secrets)
    - [Git](#Git)
    - [Buckets](#Buckets)
    - [CMS](#CMS)
    - [JSON Web Token](#JSON-Web-Token)
    - [postMessage](#postMessage)
    - [Subdomain Takeover](#Subdomain-Takeover)
    - [Uncategorized](#Uncategorized)

---

## Recon

### Subdomain Enumeration

- [Sublist3r](https://github.com/aboul3la/Sublist3r) - Sızma testi yapanlar için hızlı alt alan numaralandırma aracı
- [Amass](https://github.com/OWASP/Amass) - Derinlemesine Saldırı Yüzey Haritalama ve Varlık Keşfi
- [massdns](https://github.com/blechschmidt/massdns) - Toplu aramalar ve keşif (alt alan numaralandırma) için yüksek performanslı bir DNS saplama çözümleyici
- [Findomain](https://github.com/Findomain/Findomain) - En hızlı ve platformlar arası alt alan numaralandırıcı, zamanınızı boşa harcamayın.
- [Sudomy](https://github.com/Screetsec/Sudomy) - Sudomy, alt alanları toplamak ve böcek avı / sızma testi için otomatik keşif (keşif) gerçekleştiren alanları analiz etmek için kullanılan bir alt alan numaralandırma aracıdır.
- [chaos-client](https://github.com/projectdiscovery/chaos-client) - Chaos DNS API ile iletişim kurmak için istemciye gidin.
- [domained](https://github.com/TypeError/domained) - Çok Araçlı Alt Alan Numaralandırma
- [bugcrowd-levelup-subdomain-enumeration](https://github.com/appsecco/bugcrowd-levelup-subdomain-enumeration) - Bu depo, Bugcrowd LevelUp 2017 sanal konferansında verilen "Ezoterik alt alan numaralandırma teknikleri" konuşmasındaki tüm materyalleri içerir.
- [shuffledns](https://github.com/projectdiscovery/shuffledns) - shuffleDNS, aktif bruteforce kullanarak geçerli alt alan adlarını sıralamanıza ve alt alan adlarını joker karakter işleme ve kolay girdi-çıktı ile çözümlemenize izin veren, go'da yazılmış bir massdns sarmalayıcısıdır…
- [censys-subdomain-finder](https://github.com/christophetd/censys-subdomain-finder) - Censys'ten alınan sertifika şeffaflık günlüklerini kullanarak alt alan numaralandırması gerçekleştirin.
- [Turbolist3r](https://github.com/fleetcaptain/Turbolist3r) - Keşfedilen alanlar için analiz özelliklerine sahip alt alan numaralandırma aracı
- [censys-enumeration](https://github.com/0xbharath/censys-enumeration) - Censys'te SSL/TLS sertifika veri kümesini kullanarak belirli bir alan için alt alan adlarını/e-postaları ayıklamak için bir komut dosyası
- [tugarecon](https://github.com/LordNeoStark/tugarecon) - Sızma testi yapanlar için hızlı alt alan numaralandırma aracı.
- [as3nt](https://github.com/cinerieus/as3nt) - Başka bir Alt Alan Numaralandırma Aracı
- [Subra](https://github.com/si9int/Subra) - Alt alan numaralandırması için bir Web-UI (alt bulucu)
- [Substr3am](https://github.com/nexxai/Substr3am) - Düzenlenen SSL sertifikalarını izleyerek ilginç hedeflerin pasif keşfi/sayımı
- [domain](https://github.com/jhaddix/domain/) - enumall.py Regon-ng için kurulum betiği
- [altdns](https://github.com/infosec-au/altdns) - Alt alanların permütasyonlarını, değişikliklerini ve mutasyonlarını oluşturur ve ardından bunları çözer
- [brutesubs](https://github.com/anshumanbh/brutesubs) - Docker Compose aracılığıyla kendi kelime listelerinizi kullanarak birden çok açık kaynaklı alt alan kaba zorlama aracını (paralel olarak) çalıştırmak için bir otomasyon çerçevesi
- [dns-parallel-prober](https://github.com/lorenzog/dns-parallel-prober) - Bu, belirli bir alan adının olabildiğince çok sayıda alt alanını olabildiğince hızlı bulmak için paralelleştirilmiş bir alan adı araştırıcısıdır.
- [dnscan](https://github.com/rbsec/dnscan) - dnscan, python kelime listesi tabanlı bir DNS alt alan adı tarayıcısıdır.
- [knock](https://github.com/guelfoweb/knock) - Knockpy, bir hedef alandaki alt alanları bir kelime listesi aracılığıyla numaralandırmak için tasarlanmış bir python aracıdır.
- [hakrevdns](https://github.com/hakluke/hakrevdns) - Toplu olarak ters DNS aramaları yapmak için küçük, hızlı araç.
- [dnsx](https://github.com/projectdiscovery/dnsx) - Dnsx, kullanıcı tarafından sağlanan çözümleyiciler listesiyle seçtiğiniz birden çok DNS sorgusunu çalıştırmanıza izin veren hızlı ve çok amaçlı bir DNS araç takımıdır.
- [subfinder](https://github.com/projectdiscovery/subfinder) - Alt Bulucu, web siteleri için geçerli alt alan adlarını keşfeden bir alt alan keşif aracıdır.
- [assetfinder](https://github.com/tomnomnom/assetfinder) - Belirli bir alanla ilgili alanları ve alt alanları bulun
- [crtndstry](https://github.com/nahamsec/crtndstry) - Yine başka bir alt alan bulucu
- [VHostScan](https://github.com/codingo/VHostScan) - Geriye doğru arama yapan bir sanal ana bilgisayar tarayıcısı
- [scilla](https://github.com/edoardottt/scilla) - Bilgi Toplama aracı - DNS / Alt alanlar / Bağlantı Noktaları / Dizinler numaralandırması
- [sub3suite](https://github.com/3nock/sub3suite) - Alt alan numaralandırma, istihbarat toplama ve saldırı yüzeyi haritalama için araştırma düzeyinde bir araç paketi.
- [cero](https://github.com/glebarez/cero) - Keyfi ana bilgisayarların SSL sertifikalarından alan adlarını kazıyın
### Port Scanning

- [masscan](https://github.com/robertdavidgraham/masscan) - TCP port scanner, spews SYN packets asynchronously, scanning entire Internet in under 5 minutes.
- [RustScan](https://github.com/RustScan/RustScan) - The Modern Port Scanner
- [naabu](https://github.com/projectdiscovery/naabu) - A fast port scanner written in go with focus on reliability and simplicity.
- [nmap](https://github.com/nmap/nmap) - Nmap - the Network Mapper. Github mirror of official SVN repository.
- [sandmap](https://github.com/trimstray/sandmap) - Nmap on steroids. Simple CLI with the ability to run pure Nmap engine, 31 modules with 459 scan profiles.
- [ScanCannon](https://github.com/johnnyxmas/ScanCannon) - Combines the speed of masscan with the reliability and detailed enumeration of nmap

### Screenshots

- [EyeWitness](https://github.com/FortyNorthSecurity/EyeWitness) - EyeWitness, web sitelerinin ekran görüntülerini almak, bazı sunucu başlık bilgileri sağlamak ve mümkünse varsayılan kimlik bilgilerini belirlemek için tasarlanmıştır.
- [aquatone](https://github.com/michenriksen/aquatone) - Aquatone, çok sayıda ana bilgisayarda web sitelerinin görsel olarak incelenmesine yönelik bir araçtır ve HTTP tabanlı saldırı yüzeyine hızlı bir şekilde genel bakış elde etmek için uygundur.
- [screenshoteer](https://github.com/vladocar/screenshoteer) - Komut satırından web sitesi ekran görüntüleri ve mobil emülasyonlar oluşturun.
- [gowitness](https://github.com/sensepost/gowitness) - gowitness - Chrome Headless kullanan bir golang, web ekran görüntüsü yardımcı programı
- [WitnessMe](https://github.com/byt3bl33d3r/WitnessMe) - Web Envanteri aracı, Pyppeteer (headless Chrome/Chromium) kullanarak web sayfalarının ekran görüntülerini alır ve hayatı kolaylaştırmak için bazı ekstra özellikler sağlar.
- [eyeballer](https://github.com/BishopFox/eyeballer) - Pentest ekran görüntülerini analiz etmek için evrişimli sinir ağı
- [scrying](https://github.com/nccgroup/scrying) - RDP, web ve VNC ekran görüntülerini tek bir yerde toplamak için bir araç
- [Depix](https://github.com/beurtschipper/Depix) - Parolaları pikselleştirilmiş ekran görüntülerinden kurtarır
- [httpscreenshot](https://github.com/breenmachine/httpscreenshot/) - HTTPScreenshot, çok sayıda web sitesinin ekran görüntülerini ve HTML'sini almak için kullanılan bir araçtır.

### Technologies

- [wappalyzer](https://github.com/AliasIO/wappalyzer) - Web sitelerindeki teknolojiyi tanımlayın.
- [webanalyze](https://github.com/rverton/webanalyze) - Toplu taramayı otomatikleştirmek için Wappalyzer Limanı (web sitelerinde kullanılan teknolojileri ortaya çıkarır)
- [python-builtwith](https://github.com/claymation/python-builtwith) - BuildWith API istemcisi
- [whatweb](https://github.com/urbanadventurer/whatweb) - Yeni nesil web tarayıcı
- [retire.js](https://github.com/RetireJS/retire.js) - bilinen güvenlik açıklarına sahip JavaScript kitaplıklarının kullanımını algılayan tarayıcı
- [httpx](https://github.com/projectdiscovery/httpx) - httpx hızlı ve çok amaçlı bir HTTP araç takımıdır, retryablehttp kitaplığını kullanarak birden çok prob çalıştırılmasına izin verir, artan iş parçacığı ile sonuç güvenilirliğini korumak için tasarlanmıştır.
- [fingerprintx](https://github.com/praetorian-inc/fingerprintx) - parmak izix, diğer popüler bug bounty komut satırı araçlarıyla iyi çalışan, açık bağlantı noktalarında hizmet keşfi için bağımsız bir yardımcı programdır.

### Content Discovery

- [gobuster](https://github.com/OJ/gobuster) - Go'da yazılmış Dizin/Dosya, DNS ve VHost bozma aracı
- [recursebuster](https://github.com/C-Sto/recursebuster) - web sunucularını yinelemeli olarak sorgulamak için hızlı içerik keşif aracı, sızma testi ve web uygulaması değerlendirmelerinde kullanışlıdır
- [feroxbuster](https://github.com/epi052/feroxbuster) - Rust'ta yazılmış hızlı, basit, özyinelemeli bir içerik keşif aracı.
- [dirsearch](https://github.com/maurosoria/dirsearch) - Web yolu tarayıcı
- [dirsearch](https://github.com/evilsocket/dirsearch) - dirsearch'ın Go uygulaması.
- [filebuster](https://github.com/henshin/filebuster) - Son derece hızlı ve esnek bir web fuzzer
- [dirstalk](https://github.com/stefanoj3/dirstalk) - Dirbuster/dirb'e modern alternatif
- [dirbuster-ng](https://github.com/digination/dirbuster-ng) - dirbuster-ng, Java dirbuster aracının C CLI uygulamasıdır
- [gospider](https://github.com/jaeles-project/gospider) - Gospider - Go ile yazılmış hızlı web örümceği
- [hakrawler](https://github.com/hakluke/hakrawler) - Bir web uygulamasında uç noktaların ve varlıkların kolay ve hızlı bir şekilde keşfedilmesi için tasarlanmış basit, hızlı web gezgini
- [crawley](https://github.com/s0rg/crawley) - Golang'da yazılmış hızlı, zengin özelliklere sahip unix-way web kazıyıcı/gezgin.
  
### Links

- [LinkFinder](https://github.com/GerbenJavado/LinkFinder) - JavaScript dosyalarında uç noktaları bulan bir python betiği
- [JS-Scan](https://github.com/zseano/JS-Scan) - php'de yerleşik bir .js tarayıcı. url'leri ve diğer bilgileri kazımak için tasarlanmıştır
- [LinksDumper](https://github.com/arbazkiraak/LinksDumper) - Extract (links/possible endpoints) from responses & filter them via decoding/sorting
- [GoLinkFinder](https://github.com/0xsha/GoLinkFinder) - Hızlı ve minimal bir JS uç nokta çıkarıcı
- [BurpJSLinkFinder](https://github.com/InitRoot/BurpJSLinkFinder) - Uç nokta bağlantıları için pasif tarama JS dosyaları için Burp Uzantısı.
- [urlgrab](https://github.com/IAmStoxe/urlgrab) -Ek bağlantılar arayan bir web sitesinde gezinmek için bir golang yardımcı programı.
- [waybackurls](https://github.com/tomnomnom/waybackurls) - Wayback Machine'in bir etki alanı için bildiği tüm URL'leri getirin
- [gau](https://github.com/lc/gau) - AlienVault'un Open Threat Exchange, Wayback Machine ve Common Crawl'dan bilinen URL'leri alın.
- [getJS](https://github.com/003random/getJS) -  Tüm javascript kaynaklarını/dosyalarını hızlı bir şekilde almak için bir araç
- [linx](https://github.com/riza/linx) - JavaScript dosyalarındaki görünmez bağlantıları ortaya çıkarır

### Parametreler

- [parameth](https://github.com/maK-/parameth) - Bu araç, GET ve POST parametrelerini brute force yöntemiyle keşfetmek için kullanılabilir.
- [param-miner](https://github.com/PortSwigger/param-miner) - Bu eklenti gizli, bağlantısız parametreleri tanımlar. Özellikle web önbellek zehirleme zafiyetlerini bulmak için kullanışlıdır.
- [ParamPamPam](https://github.com/Bo0oM/ParamPamPam) - Bu araç, GET ve POST parametrelerini brute force yöntemiyle keşfetmek için kullanılır.
- [Arjun](https://github.com/s0md3v/Arjun) - HTTP parametre keşif paketi.
- [ParamSpider](https://github.com/devanshbatham/ParamSpider) - Web Arşivlerinin karanlık köşelerinden parametreleri çıkarmak için kullanılır.
- [x8](https://github.com/Sh1Yo/x8) - Rust diliyle yazılmış gizli parametre keşif paketi.

### Fuzzing

- [wfuzz](https://github.com/xmendez/wfuzz) - Web uygulama fuzzlayıcı
- [ffuf](https://github.com/ffuf/ffuf) - Go diliyle yazılmış hızlı web fuzzlayıcı
- [fuzzdb](https://github.com/fuzzdb-project/fuzzdb) - Siyah kutu uygulama hata enjeksiyonu ve kaynak keşfi için saldırı kalıpları ve temel veriler sözlüğü.
- [IntruderPayloads](https://github.com/1N3/IntruderPayloads) - Bir koleksiyon Burpsuite Intruder yükleri, BurpBounty yükleri, fuzz listeleri, zararlı dosya yüklemeleri ve web penetrasyon testi metodolojileri ve kontrol listeleri.
- [fuzz.txt](https://github.com/Bo0oM/fuzz.txt) - Potansiyel olarak tehlikeli dosyalar
- [fuzzilli](https://github.com/googleprojectzero/fuzzilli) - Bir JavaScript Motor Fuzzlayıcı
- [fuzzapi](https://github.com/Fuzzapi/fuzzapi) - Fuzzapi, REST API penetrasyon testi için kullanılan ve API_Fuzzer gem'i kullanan bir araç
- [qsfuzz](https://github.com/ameenmaali/qsfuzz) - qsfuzz (Sorgu Dizisi Fuzzlayıcı), sorgu dizilerini fuzzlamak ve kolayca zafiyetleri tespit etmek için kendi kurallarınızı oluşturmanıza olanak tanır.
- [vaf](https://github.com/d4rckh/vaf) - Nim diliyle yazılmış çok gelişmiş (web) fuzzlayıcı.

---

## Exploitation



### Command Injection

- [commix](https://github.com/commixproject/commix) - Otomatikleştirilmiş Hepsi Bir Arada İşletim Sistemi komut enjeksiyonu ve istismar aracı.

### CORS Misconfiguration

- [Corsy](https://github.com/s0md3v/Corsy) - CORS Yanlış Yapılandırma Tarayıcı
- [CORStest](https://github.com/RUB-NDS/CORStest) - Basit Bir CORS Yanlış Yapılandırma Tarayıcı
- [cors-scanner](https://github.com/laconicwolf/cors-scanner) - Çoklu iş parçacıklı bir tarayıcı, CORS hatalarını/yapılandırmalarını tespit etmeye yardımcı olur
- [CorsMe](https://github.com/Shivangx01b/CorsMe) - Kökenler Arası Kaynak Paylaşımı Yanlış Yapılandırma Tarayıcı


### CRLF Injection

- [CRLFsuite](https://github.com/Nefcore/CRLFsuite) - Özellikle CRLF enjeksiyonunu tarayarak hızlı bir şekilde tasarlanmış bir araç
- [crlfuzz](https://github.com/dwisiswant0/crlfuzz) - Go diliyle yazılmış, CRLF zafiyetini hızlı bir şekilde taramak için kullanılan bir araç
- [CRLF-Injection-Scanner](https://github.com/MichaelStott/CRLF-Injection-Scanner) - Bir liste içindeki alan adlarında CRLF enjeksiyonunu test etmek için komut satırı aracı.
- [Injectus](https://github.com/BountyStrike/Injectus) - CRLF ve açık yönlendirme (open redirect) fuzzlayıcı


### CSRF Injection

- [XSRFProbe](https://github.com/0xInfection/XSRFProbe) - Prime Cross Site Request Forgery (CSRF) Denetim ve Sömürü Aracı.

### Directory Traversal

- [dotdotpwn](https://github.com/wireghoul/dotdotpwn) - DotDotPwn - Dizin Gezintisi Fuzzeri
- [FDsploit](https://github.com/chrispetrou/FDsploit) - Dosya Dahil Etme ve Dizin Gezintisi fuzzlama, sıralama ve istismar aracı.
- [off-by-slash](https://github.com/bayotop/off-by-slash) - NGINX yanlış yapılandırma yoluyla takma ad gezinmesini ölçeklendirmek için Burp uzantısı.
- [liffier](https://github.com/momenbasel/liffier) - Olası yolu kesmek için el ile dot-dot-slash eklemekten sıkıldınız mı? Bu kısa kod parçası URL'de ../'yi artırır.


### File Inclusion

- [liffy](https://github.com/mzfr/liffy) - Yerel dosya dahil etme istismarı aracı
- [Burp-LFI-tests](https://github.com/Team-Firebugs/Burp-LFI-tests) - Burpsuite kullanarak LFI için Fuzzing işlemi
- [LFI-Enum](https://github.com/mthbernardes/LFI-Enum) - Numaralandırmayı LFI kullanarak yürüten betikler
- [LFISuite](https://github.com/D35m0nd142/LFISuite) - Tamamen Otomatik LFI Sömürücüsü (+ Ters Kabuk) ve Tarayıcı
- [LFI-files](https://github.com/hussein98d/LFI-files) - LFI için brute force saldırısı yapmak için kelime listesi


### GraphQL Injection

- [inql](https://github.com/doyensec/inql) - InQL - GraphQL Güvenlik Testi için Bir Burp Eklentisi
- [GraphQLmap](https://github.com/swisskyrepo/GraphQLmap) - GraphQLmap, pentest amaçları için bir graphql uç noktası ile etkileşimde bulunmak için bir komut dosyası motorudur.
- [shapeshifter](https://github.com/szski/shapeshifter) - GraphQL güvenlik test aracı
- [graphql_beautifier](https://github.com/zidekmat/graphql_beautifier) - GraphQL isteğini daha okunabilir hale getirmeye yardımcı olmak için Burp Suite uzantısı
- [clairvoyance](https://github.com/nikitastupin/clairvoyance) - Devre dışı bırakılmış introspeksiyona rağmen GraphQL API şemasını elde etmek!


### Header Injection

- [headi](https://github.com/mlcsec/headi) - Özelleştirilebilir ve otomatik HTTP başlık enjeksiyonu.


### Insecure Deserialization

- [ysoserial](https://github.com/frohoff/ysoserial) - Güvensiz Java nesne deserializasyonunu istismar eden yükler üreten bir konsept kanıt aracı.
- [GadgetProbe](https://github.com/BishopFox/GadgetProbe) - Uzak Java sınıf yollarındaki sınıfları, kütüphaneleri ve kütüphane sürümlerini belirlemek için Java serileştirilmiş nesneleri tüketen uç noktaları sorgulayan bir araç.
- [ysoserial.net](https://github.com/pwntester/ysoserial.net) - Çeşitli .NET biçimleyiciler için deserializasyon yükü üretici bir araç
- [phpggc](https://github.com/ambionics/phpggc) - PHPGGC, unserialize() işlevi için PHP yükleri kütüphanesi ve bunları komut satırından veya programlı olarak üreten bir araç.


### Insecure Direct Object References

- [Autorize](https://github.com/Quitten/Autorize) - Barak Tawily tarafından geliştirilen, Burp Suite için Jython ile yazılmış otomatik yetkilendirme denetimi tespit uzantısı.


### Open Redirect

- [Oralyzer](https://github.com/r0075h3ll/Oralyzer) - Açık Yönlendirme Analiz Aracı
- [Injectus](https://github.com/BountyStrike/Injectus) - CRLF ve açık yönlendirme (open redirect) fuzzlayıcı
- [dom-red](https://github.com/Naategh/dom-red) - Açık yönlendirme zafiyetini kontrol etmek için bir alan adı listesini denetleyen küçük bir betik
- [OpenRedireX](https://github.com/devanshbatham/OpenRedireX) - Açık Yönlendirme sorunları için bir fuzzlayıcı


### Race Condition

- [razzer](https://github.com/compsec-snu/razzer) - Yarış Koşulu Hatalarına Odaklanan Bir Çekirdek Fuzzer
- [racepwn](https://github.com/racepwn/racepwn) - Yarış Koşulu Çerçevesi
- [requests-racer](https://github.com/nccgroup/requests-racer) - Web uygulamalarındaki yarış koşullarını Requests ile kolayca istismar etmeyi sağlayan küçük bir Python kütüphanesi.
- [turbo-intruder](https://github.com/PortSwigger/turbo-intruder) - Turbo Intruder, büyük sayıda HTTP isteği göndermek ve sonuçları analiz etmek için bir Burp Suite uzantısıdır.
- [race-the-web](https://github.com/TheHackerDev/race-the-web) - Web uygulamalarındaki yarış koşulları için testler. Sürekli entegrasyon sürecine entegre etmek için RESTful bir API içerir.

### Request Smuggling

- [http-request-smuggling](https://github.com/anshumanpattnaik/http-request-smuggling) - HTTP İstek Smuggling Tespit Aracı
- [smuggler](https://github.com/defparam/smuggler) - Smuggler - Python 3 ile yazılmış bir HTTP İstek Smuggling / Desync test aracı
- [h2csmuggler](https://github.com/BishopFox/h2csmuggler) - HTTP İstek Smuggling'i HTTP/2 Temiz Metin Üzerinden (h2c) gerçekleştirme
- [tiscripts](https://github.com/defparam/tiscripts) - Bu betikler, CLTE ve TECL tarzı saldırılar için İstek Smuggling Desync yükleri oluşturmak için kullandığım betikler.

### Server Side Request Forgery

- [SSRFmap](https://github.com/swisskyrepo/SSRFmap) - Otomatik SSRF fuzzlayıcı ve istismar aracı
- [Gopherus](https://github.com/tarunkant/Gopherus) - Bu araç, çeşitli sunucularda SSRF istismarı ve RCE kazanmak için gopher bağlantısı üretir
- [ground-control](https://github.com/jobertabma/ground-control) - Web sunucumda çalışan betik koleksiyonu. Temel olarak SSRF, kör XSS ve XXE zafiyetleri için hata ayıklama amacıyla kullanılır.
- [SSRFire](https://github.com/micha3lb3n/SSRFire) - Otomatik bir SSRF bulucu. Sadece alan adınızı ve sunucunuzu verin ve rahatlayın! ;) Ayrıca XSS ve açık yönlendirmeleri bulma seçenekleri de bulunur
- [httprebind](https://github.com/daeken/httprebind) - DNS rebind tabanlı SSRF saldırıları için otomatik bir araç
- [ssrf-sheriff](https://github.com/teknogeek/ssrf-sheriff) - Go ile yazılmış basit bir SSRF test şerifi
- [B-XSSRF](https://github.com/SpiderMate/B-XSSRF) - Kör XSS, XXE ve SSRF'yi tespit etmek ve izlemek için araç takımı
- [extended-ssrf-search](https://github.com/Damian89/extended-ssrf-search) - Parametre brute forcing gibi farklı yöntemler kullanarak akıllı bir ssrf tarayıcısı
- [gaussrf](https://github.com/KathanP19/gaussrf) - Bilinen URL'leri AlienVault's Open Threat Exchange, Wayback Machine ve Common Crawl'dan alır ve OpenRedirection veya SSRF Parametreleri ile URL'leri filtreler.
- [ssrfDetector](https://github.com/JacobReynolds/ssrfDetector) - Sunucu tarafı istek sahteciliği tespit aracı
- [grafana-ssrf](https://github.com/RandomRobbieBF/grafana-ssrf) - Grafana'da kimlik doğrulamalı SSRF
- [sentrySSRF](https://github.com/xawdxawdx/sentrySSRF) - Sentry yapılandırmasını sayfada veya javascript dosyalarında aramak ve kör SSRF kontrol etmek için araç
- [lorsrf](https://github.com/knassar702/lorsrf) - SSRF zafiyeti bulmak için Gizli parametreler üzerinde GET ve POST yöntemlerini kullanarak brute force yapar
- [singularity](https://github.com/nccgroup/singularity) - Bir DNS rebinding saldırı çerçevesi.
- [whonow](https://github.com/brannondorsey/whonow) - Hava'da DNS Rebinding saldırıları gerçekleştirmek için bir "zararlı" DNS sunucusu (rebind.network:53 üzerinde çalışan genel bir örnek mevcut)
- [dns-rebind-toolkit](https://github.com/brannondorsey/dns-rebind-toolkit) - DNS rebind saldırıları oluşturmak için ön yüz JavaScript araç takımı.
- [dref](https://github.com/FSecureLABS/dref) - DNS Rebinding İstismarı Çerçevesi
- [rbndr](https://github.com/taviso/rbndr) - Basit DNS Rebinding Hizmeti
- [httprebind](https://github.com/daeken/httprebind) - DNS rebind tabanlı SSRF saldırıları için otomatik bir araç
- [dnsFookup](https://github.com/makuga01/dnsFookup) - DNS rebind araç takımı


### SQL Injection

- [sqlmap](https://github.com/sqlmapproject/sqlmap) - Otomatik SQL enjeksiyonu ve veritabanı ele geçirme aracı
- [NoSQLMap](https://github.com/codingo/NoSQLMap) - Otomatik NoSQL veritabanı sayısal sıralama ve web uygulama istismarı aracı
- [SQLiScanner](https://github.com/0xbug/SQLiScanner) - Charles ve sqlmap API ile otomatik SQL enjeksiyonu
- [SleuthQL](https://github.com/RhinoSecurityLabs/SleuthQL) - Potansiyel SQL enjeksiyon noktalarını keşfetmek için Python3 Burp Geçmiş analiz aracı. SQLmap ile birlikte kullanılması amaçlanmıştır.
- [mssqlproxy](https://github.com/blackarrowsec/mssqlproxy) - mssqlproxy, soket yeniden kullanımı yoluyla kısıtlanmış ortamlarda yanal hareketi gerçekleştirmek için hedef alınmış bir Microsoft SQL Sunucusu üzerinden çalışan bir araç takımıdır.
- [sqli-hunter](https://github.com/zt2/sqli-hunter) - SQLi-Hunter, SQLi kazmaktan zorlanmadan yapan basit bir HTTP / HTTPS proxy sunucusu ve SQLMAP API sarmalayıcısıdır.
- [waybackSqliScanner](https://github.com/ghostlulzhacks/waybackSqliScanner) - Wayback Machine'den URL'leri toplayarak her GET parametresini SQL enjeksiyonu açısından test eder.
- [ESC](https://github.com/NetSPI/ESC) - Evil SQL Client (ESC), gelişmiş SQL Server keşfi, erişimi ve veri çıkarma özelliklerine sahip etkileşimli bir .NET SQL konsol istemcisidir.
- [mssqli-duet](https://github.com/Keramas/mssqli-duet) - RID brute forcing temelli bir Active Directory ortamından etki edilmiş Microsoft SQL Server üzerinden etkileşimli hareket yapmak için bir SQL enjeksiyon komut dosyası
- [burp-to-sqlmap](https://github.com/Miladkhoshdel/burp-to-sqlmap) - SQLMap kullanarak Burp Suite Toplu İstekler üzerinde SQLInjection testi gerçekleştirme
- [BurpSQLTruncSanner](https://github.com/InitRoot/BurpSQLTruncSanner) - Karmaşık bir BurpSuite eklentisi olan SQL Kesme açıklıkları için.
- [andor](https://github.com/sadicann/andor) - Golang ile yazılmış Kör SQL Enjeksiyon Aracı
- [Blinder](https://github.com/mhaskar/Blinder) - Zaman tabanlı kör SQL enjeksiyonunu otomatikleştiren bir Python kütüphanesi
- [sqliv](https://github.com/the-robot/sqliv) - Büyük çaplı SQL enjeksiyon zafiyet tarama aracı
- [nosqli](https://github.com/Charlie-belmer/nosqli) - MongoDB kullanan zafiyetli web sitelerini bulmak için NoSQL Enjeksiyonu CLI aracı


### XSS Injection

- [XSStrike](https://github.com/s0md3v/XSStrike) - En gelişmiş XSS tarama aracı.
- [xssor2](https://github.com/evilcos/xssor2) - XSS'OR - JavaScript ile hackleme.
- [xsscrapy](https://github.com/DanMcInerney/xsscrapy) - XSS örümceği - 66/66 wavsep XSS tespit edildi
- [sleepy-puppy](https://github.com/Netflix-Skunkworks/sleepy-puppy) - Sleepy Puppy XSS Yük Yönetim Çerçevesi
- [ezXSS](https://github.com/ssl/ezXSS) - ezXSS, zafiyet avcıları ve ödül avcıları için (kör) Çapraz Site Komut Dosyası test etmek için kolay bir yoldur.
- [xsshunter](https://github.com/mandatoryprogrammer/xsshunter) - XSS Hunter hizmeti - XSSHunter.com'un taşınabilir bir sürümü
- [dalfox](https://github.com/hahwul/dalfox) - DalFox(Finder Of XSS) / Parametre Analizi ve golang temelli XSS Tarama aracı
- [xsser](https://github.com/epsylon/xsser) - Cross Site "Scripter" (yani XSSer), web tabanlı uygulamalardaki XSS zafiyetlerini tespit etmek, istismar etmek ve raporlamak için otomatik bir -çerçeve- aracıdır.
- [XSpear](https://github.com/hahwul/XSpear) - Güçlü XSS Tarama ve Parametre analizi aracı ve modülü
- [weaponised-XSS-payloads](https://github.com/hakluke/weaponised-XSS-payloads) - alert(1)'i P1'e dönüştürmek için tasarlanmış XSS yükleri
- [tracy](https://github.com/nccgroup/tracy) - Web uygulamasının tüm çıkışlarını ve kaynaklarını bulmaya yardımcı olması için tasarlanmış bir araç ve sonuçları anlaşılır bir şekilde gösterir.
- [ground-control](https://github.com/jobertabma/ground-control) - Web sunucumda çalışan betik koleksiyonu. Temel olarak SSRF, kör XSS ve XXE zafiyetleri için hata ayıklama amacıyla kullanılır.
- [xssValidator](https://github.com/nVisium/xssValidator) - Bu, otomasyon ve XSS zafiyetlerinin doğrulanması için tasarlanmış bir burp intruder uzantısıdır.
- [JSShell](https://github.com/Den1al/JSShell) - Etkileşimli çok kullanıcılı web JS kabuğu
- [bXSS](https://github.com/LewisArdern/bXSS) - bXSS, hata avcıları ve organizasyonlar tarafından Kör Çapraz Site Komut Dosyası tespiti yapmak için kullanılabilen bir yardımcı programdır.
- [docem](https://github.com/whitel1st/docem) - docx,odt,pptx,etc (OXML_XEE steroids üzerinde) içine XXE ve XSS yüklerini gömmek için araç
- [XSS-Radar](https://github.com/bugbountyforum/XSS-Radar) - XSS Radar, parametreleri tespit eder ve bunları çapraz site komut dosyası açıklıkları için taramaya tabi tutar.
- [BruteXSS](https://github.com/rajeshmajumdar/BruteXSS) - BruteXSS, web uygulamasındaki XSS zafiyetlerini bulmak için yazılmış basit bir python aracıdır.
- [findom-xss](https://github.com/dwisiswant0/findom-xss) - Basit bir DOM tabanlı XSS zafiyet tarayıcısı.
- [domdig](https://github.com/fcavallarin/domdig) - Tek Sayfalı Uygulamalar için DOM XSS tarayıcısı
- [femida](https://github.com/wish-i-was/femida) - Burp Suite için otomatik kör-xss araması
- [B-XSSRF](https://github.com/SpiderMate/B-XSSRF) - Kör XSS, XXE ve SSRF tespiti ve izlemesi için araç takımı
- [domxssscanner](https://github.com/yaph/domxssscanner) - DOMXSS Tarayıcı, DOM tabanlı XSS zafiyetleri için kaynak kodunu taramak için çevrimiçi bir araçtır.
- [xsshunter_client](https://github.com/mandatoryprogrammer/xsshunter_client) - XSSHunter için eşlenmiş enjeksiyon proxy aracı
- [extended-xss-search](https://github.com/Damian89/extended-xss-search) - xssfinder aracımın daha iyi bir versiyonu - bir URL listesinde farklı türde XSS taraması yapar.
- [xssmap](https://github.com/Jewel591/xssmap) - XSSMap, XSS zafiyetlerini tespit etmek için geliştirilmiş Python3 tabanlı bir araçtır.
- [XSSCon](https://github.com/menkrep1337/XSSCon) - XSSCon: Basit bir XSS Tarama aracı
- [BitBlinder](https://github.com/BitTheByte/BitBlinder) - Çapraz Site Komut Dosyası açıklıklarını tespit etmek için her form/istek gönderildiğinde özel çapraz site komut dosyası yükleri enjekte etmek için BurpSuite uzantısı
- [XSSOauthPersistence](https://github.com/dxa4481/XSSOauthPersistence) - XSS ve Oauth ile hesap kalıcılığını sürdürmek
- [shadow-workers](https://github.com/shadow-workers/shadow-workers) - Shadow Workers, XSS ve kötü amaçlı Servis İşçileri (SW) istismarı konusunda sızdırmazlık testçilerine yardımcı olması için tasarlanmış ücretsiz ve açık kaynaklı bir C2 ve proxy'dir
- [rexsser](https://github.com/profmoriarity/rexsser) - Bu, yanıtın içinden anahtar kelimeleri çıkaran ve hedef kapsamında yansıtılan XSS'i test eden bir burp eklentisidir.
- [xss-flare](https://github.com/EgeBalci/xss-flare) - Cloudflare sunucusundaki XSS avcısı.
- [Xss-Sql-Fuzz](https://github.com/jiangsir404/Xss-Sql-Fuzz) - burpsuite eklentisi GP tüm parametrelerini (özel parametreleri filtrelemek) tek tıklamayla xss sql yüklemeleri eklemek için Fuzz yapar
- [vaya-ciego-nen](https://github.com/hipotermia/vaya-ciego-nen) - Kör Çapraz Site Komut Dosyası (XSS) açıklıklarını tespit etme, yönetme ve istismar etme.
- [dom-based-xss-finder](https://github.com/AsaiKen/dom-based-xss-finder) - DOM tabanlı XSS zafiyetlerini bulan Chrome uzantısı
- [XSSTerminal](https://github.com/machinexa2/XSSTerminal) - Etkileşimli yazma kullanarak kendi XSS Yükünüzü geliştirin
- [xss2png](https://github.com/vavkamil/xss2png) - PNG IDAT parçaları XSS yükü üretici
- [XSSwagger](https://github.com/vavkamil/XSSwagger) - Eski sürümleri XSS saldırılarına karşı savunmasız olan basit bir Swagger-ui tarayıcısı


### XXE Injection

- [ground-control](https://github.com/jobertabma/ground-control) - SSRF, kör XSS ve XXE zafiyetlerini hata ayıklama için kullanılan betik koleksiyonu.
- [dtd-finder](https://github.com/GoSecure/dtd-finder) - DTD'leri listeler ve bu yerel DTD'ler kullanılarak XXE yükleri oluşturur.
- [docem](https://github.com/whitel1st/docem) - docx, odt, pptx gibi dosya türlerine XXE ve XSS yükleri gömme aracı (OXML_XEE güçlendirilmiş hali).
- [xxeserv](https://github.com/staaldraad/xxeserv) - XXE yükleri için FTP desteği olan mini bir web sunucusu.
- [xxexploiter](https://github.com/luisfontes19/xxexploiter) - XXE zafiyetlerini istismar etmeye yardımcı olan araç.
- [B-XSSRF](https://github.com/SpiderMate/B-XSSRF) - Kör XSS, XXE ve SSRF tespiti ve izlemesi için araç takımı.

---

## Miscellaneous



### Passwords

- [thc-hydra](https://github.com/vanhauser-thc/thc-hydra) - Hydra, çok sayıda protokolü hedef almak için destek sunan paralel bir giriş kırıcıdır.
- [DefaultCreds-cheat-sheet](https://github.com/ihebski/DefaultCreds-cheat-sheet) - Tüm varsayılan kimlik bilgilerini bir araya getiren bir kaynak; varsayılan şifreli cihazları bulmada Mavi/Kırmızı takımın yardımcı olur.
- [changeme](https://github.com/ztgrace/changeme) - Varsayılan kimlik bilgilerini taramak için bir araç.
- [BruteX](https://github.com/1N3/BruteX) - Hedefte çalışan tüm hizmetleri otomatik olarak kaba kuvvet saldırısı yapmak için kullanılır.
- [patator](https://github.com/lanjelot/patator) - Patator, modüler bir tasarıma ve esnek bir kullanıma sahip çok amaçlı bir kaba kuvvet saldırısı aracıdır.


### Secrets

### Secret Detection

- [git-secrets](https://github.com/awslabs/git-secrets) - Sizi git depolarına gizli bilgi ve kimlik bilgilerini taşımanızı engeller.
- [gitleaks](https://github.com/zricethezav/gitleaks) - Gizli bilgileri regex ve entropi kullanarak tarayan bir git depolarını (veya dosyalarını) tarar.
- [truffleHog](https://github.com/dxa4481/truffleHog) - Yüksek entropili dizeleri ve gizli bilgileri git depolarında arar, taahhüt geçmişine derinlemesine iner.
- [gitGraber](https://github.com/hisxo/gitGraber) - gitGraber: GitHub'ı izler, farklı çevrimiçi hizmetlerde hassas veri arar ve gerçek zamanlı olarak bulur.
- [talisman](https://github.com/thoughtworks/talisman) - Git tarafından sağlanan ön itme kanca noktasına entegre olarak, Talisman çıkış yapmış değişiklik setini yetkisiz gibi görünen şeyler açısından doğrular - örneğin yetkilendirme belirteçleri ve özel anahtarlar.
- [GitGot](https://github.com/BishopFox/GitGot) - Yarı otomatik, geribildirim odaklı bir araç olan GitGot, hassas gizli bilgileri hızlı bir şekilde aramak için GitHub üzerindeki genel veri kalabalıklarını tarar.
- [git-all-secrets](https://github.com/anshumanbh/git-all-secrets) - Çeşitli açık kaynaklı git arama araçlarını kullanarak tüm git gizli bilgilerini yakalamak için bir araç.
- [github-search](https://github.com/gwen001/github-search) - GitHub üzerinde temel arama yapmak için araçlar.
- [git-vuln-finder](https://github.com/cve-search/git-vuln-finder) - Olası yazılım güvenlik açıklarını git taahhüt mesajlarından bulma.
- [commit-stream](https://github.com/x1sec/commit-stream) - Github etkinlik API'sinden taahhüt günlüklerini gerçek zamanlı olarak çıkararak Github depolarını bulmak için bir OSINT aracı.
- [gitrob](https://github.com/michenriksen/gitrob) - GitHub organizasyonları için keşif aracı
- [repo-supervisor](https://github.com/auth0/repo-supervisor) - Kodunuzu güvenlik yanlış yapılandırmaları, parolaları ve gizli bilgileri tarar.
- [GitMiner](https://github.com/UnkL4b/GitMiner) - İleri madencilik için bir araçtır ve GitHub üzerinde içerik madenciliği yapar.
- [shhgit](https://github.com/eth0izzle/shhgit) - Ah shhgit! Gerçek zamanlı olarak GitHub gizli bilgileri bulur.
- [detect-secrets](https://github.com/Yelp/detect-secrets) - Kod içindeki gizli bilgileri algılamanın ve önlemenin işletme dostu bir yoludur.
- [rusty-hog](https://github.com/newrelic/rusty-hog) - Performans için Rust dilinde inşa edilmiş bir dizi gizli tarama aracı. TruffleHog'a dayalıdır.
- [whispers](https://github.com/Skyscanner/whispers) - Sabitlenmiş gizli bilgileri ve tehlikeli davranışları belirleme
- [yar](https://github.com/nielsing/yar) - Örgütleri, kullanıcıları ve/veya depoları yağmalamak için bir araçtır.
- [dufflebag](https://github.com/BishopFox/dufflebag) - Açık EBS hacimlerini gizli bilgiler için tarar
- [secret-bridge](https://github.com/duo-labs/secret-bridge) - Sızan gizli bilgileri izler
- [earlybird](https://github.com/americanexpress/earlybird) - Erken Kuş, kaynak kodu depolarını tarar ve açık metin parola ihlalleri, PII, eski şifreleme yöntemleri, anahtar dosyaları ve daha fazlasını bulma yeteneğine sahip bir hassas veri tespit aracıdır.
- [Trufflehog-Chrome-Extension](https://github.com/trufflesecurity/Trufflehog-Chrome-Extension) - Trufflehog-Chrome-Extension
- [noseyparker](https://github.com/praetorian-inc/noseyparker) - Nosey Parker, metin verilerinde ve Git geçmişinde gizli bilgileri ve hassas bilgileri bulan komut satırı programı.

### Git

- [GitTools](https://github.com/internetwache/GitTools) - Pwn'ing için 3 araç içeren bir depo: .git depoları olan web siteleri
- [gitjacker](https://github.com/liamg/gitjacker) - Yanlış yapılandırılmış web sitelerinden git depolarını sızdırır
- [git-dumper](https://github.com/arthaud/git-dumper) - Bir web sitesinden git deposunu döken bir araç
- [GitHunter](https://github.com/digininja/GitHunter) - İlginç içerik aramak için bir Git deposunu arayan bir araç
- [dvcs-ripper](https://github.com/kost/dvcs-ripper) - Web erişilebilir (dağıtılmış) sürüm kontrol sistemlerini yırtar: SVN/GIT/HG...
- [Gato (Github Attack TOolkit)](https://github.com/praetorian-inc/gato) - GitHub Kendi Barındıran Çalıştırıcı Numaraları ve Saldırı Aracı

### Buckets

- [S3Scanner](https://github.com/sa7mon/S3Scanner) - Açık AWS S3 kovalarını tarar ve içeriğini döker.
- [AWSBucketDump](https://github.com/jordanpotti/AWSBucketDump) - S3 Kovalarında İlginç Dosyaları Aramak İçin Güvenlik Aracı.
- [CloudScraper](https://github.com/jordanpotti/CloudScraper) - BulutScraper: Bulut kaynaklarını aramak için hedefleri sıralama aracı. S3 Kovaları, Azure Blokları, Digital Ocean Depolama Alanı.
- [s3viewer](https://github.com/SharonBrizinov/s3viewer) - Genel olarak açık Amazon AWS S3 Kova Görüntüleyicisi.
- [festin](https://github.com/cr0hn/festin) - FestIn - S3 Kova Zayıflığı Keşfi
- [s3reverse](https://github.com/hahwul/s3reverse) - Farklı S3 kovalarının formatını tek bir formata dönüştürür; hata avı ve güvenlik testleri için kullanılır.
- [mass-s3-bucket-tester](https://github.com/random-robbie/mass-s3-bucket-tester) - Belirli bir listeyi tarayarak S3 kovalarını test eder, dizin listeleme etkin mi veya yüklenebilir mi diye kontrol eder.
- [S3BucketList](https://github.com/AlecBlance/S3BucketList) - Taleplerde bulunan Amazon S3 Kovalarını listeleyen Firefox eklentisi.
- [dirlstr](https://github.com/cybercdh/dirlstr) - Bir URL listesindeki dizin listelerini veya açık S3 kovalarını bulur.
- [Burp-AnonymousCloud](https://github.com/codewatchorg/Burp-AnonymousCloud) - Bulut kovalarını belirlemek ve ardından bunları kamu erişilebilir zafiyetler için test etmek için pasif tarama yapan Burp eklentisi.
- [kicks3](https://github.com/abuvanth/kicks3) - HTML, JS ve kova yapılandırma testi aracılığıyla S3 kovalarını bulma aracı.
- [2tearsinabucket](https://github.com/Revenant40/2tearsinabucket) - Belirli bir hedef için S3 kovalarını sıralar.
- [s3_objects_check](https://github.com/nccgroup/s3_objects_check) - Etkili S3 nesne izinlerinin beyaz kutu değerlendirmesi; kamu erişilebilir dosyaları tanımlamak için kullanılır.
- [s3tk](https://github.com/ankane/s3tk) - Amazon S3 için bir güvenlik araç takımı
- [CloudBrute](https://github.com/0xsha/CloudBrute) - Harika bir bulut numaralandırıcı
- [s3cario](https://github.com/0xspade/s3cario) - Bu araç, önceki bir Amazon S3 kovası olup olmadığını kontrol eder ve ardından değilse etki alanının bir kova adı olup olmadığını kontrol etmeye çalışır.
- [S3Cruze](https://github.com/JR0ch17/S3Cruze) - Pentester'lar için her şeyi içeren bir AWS S3 kova aracı.


### CMS

- [wpscan](https://github.com/wpscanteam/wpscan) - WPScan, ticari olmayan kullanım için ücretsiz olan, siyah kutu WordPress güvenlik tarayıcısı
- [WPSpider](https://github.com/cyc10n3/WPSpider) - wpscan yardımcı programı tarafından desteklenen WordPress taramalarını çalıştırmak ve zamanlamak için merkezi bir gösterge paneli.
- [wprecon](https://github.com/blackcrw/wprecon) - Wordpress Keşfi
- [CMSmap](https://github.com/Dionach/CMSmap) - CMSmap, en popüler CMS'lerin güvenlik açıklarını tespit etme sürecini otomatikleştiren bir python açık kaynak CMS tarayıcısıdır.
- [joomscan](https://github.com/OWASP/joomscan) - OWASP Joomla Güvenlik Açığı Tarayıcı Projesi
- [pyfiscan](https://github.com/fgeek/pyfiscan) - Ücretsiz web uygulama açığı ve sürüm tarayıcısı


### JSON Web Token

- [jwt_tool](https://github.com/ticarpi/jwt_tool) - JSON Web Token'ları test etmek, ayarlamak ve çözmek için bir araç takımı
- [c-jwt-cracker](https://github.com/brendan-rius/c-jwt-cracker) - C dilinde yazılmış JWT brute force kırıcı
- [jwt-heartbreaker](https://github.com/wallarm/jwt-heartbreaker) - Bilinen genel kaynaklardan gelen anahtarlarla JWT (JSON Web Token) kontrolü yapmak için Burp uzantısı
- [jwtear](https://github.com/KINGSABRI/jwtear) - Hackerlar için JWT belgelerini ayrıştırmak, oluşturmak ve manipüle etmek için modüler bir komut satırı aracı
- [jwt-key-id-injector](https://github.com/dariusztytko/jwt-key-id-injector) - Hipotetik JWT güvenlik açıklarına karşı kontrol etmek için basit bir Python betiği
- [jwt-hack](https://github.com/hahwul/jwt-hack) - JWT'leri (JSON Web Token) hacklemek ve güvenlik testi yapmak için bir araç
- [jwt-cracker](https://github.com/lmammino/jwt-cracker) - Basit HS256 JWT belge kaba kuvvet kırıcısı

### postMessage

- [postMessage-tracker](https://github.com/fransr/postMessage-tracker) - postMessage kullanımını (URL, etki alanı ve yığın) CORS ile kaydederek ve genişletme simgesi olarak hem kayıt hem de görsel olarak izlemek için bir Chrome Eklentisi
- [PostMessage_Fuzz_Tool](https://github.com/kiranreddyrebel/PostMessage_Fuzz_Tool) - #BugBounty #BugBounty Araçları #WebDeveloper Aracı
  
### Subdomain Takeover

- [subjack](https://github.com/haccer/subjack) - Go dilinde yazılmış Alt Alan Ele Geçirme aracı
- [SubOver](https://github.com/Ice3man543/SubOver) - Güçlü bir Alt Alan Ele Geçirme aracı
- [autoSubTakeover](https://github.com/JordyZomer/autoSubTakeover) - Bir CNAME'nin kapsam adresine çözünüp çözünmediğini kontrol etmek için kullanılan bir araç. CNAME, kapsam dışı bir adrese çözünüyorsa, alt alan ele geçirme olasılığını kontrol etmek mantıklı olabilir.
- [NSBrute](https://github.com/shivsahni/NSBrute) - AWS NS Ele Geçirme açığına karşı savunmasız alanları ele geçirmek için kullanılan Python aracı
- [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) - "XYZ'yi ele geçirebilir miyim?" — hizmetlerin listesi ve sallanan DNS kayıtlarıyla (alt)alanları nasıl talep edeceğiniz.
- [cnames](https://github.com/cybercdh/cnames) - Çözülen alt alan listesini alır ve toplu olarak ilgili CNAME'leri döndürür.
- [subHijack](https://github.com/vavkamil/old-repos-backup/tree/master/subHijack-master) - Unutulmuş ve yanlış yapılandırılmış alt alan ele geçirme
- [tko-subs](https://github.com/anshumanbh/tko-subs) - Ölü DNS kayıtlarıyla alt alan ele geçirme olasılığını tespit etmeye ve ele geçirmeye yardımcı olan bir araç
- [HostileSubBruteforcer](https://github.com/nahamsec/HostileSubBruteforcer) - Bu uygulama mevcut alt alanları bruteforce eder ve 3. tarafın ana bilgisayarın doğru şekilde ayarlandığını kontrol eder.
- [second-order](https://github.com/mhmdiaa/second-order) - İkinci aşama alt alan ele geçirme taraması
- [takeover](https://github.com/mzfr/takeover) - Alt alan ele geçirme olasılıklarını kitle çekiminde test etmek için bir araç
- [dnsReaper](https://github.com/punk-security/dnsReaper) - DNS Reaper, başka bir alt alan ele geçirme aracıdır, ancak hassasiyet, hız ve silah deposundaki imza sayısı üzerinde vurgu yapar!

### Vulnerability Scanners

- [nuclei](https://github.com/projectdiscovery/nuclei) - Şablonlara dayalı hedef odaklı tarama için hızlı bir araç olan Nuclei, büyük ölçüde genişletilebilirlik ve kullanım kolaylığı sunar.
- [Sn1per](https://github.com/1N3/Sn1per) - Saldırgan güvenlik uzmanları için otomatik pentest çerçevesi
- [metasploit-framework](https://github.com/rapid7/metasploit-framework) - Metasploit Framework
- [nikto](https://github.com/sullo/nikto) - Nikto web sunucusu tarayıcı
- [arachni](https://github.com/Arachni/arachni) - Web Uygulama Güvenliği Tarayıcı Çerçevesi
- [jaeles](https://github.com/jaeles-project/jaeles) - Otomatik Web Uygulama Testi için İsviçre Çakısı
- [retire.js](https://github.com/RetireJS/retire.js) - Bilinen güvenlik açıkları olan JavaScript kütüphanelerini tespit eden tarayıcı
- [Osmedeus](https://github.com/j3ssie/Osmedeus) - Keşif ve zafiyet taraması için tamamen otomatikleştirilmiş saldırgan güvenlik çerçevesi
- [getsploit](https://github.com/vulnersCom/getsploit) - Saldırıları aramak ve indirmek için komut satırı yardımcı programı
- [flan](https://github.com/cloudflare/flan) - Oldukça güzel bir zafiyet tarayıcı
- [Findsploit](https://github.com/1N3/Findsploit) - Yerel ve çevrimiçi veritabanlarında hızlıca saldırıları bulun
- [BlackWidow](https://github.com/1N3/BlackWidow) - Hedef web sitesinde OWASP zafiyetlerini toplamak ve fuzz yapmak için Python tabanlı bir web uygulama tarayıcı
- [backslash-powered-scanner](https://github.com/PortSwigger/backslash-powered-scanner) - Bilinmeyen enjeksiyon açıkları sınıflarını bulur
- [Eagle](https://github.com/BitTheByte/Eagle) - Kit tabanlı çoklu iş parçacıklı zafiyet tarayıcı, web tabanlı uygulama zafiyetlerini kitle tespiti için
- [cariddi](https://github.com/edoardottt/cariddi) - Alan listesi alır, URL'leri gezinir ve uç noktaları, sırları, API anahtarlarını, dosya uzantılarını, belirteçleri vb. taramak için tarar
- [OWASP ZAP](https://github.com/zaproxy/zaproxy) - Dünya genelinde en popüler ücretsiz web güvenliği araçlarından biri olan OWASP ZAP ve uluslararası gönüllüler tarafından aktif olarak bakımı yapılır
- [SSTImap](https://github.com/vladko312/SSTImap) - SSTImap, web sitelerini Kod Enjeksiyonu ve Sunucu Tarafı Şablon Enjeksiyonu zafiyetleri için kontrol edebilen ve onları istismar edebilen bir penetrasyon testi yazılımıdır.
- 
### Uncategorized

- [JSONBee](https://github.com/zigoo0/JSONBee) - Farklı web sitelerinin içerik güvenlik politikasını (CSP) aşmak için kullanılmaya hazır JSONP uç noktaları/payloadları.
- [CyberChef](https://github.com/gchq/CyberChef) - Siber İsviçre Çakısı - şifreleme, kodlama, sıkıştırma ve veri analizi için web uygulaması
- [bountyplz](https://github.com/fransr/bountyplz) - Markdown şablonlarından otomatik güvenlik raporlama (HackerOne ve Bugcrowd şu anda desteklenen platformlardır)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) - Web Uygulama Güvenliği ve Pentest/CTF için kullanışlı payload ve bypass listesi
- [bounty-targets-data](https://github.com/arkadiyt/bounty-targets-data) - Bu depo, bildirime uygun olan günlük güncellenen veri dökümlerini içerir (Hackerone/Bugcrowd/Intigriti gibi ödül avı platformlarının kapsamları)
- [android-security-awesome](https://github.com/ashishb/android-security-awesome) - Android güvenliği ile ilgili kaynakların bir koleksiyonu
- [awesome-mobile-security](https://github.com/vaib25vicky/awesome-mobile-security) - Tüm kullanışlı android ve iOS güvenlik ile ilgili kaynakları tek bir yerde toplama çabası.
- [awesome-vulnerable-apps](https://github.com/vavkamil/awesome-vulnerable-apps) - Harika Zafiyetli Uygulamalar
- [XFFenum](https://github.com/vavkamil/XFFenum) - X-Forwarded-For [403 forbidden] taraması
- [httpx](https://github.com/projectdiscovery/httpx) - httpx, yeniden denenir http kütüphanesi kullanarak birden fazla prob yapma olanağı sağlayan hızlı ve çok amaçlı bir HTTP aracıdır. Sonuç güvenilirliğini artırılmış iş parçacıkları ile korumak için tasarlanmıştır.
- [csprecon](https://github.com/edoardottt/csprecon) - İçerik Güvenlik Politikası kullanarak yeni hedef alanlar keşfetme

---


