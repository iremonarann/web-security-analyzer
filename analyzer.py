"""
BİL 420 Projesi
İrem Onaran - 201101045
Konu: Web Güvenlik Başlıkları, Çerez ve TLS Analiz Aracı
"""

import requests
import sys
import ssl
import socket
import re
import argparse
from urllib.parse import urlparse
from datetime import datetime

# Terminal çıktılarını renklendirmek için kullandığım sınıf
class Renkler:
    MOR_BASLIK = '\033[95m'
    YESIL_OK = '\033[92m'
    SARI_UYARI = '\033[93m'
    KIRMIZI_HATA = '\033[91m'
    SIFIRLA = '\033[0m'
    KALIN = '\033[1m'

# Hangi açık ne anlama geliyor ve ne yapılması lazım
# Burada riskleri, CIA üçgenini ve çözüm önerilerini tutuyorum.
RISK_VERITABANI = {
    'Strict-Transport-Security': {
        'risk': 'Yüksek', 'cia': 'Gizlilik', 
        'aciklama': 'HSTS başlığı yok. Bu durum SSL Strip saldırılarına kapı açabilir.',
        'cozum': 'Sunucu ayarlarına "Strict-Transport-Security" eklenmeli.'
    },
    'Content-Security-Policy': {
        'risk': 'Yüksek', 'cia': 'Bütünlük', 
        'aciklama': 'CSP eksik. XSS saldırılarına karşı koruma zayıf.',
        'cozum': 'Güçlü bir "Content-Security-Policy" kuralı tanımlanmalı.'
    },
    'X-Content-Type-Options': {
        'risk': 'Orta', 'cia': 'Bütünlük', 
        'aciklama': 'MIME-sniffing koruması yok. Dosyalar yanlış türde çalıştırılabilir.',
        'cozum': '"nosniff" parametresi ile bu başlık eklenmeli.'
    },
    'X-Frame-Options': {
        'risk': 'Orta', 'cia': 'Bütünlük', 
        'aciklama': 'Clickjacking koruması yok. Site iframe içine alınabilir.',
        'cozum': '"SAMEORIGIN" veya "DENY" olarak ayarlanmalı.'
    },
    'Sunucu-Bilgisi': {
        'risk': 'Düşük', 'cia': 'Gizlilik', 
        'aciklama': 'Sunucu kendi versiyon bilgisini ifşa ediyor (Information Disclosure).',
        'cozum': 'Server ve X-Powered-By başlıkları gizlenmeli.'
    },
    'Secure-Flag': {
        'risk': 'Orta', 'cia': 'Gizlilik', 
        'aciklama': 'Çerezde "Secure" bayrağı yok. HTTP üzerinden çalınabilir.',
        'cozum': 'Çerez ayarlarına "Secure" eklenmeli.'
    },
    'HttpOnly-Flag': {
        'risk': 'Orta', 'cia': 'Gizlilik', 
        'aciklama': 'Çerezde "HttpOnly" bayrağı yok. Javascript ile çalınabilir (XSS).',
        'cozum': 'Çerez ayarlarına "HttpOnly" eklenmeli.'
    },
    'Zayif-TLS': {
        'risk': 'Kritik', 'cia': 'Gizlilik/Bütünlük', 
        'aciklama': 'Çok eski bir TLS sürümü kullanılıyor.',
        'cozum': 'Sunucu TLS 1.2 veya 1.3 sürümüne güncellenmeli.'
    },
    'Acik-Port': {
        'risk': 'Değişken', 'cia': 'Erişilebilirlik/Gizlilik', 
        'aciklama': 'Gereksiz açık portlar saldırı yüzeyini artırır.',
        'cozum': 'Kullanılmayan servisler kapatılmalı veya firewall kullanılmalı.'
    }
}

# Hem ekrana basıp hem de dosyaya kaydetmek için yazdığım yardımcı sınıf
# Print fonksiyonunu buna yönlendiriyorum.
class LogTutucu(object):
    def __init__(self, dosya_adi):
        self.terminal = sys.stdout
        self.log_dosyasi = open(dosya_adi, "w", encoding="utf-8")
        # Dosyaya yazarken renk kodlarını temizlemek için regex
        self.renk_temizleyici = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

    def write(self, mesaj):
        self.terminal.write(mesaj) # Ekrana renkli bas
        temiz_mesaj = self.renk_temizleyici.sub('', mesaj)
        self.log_dosyasi.write(temiz_mesaj) # Dosyaya temiz bas

    def flush(self):
        # Print fonksiyonunun düzgün çalışması için gerekli
        self.terminal.flush()
        self.log_dosyasi.flush()


# ANALİZ FONKSİYONLARI 

def sunucu_gizliligi_kontrol(headers):
    """Sunucunun versiyon bilgisini ifşa edip etmediğine bakar."""
    riskli_basliklar = ['Server', 'X-Powered-By', 'X-AspNet-Version']
    sorun_bulundu = False
    
    print(f"\n{Renkler.KALIN}Sunucu Bilgi İfşası Kontrolü:{Renkler.SIFIRLA}")
    for h in riskli_basliklar:
        if h in headers:
            print(f"  {Renkler.SARI_UYARI}[!] UYARI: {h} başlığı bilgi veriyor: '{headers[h]}'{Renkler.SIFIRLA}")
            sorun_bulundu = True
    
    if sorun_bulundu:
        detay = RISK_VERITABANI['Sunucu-Bilgisi']
        print(f"     -> {Renkler.KIRMIZI_HATA}Risk:{Renkler.SIFIRLA} {detay['risk']} | Etki: {detay['cia']}")
        print(f"     -> Çözüm: {detay['cozum']}")
    else:
        print(f"  {Renkler.YESIL_OK}[✓] Sunucu sürüm bilgileri gizlenmiş.{Renkler.SIFIRLA}")

def header_guvenlik_kontrolu(headers):
    """HTTP yanıt başlıklarını (Headers) tek tek kontrol eder."""
    print(f"\n{Renkler.MOR_BASLIK}=== 1. GÜVENLİK BAŞLIK ANALİZİ (HEADERS) ==={Renkler.SIFIRLA}")
    
    # Önce sunucu bilgisini kontrol edelim
    sunucu_gizliligi_kontrol(headers)

    # CSP Kontrolü
    print(f"\n{Renkler.KALIN}Content-Security-Policy (XSS Kalkanı):{Renkler.SIFIRLA}")
    if 'Content-Security-Policy' in headers:
        print(f"  {Renkler.YESIL_OK}[✓] KORUMA AKTİF.{Renkler.SIFIRLA}")
    elif 'Content-Security-Policy-Report-Only' in headers:
        # Report-only olması tam koruma sağlamaz.
        print(f"  {Renkler.SARI_UYARI}[!] RİSKLİ: Sadece 'Raporlama' modu aktif.{Renkler.SIFIRLA}")
        print(f"     -> Öneri: Politikayı test ettikten sonra 'Report-Only' modundan çıkarın.")
    else:
        print(f"  {Renkler.KIRMIZI_HATA}[X] EKSİK.{Renkler.SIFIRLA}")
        print(f"     -> Çözüm: {RISK_VERITABANI['Content-Security-Policy']['cozum']}")

    # Diğer standart başlıkların kontrolü
    print(f"\n{Renkler.KALIN}Diğer Kritik Başlıklar:{Renkler.SIFIRLA}")
    kontrol_listesi = ['Strict-Transport-Security', 'X-Content-Type-Options', 'X-Frame-Options']
    
    for h in kontrol_listesi:
        if h in headers:
            print(f"  {Renkler.YESIL_OK}[✓] {h}: Mevcut{Renkler.SIFIRLA}")
        else:
            print(f"  {Renkler.KIRMIZI_HATA}[X] {h}: EKSİK{Renkler.SIFIRLA}")
            if h in RISK_VERITABANI:
                print(f"     -> Çözüm: {RISK_VERITABANI[h]['cozum']}")

def cookie_guvenlik_kontrolu(cookies):
    """Set-Cookie başlıklarındaki Secure ve HttpOnly bayraklarına bakar."""
    print(f"\n{Renkler.MOR_BASLIK}=== 2. ÇEREZ GÜVENLİK ANALİZİ ==={Renkler.SIFIRLA}")
    
    if not cookies:
        print(f"{Renkler.YESIL_OK}[i] Herhangi bir çerez (cookie) bulunamadı.{Renkler.SIFIRLA}")
        return

    hatali_cerez_sayisi = 0
    for cookie in cookies:
        print(f"\n{Renkler.KALIN}{cookie.name}{Renkler.SIFIRLA}")
        
        # Secure
        if cookie.secure:
            print(f"  {Renkler.YESIL_OK}[✓] Secure: Var{Renkler.SIFIRLA}")
        else:
            print(f"  {Renkler.KIRMIZI_HATA}[X] Secure: EKSİK{Renkler.SIFIRLA}")
            hatali_cerez_sayisi += 1
        
        # HttpOnly (bazen farklı yerlerde olabiliyor, hepsine bakıyoruz)
        httponly_var_mi = cookie.has_nonstandard_attr('httponly') or cookie.has_nonstandard_attr('HttpOnly') or 'httponly' in cookie._rest
        
        if httponly_var_mi:
            print(f"  {Renkler.YESIL_OK}[✓] HttpOnly: Var{Renkler.SIFIRLA}")
        else:
            print(f"  {Renkler.KIRMIZI_HATA}[X] HttpOnly: EKSİK{Renkler.SIFIRLA}")
            hatali_cerez_sayisi += 1
    
    if hatali_cerez_sayisi > 0:
        print(f"\n{Renkler.KIRMIZI_HATA}Toplam {hatali_cerez_sayisi} çerez hatası tespit edildi.{Renkler.SIFIRLA}")
    else:
        print(f"\n{Renkler.YESIL_OK}Tüm çerezler güvenli görünüyor.{Renkler.SIFIRLA}")

def ssl_tls_kontrolu(hostname):
    """Soket bağlantısı ile TLS sürümü ve sertifika tarihini kontrol eder."""
    print(f"\n{Renkler.MOR_BASLIK}=== 3. TLS/SSL VE SERTİFİKA ANALİZİ ==={Renkler.SIFIRLA}")
    
    baglam = ssl.create_default_context()
    try:
        # 443 portuna güvenli bağlantı deniyoruz
        with socket.create_connection((hostname, 443), timeout=5) as soket:
            with baglam.wrap_socket(soket, server_hostname=hostname) as guvenli_soket:
                versiyon = guvenli_soket.version()
                
                # Eski protokoller risklidir
                if versiyon in ['TLSv1', 'TLSv1.1']:
                    print(f"{Renkler.KIRMIZI_HATA}[X] TLS: {versiyon} (ZAYIF){Renkler.SIFIRLA}")
                else:
                    print(f"{Renkler.YESIL_OK}[✓] TLS: {versiyon} (Güvenli){Renkler.SIFIRLA}")
                
                # Sertifika detaylarını al
                sertifika = guvenli_soket.getpeercert()
                try:
                    saglayici_bilgisi = dict(x[0] for x in sertifika['issuer'])
                    saglayici = saglayici_bilgisi.get('organizationName') or saglayici_bilgisi.get('commonName')
                    print(f"{Renkler.YESIL_OK}[✓] Sertifika Sağlayıcı: {saglayici}{Renkler.SIFIRLA}")
                except:
                    print(f"{Renkler.SARI_UYARI}[i] Sertifika sağlayıcı bilgisi okunamadı.{Renkler.SIFIRLA}")
                    
                print(f"{Renkler.YESIL_OK}[✓] Sertifika Bitiş: {sertifika['notAfter']}{Renkler.SIFIRLA}")
                
    except Exception as hata:
        print(f"{Renkler.KIRMIZI_HATA}[-] SSL Bağlantı Hatası: {hata}{Renkler.SIFIRLA}")

def port_taramasi(hostname):
    """Kritik portları tarayarak gereksiz açık kapı var mı diye bakar."""
    print(f"\n{Renkler.MOR_BASLIK}=== 4. PORT TARAMA (NETWORK ANALİZİ) ==={Renkler.SIFIRLA}")
    print("Kritik portlar taranıyor (Biraz zaman alabilir)...")
    
    # Tarayacağımız en önemli portlar
    hedef_portlar = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
        53: 'DNS', 80: 'HTTP', 443: 'HTTPS',
        3306: 'MySQL', 8080: 'HTTP-Alt', 3389: 'RDP'
    }
    
    acik_port_sayisi = 0
    for port, servis in hedef_portlar.items():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5) # Hızlı olsun diye timeout'u kısa tuttum
        sonuc = s.connect_ex((hostname, port))
        
        if sonuc == 0:
            print(f"  {Renkler.SARI_UYARI}[!] AÇIK PORT: {port} ({servis}){Renkler.SIFIRLA}")
            acik_port_sayisi += 1
        s.close()
        
    if acik_port_sayisi > 0:
        detay = RISK_VERITABANI['Acik-Port']
        print(f"\n     -> {Renkler.KIRMIZI_HATA}Risk:{Renkler.SIFIRLA} {detay['risk']}")
        print(f"     -> Çözüm: {detay['cozum']}")
    else:
        print(f"{Renkler.YESIL_OK}[✓] Kritik portlarda bir açıklık görülmedi.{Renkler.SIFIRLA}")


# ANA PROGRAM
if __name__ == "__main__":

    # Komut satırından argüman almak için
    parser = argparse.ArgumentParser(description='Web Güvenlik Analiz Aracı - BİL420')
    parser.add_argument('-u', '--url', help='Analiz edilecek URL')
    args = parser.parse_args()

    # Eğer parametre girilmediyse kullanıcıya sor
    if not args.url:
        hedef_url = input("Analiz edilecek URL'yi girin (örn: google.com): ").strip()
    else:
        hedef_url = args.url

    # URL temizleme ve dosya adı oluşturma
    temiz_url = hedef_url.replace('https://', '').replace('http://', '').split('/')[0]
    tarih = datetime.now().strftime('%Y-%m-%d')
    dosya_adi = f"rapor_{temiz_url}_{tarih}.txt"


    orijinal_stdout = sys.stdout

    # Çıktıları artık hem ekrana hem dosyaya yönlendir
    sys.stdout = LogTutucu(dosya_adi)

    print(f"--- ANALİZ BAŞLIYOR: {datetime.now()} ---")
    print(f"Hedef: {hedef_url}\n")

    try:
        # Başında http yoksa ekleyelim
        if not hedef_url.startswith('http'): 
            hedef_url = 'https://' + hedef_url
            
        # İstek atıyoruz
        # verify=True varsayılan olarak açıktır ama yine de belirttim
        response = requests.get(hedef_url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=10, verify=True)
        print(f"[+] Bağlantı Başarılı. Kod: {response.status_code}")
        
        # Sırasıyla modülleri çalıştır
        header_guvenlik_kontrolu(response.headers)
        cookie_guvenlik_kontrolu(response.cookies)
        
        # URL'den domain adını ayırıp TLS ve Port taraması yapıyoruz
        parsed_url = urlparse(hedef_url)
        if parsed_url.hostname:
            ssl_tls_kontrolu(parsed_url.hostname)
            port_taramasi(parsed_url.hostname)

    except Exception as hata:
        print(f"{Renkler.KIRMIZI_HATA}[-] Bir hata oluştu: {hata}{Renkler.SIFIRLA}")


    # Dosyaya yazma işlemini durdurmak için terminali eski haline döndürdüm.
    sys.stdout = orijinal_stdout
    print(f"\nAnaliz tamamlandı. Rapor dosyası oluşturuldu: {dosya_adi}")