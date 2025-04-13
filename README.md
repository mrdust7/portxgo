# portxgo
Gelişmiş Go Port Tarama Aracı

![New Project](https://github.com/user-attachments/assets/841a0ecb-bb2e-4815-a46e-58f34f969b23)
# PORTXGO - Gelişmiş Go Port Tarama Aracı

PORTXGO, Go programlama dili ile geliştirilmiş, hızlı ve güçlü bir ağ güvenliği tarama aracıdır. Nmap'e benzer şekilde çeşitli tarama türleri destekleyen, IPv4/IPv6 ve subnet taraması yapabilen modern bir port tarayıcıdır.

![PORTXGO Banner](https://via.placeholder.com/800x200/0073e6/ffffff?text=PORTXGO)

## Özellikler

✅ **Çoklu Tarama Türleri**
- TCP Connect taraması
- UDP port taraması
- SYN, ACK, FIN, NULL, XMAS taramaları (root/admin gerekli)

✅ **Geniş Ağ Desteği**
- IPv4 ve IPv6 desteği
- CIDR subnet taraması (192.168.1.0/24 gibi)
- Hostname çözümleme

✅ **Host Keşfi**
- ICMP ping ile host tespiti
- Ping olmadan tarama seçeneği

✅ **Servis ve Sürüm Tespiti**
- Gelişmiş banner grabbing
- Servis ve sürüm bilgisi çıkarma
- İşletim sistemi ipuçları

✅ **Rapor Formatları**
- JSON
- XML
- HTML
- TXT

✅ **Performans ve Esneklik**
- Çok iş parçacıklı tarama (Thread sayısı ayarlanabilir)
- Portları rastgele sırayla tarama (IDS/IPS kaçınma)
- Hızlı tarama modu (yaygın portlar)

## Kurulum

### Ön Koşullar

- Go 1.16 veya üstü
- SYN taraması için libpcap (opsiyonel)

### Kaynaktan Derleme

```bash
# Repoyu klonlayın
git clone https://github.com/mrdust7/portxgo.git
cd portxgo

# Bağımlılıkları yükleyin
go mod tidy

# Normal özellikleri derleme
go build

# SYN taraması gibi gelişmiş özellikler için
go build -tags=syn
```

### Gerekli Bağımlılıklar (SYN taraması için)

**Linux:**
```bash
sudo apt-get install libpcap-dev
```

**Windows:**
WinPcap veya Npcap kurulumu gerekir.

**macOS:**
```bash
brew install libpcap
```

## Kullanım

### Temel Kullanım

```bash
# Tek bir host için temel tarama
portxgo example.com

# Belirli portları tarama
portxgo 192.168.1.1 -p 80,443,8080

# Port aralığı tarama
portxgo scanme.nmap.org -p 1-1000
```

### Tarama Türleri

```bash
# UDP taraması
portxgo 192.168.1.1 --udp -p 53,161,123

# SYN taraması (root/admin gerekli)
sudo portxgo 10.0.0.1 --syn -p 1-1000

# FIN/NULL/XMAS taramaları
sudo portxgo 10.0.0.1 --fin -p 1-1000
sudo portxgo 10.0.0.1 --null -p 1-1000
sudo portxgo 10.0.0.1 --xmas -p 1-1000
```

### Ağ Taraması

```bash
# CIDR subnet taraması
portxgo 192.168.0.0/24 -p 22,80,443

# IPv6 taraması
portxgo 2001:db8::/120 -p 80,443
```

### Gelişmiş Tarama

```bash
# Sadece ping taraması
portxgo 10.0.0.0/24 --ping

# Ping kontrolü sonrası port tarama
portxgo example.com --ping-scan -p 1-1000

# Sadece açık portları göster
portxgo 192.168.1.1 -p 1-65535 --open

# Rastgele port sırası
portxgo 10.0.0.1 -p 1-1000 -r

# 500 thread ile yüksek hızlı tarama
portxgo scanme.nmap.org -p 1-65535 -t 500
```

### Rapor Formatları

```bash
# JSON raporu
portxgo example.com -p 1-1000 -o json

# XML raporu
portxgo 192.168.1.1 -o xml

# HTML raporu
portxgo scanme.nmap.org -o html
```

## Ekran Görüntüleri

![Örnek Tarama](https://via.placeholder.com/800x400/0073e6/ffffff?text=PORTXGO+Example+Scan)

## Yasal Uyarı

Bu aracı yalnızca yetkili olduğunuz sistemlerde ve yasal amaçlar için kullanın. İzinsiz tarama yapmak yasalara aykırı olabilir. Yazılımın kullanımından doğacak her türlü sorumluluk kullanıcıya aittir.

## Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için [LICENSE](LICENSE) dosyasını inceleyebilirsiniz.

## İletişim

GitHub: [@mrdust7](https://github.com/mrdust7)
