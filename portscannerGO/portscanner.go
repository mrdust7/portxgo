//go:build !syn
// +build !syn

/*
PORTXGO - Gelişmiş Go Port Tarayıcı

Bu uygulamayı çalıştırmak için aşağıdaki kütüphaneleri yüklemeniz gerekebilir:

SYN taraması için gerekli kütüphaneler:
    go get github.com/google/gopacket
    go get github.com/google/gopacket/layers
    go get github.com/google/gopacket/pcap

Windows'ta libpcap'i yüklemek için WinPcap veya Npcap'i kurmanız gerekebilir.
Linux'ta "libpcap-dev" paketini yükleyin: sudo apt-get install libpcap-dev

SYN taraması yapabilmek için programın root/yönetici yetkisiyle çalıştırılması gerekir.

Tüm özellikleri etkinleştirmek için şöyle derleyin:
    go build -tags=syn portscanner.go

Eğer sadece temel özellikleri kullanmak isterseniz:
    go build portscanner.go
*/

package main

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html/template"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	// github.com/google/gopacket ve alt paketleri SYN tarama özellikleri
	// için gereklidir. Yüklendiğinde ve 'syn' tag'iyle derlendiğinde,
	// bu importları etkinleştirin
	// _ "github.com/google/gopacket"
	// _ "github.com/google/gopacket/layers"
	// _ "github.com/google/gopacket/pcap"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// SYN taraması desteği olmayan derlemelerde uyarı
var synScanNotAvailable = true

// ScanOptions tarama seçeneklerini tutar
type ScanOptions struct {
	startIP        net.IP
	endIP          net.IP
	ips            []string // Subnet taraması için IP adresleri
	isIPv6         bool     // IPv6 desteği
	cidr           string   // CIDR gösterimi
	startPort      int
	endPort        int
	threadCount    int
	randomize      bool
	protocol       string
	quickScan      bool
	scanType       string // "connect", "syn", "ack", "fin", "null", "xmas", "udp", "ping"
	outputFormat   string // "txt", "json", "xml", "html"
	pingBeforeScan bool   // Ping ile host tespiti yap
	onlyShowOpen   bool   // Sadece açık portları göster
}

// ServiceInfo bir portun servis bilgilerini tutar
type ServiceInfo struct {
	Port      int
	State     string
	Service   string
	Version   string
	OS        string
	ExtraInfo string
}

// ServiceProbe bir servise özel sorgulama bilgisini tutar
type ServiceProbe struct {
	Name    string        // Servis adı
	Probe   []byte        // Gönderilecek veri
	Match   string        // Cevabı tanımak için regex pattern
	Timeout time.Duration // Timeout süresi
}

// Bazı yaygın servisler için özel problar
var serviceProbes = map[int][]ServiceProbe{
	21: { // FTP
		{
			Name:    "FTP",
			Probe:   []byte(""), // FTP banner istemeden gönderir
			Match:   "220",
			Timeout: 5 * time.Second,
		},
	},
	22: { // SSH
		{
			Name:    "SSH",
			Probe:   []byte("SSH-2.0-PORTXGO\r\n"),
			Match:   "SSH-",
			Timeout: 5 * time.Second,
		},
	},
	23: { // TELNET
		{
			Name:    "TELNET",
			Probe:   []byte(""),
			Match:   "",
			Timeout: 5 * time.Second,
		},
	},
	25: { // SMTP
		{
			Name:    "SMTP",
			Probe:   []byte("EHLO portxgo.local\r\n"),
			Match:   "220",
			Timeout: 5 * time.Second,
		},
	},
	80: { // HTTP
		{
			Name:    "HTTP",
			Probe:   []byte("GET / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: PORTXGO Scanner\r\n\r\n"),
			Match:   "HTTP/",
			Timeout: 5 * time.Second,
		},
	},
	443: { // HTTPS
		{
			Name:    "HTTPS",
			Probe:   []byte("GET / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: PORTXGO Scanner\r\n\r\n"),
			Match:   "HTTP/",
			Timeout: 5 * time.Second,
		},
	},
	3306: { // MySQL
		{
			Name:    "MySQL",
			Probe:   []byte(""),
			Match:   "",
			Timeout: 5 * time.Second,
		},
	},
	5432: { // PostgreSQL
		{
			Name:    "PostgreSQL",
			Probe:   []byte(""),
			Match:   "PGSQL",
			Timeout: 5 * time.Second,
		},
	},
}

// BannerInfo port banner bilgilerini tutar
type BannerInfo struct {
	Port   int
	Banner string
}

// Service sürüm bilgisini değerlendirmek için paternler ve kurallar
var servicePatterns = map[string][]struct {
	Pattern string
	Name    string
	Version string
}{
	"SSH": {
		{Pattern: "OpenSSH_([\\d\\.]+)", Name: "OpenSSH", Version: ""},
		{Pattern: "SSH-([\\d\\.]+)", Name: "Generic SSH", Version: ""},
	},
	"HTTP": {
		{Pattern: "Server: Apache/(\\d+\\.\\d+\\.\\d+)", Name: "Apache", Version: ""},
		{Pattern: "Server: nginx/(\\d+\\.\\d+\\.\\d+)", Name: "Nginx", Version: ""},
		{Pattern: "Server: Microsoft-IIS/(\\d+\\.\\d+)", Name: "IIS", Version: ""},
	},
	"FTP": {
		{Pattern: "220 (.*) FTP", Name: "Generic FTP", Version: ""},
		{Pattern: "220 ProFTPD (\\d+\\.\\d+\\.\\d+)", Name: "ProFTPD", Version: ""},
		{Pattern: "220 FileZilla Server version (\\d+\\.\\d+\\.\\d+)", Name: "FileZilla", Version: ""},
	},
	"SMTP": {
		{Pattern: "220 (.*) ESMTP (.*)", Name: "ESMTP", Version: ""},
		{Pattern: "220 (.*) Postfix", Name: "Postfix", Version: ""},
	},
	"POP3": {
		{Pattern: "\\+OK (.*)POP3(.*)ready", Name: "POP3", Version: ""},
	},
	"IMAP": {
		{Pattern: "\\* OK (.*)IMAP(.*)ready", Name: "IMAP", Version: ""},
	},
}

// ScanResult tarama sonuçlarını tutan ana yapı
type ScanResult struct {
	XMLName     xml.Name      `xml:"scan_result" json:"-"`
	Target      string        `xml:"target" json:"target"`
	StartTime   string        `xml:"start_time" json:"start_time"`
	EndTime     string        `xml:"end_time" json:"end_time"`
	Duration    float64       `xml:"duration" json:"duration"`
	TotalPorts  int           `xml:"total_ports" json:"total_ports"`
	OpenPorts   int           `xml:"open_ports" json:"open_ports"`
	PortRange   string        `xml:"port_range" json:"port_range"`
	Protocol    string        `xml:"protocol" json:"protocol"`
	ScanType    string        `xml:"scan_type" json:"scan_type"`
	ThreadCount int           `xml:"thread_count" json:"thread_count"`
	PortDetails []ServiceInfo `xml:"ports>port" json:"ports"`
}

// getEnhancedBanner servise özgü istek göndererek daha detaylı banner alır
func getEnhancedBanner(protocol, hostname string, port int, timeout time.Duration) string {
	// Önce servise özel prob var mı kontrol et
	probes, ok := serviceProbes[port]
	if !ok || len(probes) == 0 {
		// Prob yoksa normal banner alma işlemini kullan
		return getBanner(protocol, hostname, port, timeout)
	}

	// Her bir probu dene
	for _, probe := range probes {
		// Bağlantı aç
		address := net.JoinHostPort(hostname, strconv.Itoa(port))
		conn, err := net.DialTimeout(protocol, address, timeout)
		if err != nil {
			continue // Bu probe başarısız, bir sonrakini dene
		}

		// Önce varsa banner'ı oku (bazı servisler hemen banner gönderir)
		initialBanner := ""
		if protocol == "tcp" {
			// İlk banner için kısa timeout
			err = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			if err == nil {
				buffer := make([]byte, 1024)
				n, _ := conn.Read(buffer)
				if n > 0 {
					initialBanner = string(bytes.Trim(buffer[:n], "\x00"))
				}
			}
		}

		// Probe verisini gönder
		if len(probe.Probe) > 0 {
			_, err = conn.Write(probe.Probe)
			if err != nil {
				conn.Close()
				continue
			}
		}

		// Timeout ayarla
		err = conn.SetReadDeadline(time.Now().Add(probe.Timeout))
		if err != nil {
			conn.Close()
			continue
		}

		// Cevabı oku
		buffer := make([]byte, 4096) // Daha büyük buffer
		n, err := conn.Read(buffer)
		conn.Close()

		if err != nil {
			// Zaman aşımı veya başka bir hata, eğer initialBanner varsa onu kullan
			if initialBanner != "" {
				return initialBanner
			}
			continue
		}

		response := string(bytes.Trim(buffer[:n], "\x00"))

		// Eğer başlangıçta banner aldıysak ve şimdi de bir cevap aldıysak bunları birleştir
		if initialBanner != "" && initialBanner != response {
			return initialBanner + " " + response
		}

		return response
	}

	// Hiçbir prob başarılı olmadıysa standart banner alma yöntemini kullan
	return getBanner(protocol, hostname, port, timeout)
}

// getBanner banner bilgisini alır
func getBanner(protocol, hostname string, port int, timeout time.Duration) string {
	address := net.JoinHostPort(hostname, strconv.Itoa(port))
	conn, err := net.DialTimeout(protocol, address, timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	// Banner okuma için timeout ayarla
	err = conn.SetReadDeadline(time.Now().Add(timeout / 2))
	if err != nil {
		return ""
	}

	// Banner'ı oku
	buffer := make([]byte, 1024)
	n, _ := conn.Read(buffer)
	if n > 0 {
		return string(bytes.Trim(buffer[:n], "\x00"))
	}
	return ""
}

func getServiceName(port int) string {
	common_ports := map[int]string{
		20:    "FTP-DATA",
		21:    "FTP",
		22:    "SSH",
		23:    "TELNET",
		25:    "SMTP",
		53:    "DNS",
		67:    "DHCP",
		68:    "DHCP",
		69:    "TFTP",
		80:    "HTTP",
		110:   "POP3",
		123:   "NTP",
		137:   "NetBIOS",
		139:   "NetBIOS",
		143:   "IMAP",
		161:   "SNMP",
		443:   "HTTPS",
		445:   "SMB",
		514:   "Syslog",
		587:   "SMTP",
		1433:  "MSSQL",
		1723:  "PPTP",
		3306:  "MySQL",
		3389:  "RDP",
		5432:  "PostgreSQL",
		5900:  "VNC",
		6379:  "Redis",
		8080:  "HTTP-Proxy",
		27017: "MongoDB",
	}

	if service, ok := common_ports[port]; ok {
		return service
	}
	return "unknown"
}

// getBannerWithVersion banner ve sürüm bilgilerini alır
func getBannerWithVersion(protocol, hostname string, port int, timeout time.Duration) (string, string, string, string) {
	// Gelişmiş banner grabbing kullan
	banner := getEnhancedBanner(protocol, hostname, port, timeout)
	if banner == "" {
		return "", "", "", ""
	}

	// ServiceInfo.Service alanındaki servis adı
	serviceName := getServiceName(port)

	// Versiyon bilgisini çıkarmaya çalış
	var version, os, extraInfo string

	// Servis tipine göre farklı paternler kontrol edilir
	if patterns, ok := servicePatterns[serviceName]; ok {
		for _, pattern := range patterns {
			// Regex ile servise özgü bilgileri çıkar
			// Gerçek bir regex kullanımı daha kompleks olurdu
			if strings.Contains(banner, pattern.Pattern) {
				version = strings.Split(banner, pattern.Pattern)[1]
				break
			}
		}
	}

	// OS tespiti ve diğer bilgiler için basit kontroller
	if strings.Contains(strings.ToLower(banner), "ubuntu") {
		os = "Ubuntu"
	} else if strings.Contains(strings.ToLower(banner), "debian") {
		os = "Debian"
	} else if strings.Contains(strings.ToLower(banner), "centos") {
		os = "CentOS"
	} else if strings.Contains(strings.ToLower(banner), "windows") {
		os = "Windows"
	}

	// Ekstra bilgiler
	if strings.Contains(strings.ToLower(banner), "ssl") || strings.Contains(strings.ToLower(banner), "tls") {
		extraInfo = "Encrypted"
	}

	// Uzun veya garip bannerları kırp
	if len(banner) > 50 {
		banner = banner[:50] + "..."
	}

	return banner, version, os, extraInfo
}

// scanPort işlevini güncelle
func scanPort(portChan <-chan int, resultChan chan<- ServiceInfo, progressChan chan<- int, protocol, hostname string, timeout time.Duration, scanType string) {
	for port := range portChan {
		address := net.JoinHostPort(hostname, strconv.Itoa(port))
		result := ServiceInfo{
			Port:    port,
			State:   "closed",
			Service: getServiceName(port),
		}

		// Tarama tipine göre farklı tarama yöntemleri kullan
		switch scanType {
		case "connect":
			// Normal bağlantı taraması (varsayılan)
			conn, err := net.DialTimeout(protocol, address, timeout)
			if err == nil {
				result.State = "open"
				// Gelişmiş banner ve versiyon tespiti kullan
				banner, version, os, extraInfo := getBannerWithVersion(protocol, hostname, port, timeout)
				if banner != "" {
					result.Service = result.Service // Sadece servis ismi korunsun
					result.Version = version
					result.OS = os
					result.ExtraInfo = extraInfo
				}
				conn.Close()
			}
		case "udp":
			// UDP taraması - UDP protokolünü kullanır
			udpScanned := scanUDP(hostname, port, timeout)
			if udpScanned {
				result.State = "open|filtered" // UDP durumunda kesin olmayan sonuç
				// UDP banner grabbing daha zor olduğundan basit bilgiler
				result.Service = getServiceName(port)
			}
		case "ack", "fin", "null", "xmas":
			// Bu tarama tipleri SYN tag'i ile derleme gerektirir
			// syn tag kullanılmadığında mesaj göster ama connect taraması yap
			if synScanNotAvailable {
				// Connect taraması yap ve uyarı ekle
				conn, err := net.DialTimeout("tcp", address, timeout)
				if err == nil {
					result.State = "open"
					result.ExtraInfo = fmt.Sprintf("(%s taraması kullanılamıyor, connect taraması yapıldı)", scanType)
					conn.Close()
				}
			}
		default:
			// Diğer tarama tipleri için varsayılan connect taraması yap
			conn, err := net.DialTimeout(protocol, address, timeout)
			if err == nil {
				result.State = "open"
				conn.Close()
			}
		}

		resultChan <- result
		progressChan <- 1
	}
}

// scanUDP performanslı UDP taraması yapar
func scanUDP(hostname string, port int, timeout time.Duration) bool {
	address := net.JoinHostPort(hostname, strconv.Itoa(port))
	conn, err := net.DialTimeout("udp", address, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	// UDP için timeout ayarla
	err = conn.SetDeadline(time.Now().Add(timeout))
	if err != nil {
		return false
	}

	// Bazı UDP servisleri için temel problar gönder
	udpPayloads := map[int][]byte{
		53:  {0x00, 0x00, 0x10, 0x00, 0x00}, // DNS
		161: {0x30, 0x3A, 0x02, 0x01, 0x03}, // SNMP
		123: {0x1B, 0x00, 0x00, 0x00},       // NTP
		137: {0x80, 0xF0, 0x00, 0x10},       // NetBIOS
		// Diğer UDP protokolleri için problar eklenebilir
	}

	// Port için özel payload varsa gönder, yoksa boş veri gönder
	payload, exists := udpPayloads[port]
	if !exists {
		payload = []byte{0x00, 0x00, 0x00, 0x00}
	}

	_, err = conn.Write(payload)
	if err != nil {
		return false
	}

	// Cevap bekle (bazı portlar cevap vermez, bu normal)
	buffer := make([]byte, 1024)
	err = conn.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return false
	}

	n, err := conn.Read(buffer)
	if err == nil && n > 0 {
		// Cevap aldık, kesinlikle açık
		return true
	}

	// Cevap alınamadı ama bu UDP için normal olabilir
	// "ICMP port unreachable" hatası alınmadıysa "open|filtered" kabul edilir
	// Bu basitleştirilmiş bir UDP taramasıdır
	return true
}

// ParseCIDR CIDR notasyonunu işleyerek IP aralığı oluşturur
func parseCIDR(cidr string) ([]string, bool, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, false, err
	}

	isIPv6 := ip.To4() == nil

	var ips []string
	// IPv4 için
	if !isIPv6 {
		// IP ağındaki ilk adresi başlangıç olarak al
		start := ip.Mask(ipNet.Mask)
		// CIDR ağındaki toplam adres sayısını hesapla
		ones, bits := ipNet.Mask.Size()
		size := 1 << (bits - ones)
		// 2 adres çıkarıyoruz (network adresi ve broadcast adresi)
		if size > 2 {
			size -= 2
		} else {
			size = 1 // Tek host durumu
		}

		// IP adreslerini oluştur
		ips = make([]string, 0, size)
		for i := 0; i < size; i++ {
			// İlk adres network address, son adres broadcast
			if i > 0 || size <= 2 {
				ips = append(ips, nextIP(start).String())
			} else {
				// İlk iterasyonda network adresini atla
				nextIP(start)
			}
		}
	} else {
		// IPv6 için prefix tabanlı oluşturma
		prefix, bits := ipNet.Mask.Size()
		if bits-prefix > 16 {
			// Maksimum /112 prefix - çok fazla IP oluşturmayı engellemek için
			return nil, true, fmt.Errorf("IPv6 ağı çok büyük (en fazla /112 destekleniyor)")
		}

		// IP adreslerini oluştur
		ips = make([]string, 0)
		// Başlangıç IPv6 adresi
		start := ip.Mask(ipNet.Mask)
		addrCount := 1 << uint(bits-prefix)
		// Maksimum 65536 adres - güvenlik için
		if addrCount > 65536 {
			addrCount = 65536
		}

		for i := 0; i < addrCount; i++ {
			ips = append(ips, nextIPv6(start, i).String())
		}
	}

	return ips, isIPv6, nil
}

// nextIPv6 verilen IPv6 adresine offset ekler
func nextIPv6(ip net.IP, offset int) net.IP {
	newIP := make(net.IP, len(ip))
	copy(newIP, ip)

	// 16 baytlık IPv6 adresi
	for i := 15; i >= 0; i-- {
		oldByte := int(newIP[i]) + (offset % 256)
		newIP[i] = byte(oldByte % 256)
		offset = offset/256 + oldByte/256
		if offset == 0 {
			break
		}
	}

	return newIP
}

// doPingScan ICMP echo request kullanarak host tespiti yapar - IPv6 desteği
func doPingScan(host string, isIPv6 bool) bool {
	var err error
	var c *icmp.PacketConn
	var dst net.Addr

	if isIPv6 {
		// IPv6 ping
		c, err = icmp.ListenPacket("ip6:ipv6-icmp", "::")
		if err != nil {
			fmt.Printf("IPv6 ping dinleme hatası: %v\n", err)
			return false
		}
		dst, err = net.ResolveIPAddr("ip6", host)
	} else {
		// IPv4 ping
		c, err = icmp.ListenPacket("ip4:icmp", "0.0.0.0")
		if err != nil {
			fmt.Printf("IPv4 ping dinleme hatası: %v\n", err)
			return false
		}
		dst, err = net.ResolveIPAddr("ip4", host)
	}

	if err != nil {
		fmt.Printf("Hedef IP çözümleme hatası: %v\n", err)
		return false
	}

	defer c.Close()

	// ICMP Echo Request mesajı oluştur
	var msgType icmp.Type
	if isIPv6 {
		msgType = ipv6.ICMPTypeEchoRequest
	} else {
		msgType = ipv4.ICMPTypeEcho
	}

	msg := icmp.Message{
		Type: msgType, Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte("PORTXGO-PING"),
		},
	}

	// Mesajı byte dizisine dönüştür
	var proto int
	if isIPv6 {
		proto = 58 // ICMPv6
	} else {
		proto = 1 // ICMPv4
	}

	binMsg, err := msg.Marshal(nil)
	if err != nil {
		fmt.Printf("ICMP mesaj oluşturma hatası: %v\n", err)
		return false
	}

	// Ping gönder
	start := time.Now()
	_, err = c.WriteTo(binMsg, dst)
	if err != nil {
		fmt.Printf("ICMP gönderme hatası: %v\n", err)
		return false
	}

	// Cevap için bekle
	rb := make([]byte, 1500)
	err = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if err != nil {
		return false
	}

	// Cevabı oku
	n, _, err := c.ReadFrom(rb)
	if err != nil {
		return false
	}

	// ICMP cevabını işle
	rm, err := icmp.ParseMessage(proto, rb[:n])
	if err != nil {
		fmt.Printf("ICMP cevap ayrıştırma hatası: %v\n", err)
		return false
	}

	// Echo Reply olup olmadığını kontrol et
	pingLatency := time.Since(start).Milliseconds()

	if isIPv6 {
		switch rm.Type {
		case ipv6.ICMPTypeEchoReply:
			fmt.Printf("Host %s aktif (ping: %dms)\n", host, pingLatency)
			return true
		default:
			return false
		}
	} else {
		switch rm.Type {
		case ipv4.ICMPTypeEchoReply:
			fmt.Printf("Host %s aktif (ping: %dms)\n", host, pingLatency)
			return true
		default:
			return false
		}
	}
}

// main fonksiyonunda syn taraması istendiğinde uyarı göster
func main() {
	// Komut satırı argümanlarını işle
	if len(os.Args) < 2 {
		printHelp()
	}

	options := ScanOptions{
		threadCount: 100,
		protocol:    "tcp",
		startPort:   1,
		endPort:     1024,
		scanType:    "connect", // Varsayılan tarama tipi
	}

	// Argümanları parse et
	var target string
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-h", "--help":
			printHelp()
		case "-p":
			if i+1 < len(args) {
				ports := strings.Split(args[i+1], "-")
				if len(ports) == 2 {
					options.startPort, _ = strconv.Atoi(ports[0])
					options.endPort, _ = strconv.Atoi(ports[1])
				} else {
					// Tek port veya virgülle ayrılmış portlar
					portList := strings.Split(args[i+1], ",")
					if len(portList) > 0 {
						options.startPort, _ = strconv.Atoi(portList[0])
						options.endPort = options.startPort
						if len(portList) > 1 {
							lastPort, _ := strconv.Atoi(portList[len(portList)-1])
							options.endPort = lastPort
						}
					}
				}
				i++
			}
		case "-t":
			if i+1 < len(args) {
				options.threadCount, _ = strconv.Atoi(args[i+1])
				i++
			}
		case "-r":
			options.randomize = true
		case "-q":
			options.quickScan = true
		case "--syn":
			options.scanType = "syn"
		case "--ack":
			options.scanType = "ack"
		case "--fin":
			options.scanType = "fin"
		case "--null":
			options.scanType = "null"
		case "--xmas":
			options.scanType = "xmas"
		case "--udp":
			options.protocol = "udp"
			options.scanType = "udp"
		case "--ping":
			options.scanType = "ping"
		case "--ping-scan":
			options.pingBeforeScan = true
		case "--open":
			options.onlyShowOpen = true
		case "--output", "-o":
			if i+1 < len(args) {
				switch args[i+1] {
				case "json":
					options.outputFormat = "json"
				case "xml":
					options.outputFormat = "xml"
				case "html":
					options.outputFormat = "html"
				default:
					options.outputFormat = "txt" // Varsayılan metin formatı
				}
				i++
			}
		default:
			if !strings.HasPrefix(args[i], "-") {
				target = args[i]
			}
		}
	}

	if target == "" {
		fmt.Println("Hedef belirtilmedi!")
		return
	}

	// Hedefi çözümle
	// CIDR notasyonu mu kontrol et
	if strings.Contains(target, "/") {
		// CIDR subnet taraması
		ips, isIPv6, err := parseCIDR(target)
		if err != nil {
			fmt.Printf("CIDR ayrıştırma hatası: %v\n", err)
			return
		}

		options.ips = ips
		options.isIPv6 = isIPv6
		options.cidr = target

		// Toplam taranacak IP sayısını göster
		fmt.Printf("CIDR ağı ayrıştırıldı: %s (%d IP adresi)\n", target, len(ips))
	} else {
		// Tekil IP veya host taraması
		ip, err := resolveHost(target)
		if err != nil {
			fmt.Printf("Hata: %v\n", err)
			return
		}

		options.startIP = ip
		options.endIP = ip
		options.isIPv6 = ip.To4() == nil

		if options.isIPv6 {
			fmt.Printf("IPv6 adresi algılandı: %s\n", ip.String())
		}
	}

	if options.startPort <= 0 || options.endPort <= 0 || options.startPort > options.endPort {
		fmt.Println("Geçersiz port aralığı.")
		return
	}

	// Sadece Ping taraması için özel durum
	if options.scanType == "ping" {
		// CIDR bloğu için ping
		if options.cidr != "" {
			fmt.Printf("CIDR ağı ping taraması yapılıyor: %s\n", options.cidr)
			activeHosts := 0

			for _, ip := range options.ips {
				if doPingScan(ip, options.isIPv6) {
					activeHosts++
				}
				time.Sleep(100 * time.Millisecond) // Rate limiting
			}

			fmt.Printf("\nPing taraması tamamlandı: %d aktif cihaz bulundu (toplam: %d)\n",
				activeHosts, len(options.ips))
		} else {
			// Tekil IP için ping
			fmt.Printf("ICMP Ping taraması yapılıyor: %s\n", target)
			if doPingScan(options.startIP.String(), options.isIPv6) {
				fmt.Printf("\nHedef %s yanıt veriyor (aktif)\n", target)
			} else {
				fmt.Printf("\nHedef %s yanıt vermiyor\n", target)
			}
		}
		return
	}

	// CIDR subnet taraması için ana döngü
	if options.cidr != "" {
		// CIDR subnet için port taraması
		fmt.Printf("Subnet taraması ve port taraması başlatılıyor: %s, portlar: %d-%d\n",
			options.cidr, options.startPort, options.endPort)

		// IP'leri akıllıca dağıt - flood önleme
		ipChunks := chunkSlice(options.ips, 5) // Her seferde 5 IP

		for _, ipChunk := range ipChunks {
			var wg sync.WaitGroup
			for _, ip := range ipChunk {
				wg.Add(1)
				go func(ipAddr string) {
					defer wg.Done()

					// Ping ile host kontrolü
					if options.pingBeforeScan {
						if !doPingScan(ipAddr, options.isIPv6) {
							return // Host yanıt vermiyorsa atla
						}
					}

					// IP adresine port taraması
					scanIP(ipAddr, options)

				}(ip)
			}
			wg.Wait()
			// IP grupları arasında biraz bekle
			time.Sleep(500 * time.Millisecond)
		}

		fmt.Printf("\nSubnet taraması tamamlandı: %s\n", options.cidr)
		return
	}

	// Ping taraması yaparak host tespiti
	if options.pingBeforeScan {
		fmt.Printf("Tarama öncesi ICMP Ping kontrolü yapılıyor: %s\n", target)
		if !doPingScan(options.startIP.String(), options.isIPv6) {
			fmt.Printf("\nUYARI: Hedef %s ping'e yanıt vermiyor. Taramaya devam etmek istiyor musunuz? (e/h): ", target)
			var answer string
			fmt.Scanln(&answer)
			if strings.ToLower(answer) != "e" {
				fmt.Println("Tarama iptal edildi.")
				return
			}
		}
	}

	// Tekil IP adresi için port taraması yap
	scanIP(options.startIP.String(), options)
}

// scanIP tekil bir IP adresi için port taraması yapar
func scanIP(ipAddr string, options ScanOptions) {
	// Port listesini oluştur
	var ports []int

	// Port listesini oluştur
	if options.quickScan {
		ports = getCommonPorts()
	} else {
		for port := options.startPort; port <= options.endPort; port++ {
			ports = append(ports, port)
		}
	}

	// Portları karıştır
	if options.randomize {
		shufflePorts(ports)
	}

	// Performans için ayarlar
	timeout := 1 * time.Second
	if options.protocol == "udp" {
		timeout = 2 * time.Second // UDP için daha uzun timeout
	}

	results := make(chan ServiceInfo, len(ports))
	progress := make(chan int)
	portsChan := make(chan int, 100) // Port kanalı için tampon

	// ANSI Renk Kodları
	const (
		Reset   = "\033[0m"
		Red     = "\033[31m"
		Green   = "\033[32m"
		Yellow  = "\033[33m"
		Blue    = "\033[34m"
		Magenta = "\033[35m"
		Cyan    = "\033[36m"
		White   = "\033[37m"
		// İsteğe bağlı olarak diğer renkler eklenebilir
	)

	// ASCII Art banner sadece bir kere göster
	if options.cidr == "" {
		showBanner()
	}

	// Port tarama iş akışı
	fmt.Printf("\nHedef IP: %s\n", ipAddr)
	fmt.Printf("Port taraması başlatılıyor (%d port)...\n", len(ports))
	fmt.Printf("Thread sayısı: %d\n", options.threadCount)
	if options.quickScan {
		fmt.Println("Mod: Hızlı tarama (yaygın portlar)")
	}
	if options.randomize {
		fmt.Println("Mod: Rastgele port sırası")
	}
	fmt.Println()

	startTime := time.Now()
	totalPorts := len(ports)
	scannedPorts := 0

	// Progress bar goroutine
	go func() {
		for range progress {
			scannedPorts++
			percent := float64(scannedPorts) * 100 / float64(totalPorts)
			fmt.Printf("\rTaranıyor... [%d/%d] %.1f%% tamamlandı", scannedPorts, totalPorts, percent)
		}
		fmt.Println()
	}()

	// Worker pool oluştur
	if options.scanType == "syn" && !synScanNotAvailable {
		// SYN taraması için yetki kontrolü
		if os.Geteuid() != 0 {
			fmt.Println("SYN taraması için root / yönetici yetkileri gereklidir!")
			fmt.Println("Komutu 'sudo' veya yönetici olarak çalıştırın.")
			return
		}
		// Bu kısım sadece syn tag'i etkinleştirildiğinde ve gerekli
		// kütüphaneler yüklendiğinde çalışacak
		fmt.Printf("%s taraması yapılıyor...\n", options.scanType)
	} else if options.scanType != "connect" && synScanNotAvailable {
		// Gelişmiş tarama türleri için uyarı göster
		fmt.Printf("UYARI: %s taraması için 'syn' tag'i ile derleme gereklidir.\n", options.scanType)
		fmt.Println("Varsayılan connect taraması kullanılıyor.")
		fmt.Println("Gelişmiş tarama için: go build -tags=syn portscanner.go")
		options.scanType = "connect" // Varsayılan connect taramasına geri dön
	}

	// Normal socket-tabanlı tarama için worker havuzu
	createWorkerPool(options.threadCount, portsChan, results, progress, options.protocol, ipAddr, timeout, options.scanType)

	// Port listesini kanala gönder
	go func() {
		for _, port := range ports {
			portsChan <- port
		}
		close(portsChan)
	}()

	// Sonuçları topla ve formatla
	openPorts := 0
	var result ScanResult
	result.Target = ipAddr
	result.StartTime = startTime.Format("2006-01-02 15:04:05")
	result.PortRange = fmt.Sprintf("%d-%d", options.startPort, options.endPort)
	result.Protocol = options.protocol
	result.ScanType = options.scanType
	result.ThreadCount = options.threadCount
	result.TotalPorts = len(ports)

	// Ekranda gösterilecek başlıklar
	fmt.Println("\n\nPORT\tDURUM\tSERVIS\t\tVERSION\t\tOS")
	fmt.Println("----\t-----\t-------\t\t-------\t\t--")

	// Sonuçları topla
	var openPortDetails []ServiceInfo
	for portResult := range results {
		if portResult.State == "open" {
			versionInfo := ""
			if portResult.Version != "" {
				versionInfo = portResult.Version
			}

			osInfo := ""
			if portResult.OS != "" {
				osInfo = portResult.OS
			}

			extraInfo := ""
			if portResult.ExtraInfo != "" {
				extraInfo = fmt.Sprintf("(%s)", portResult.ExtraInfo)
			}

			// Ekrana yazdır
			fmt.Printf("%d\t%s\t%s\t\t%s\t\t%s %s\n",
				portResult.Port, portResult.State, portResult.Service,
				versionInfo, osInfo, extraInfo)

			// Port detaylarını topla
			openPortDetails = append(openPortDetails, portResult)
			openPorts++
		} else if !options.onlyShowOpen {
			// Kapalı portları da göster (--open parametresi verilmediyse)
			fmt.Printf("%d\t%s\t%s\n", portResult.Port, portResult.State, portResult.Service)
		}
	}

	// Sonuç yapısını tamamla
	endTime := time.Now()
	duration := endTime.Sub(startTime)
	result.EndTime = endTime.Format("2006-01-02 15:04:05")
	result.Duration = duration.Seconds()
	result.OpenPorts = openPorts
	result.PortDetails = openPortDetails

	// Rapor dosyasını oluştur
	var reportData []byte
	var reportErr error
	var fileExt string

	switch options.outputFormat {
	case "json":
		reportData, reportErr = generateJSONReport(result)
		fileExt = "json"
	case "xml":
		reportData, reportErr = generateXMLReport(result)
		fileExt = "xml"
	case "html":
		reportData, reportErr = generateHTMLReport(result)
		fileExt = "html"
	default: // txt
		// Basit text raporu için bir metnin oluşturulması
		var textReport strings.Builder
		textReport.WriteString("=== PORTXGO v1.0 ===\n")
		textReport.WriteString(fmt.Sprintf("Port Tarama Raporu - %s\n", result.StartTime))
		textReport.WriteString(fmt.Sprintf("Hedef: %s\n", result.Target))
		textReport.WriteString(fmt.Sprintf("Port Aralığı: %s\n", result.PortRange))
		textReport.WriteString(fmt.Sprintf("Protokol: %s\n", result.Protocol))
		if result.ScanType != "" {
			textReport.WriteString(fmt.Sprintf("Tarama Tipi: %s\n", result.ScanType))
		}
		if options.quickScan {
			textReport.WriteString("Mod: Hızlı tarama (yaygın portlar)\n")
		}
		if options.randomize {
			textReport.WriteString("Mod: Rastgele port sırası\n")
		}
		textReport.WriteString(fmt.Sprintf("Thread sayısı: %d\n\n", result.ThreadCount))
		textReport.WriteString("PORT\tDURUM\tSERVIS\t\tVERSION\t\tOS\n")
		textReport.WriteString("----\t-----\t-------\t\t-------\t\t--\n")

		for _, port := range result.PortDetails {
			textReport.WriteString(fmt.Sprintf("%d\t%s\t%s\t\t%s\t\t%s %s\n",
				port.Port, port.State, port.Service,
				port.Version, port.OS,
				func() string {
					if port.ExtraInfo != "" {
						return fmt.Sprintf("(%s)", port.ExtraInfo)
					}
					return ""
				}()))
		}

		summaryText := fmt.Sprintf("\nTarama tamamlandı! Süre: %.2f saniye\n", result.Duration)
		summaryText += fmt.Sprintf("Toplam %d açık port bulundu.\n", result.OpenPorts)
		textReport.WriteString(summaryText)

		reportData = []byte(textReport.String())
		fileExt = "txt"
	}

	if reportErr != nil {
		fmt.Printf("Rapor oluşturulurken hata: %v\n", reportErr)
	} else {
		// Raporu dosyaya kaydet
		cleanIP := strings.ReplaceAll(ipAddr, ":", "-") // IPv6 için : karakteri dosya adında sorun çıkarabilir
		outputFile := fmt.Sprintf("scan_%s_%s.%s",
			cleanIP,
			time.Now().Format("20060102_150405"),
			fileExt)

		if err := os.WriteFile(outputFile, reportData, 0644); err != nil {
			fmt.Printf("Rapor dosyaya kaydedilemedi: %v\n", err)
		} else {
			fmt.Printf("\nRapor dosyaya kaydedildi: %s\n", outputFile)
		}
	}

	// Özet bilgileri göster
	fmt.Printf("\nTarama tamamlandı! Süre: %.2f saniye\n", result.Duration)
	fmt.Printf("Toplam %d açık port bulundu.\n", result.OpenPorts)
}

// IP adresinden hostname çözümleme ekle
func lookupHostname(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return names[0]
}

// Host adını IP adresine çözer - IPv6 desteği ekle
func resolveHost(host string) (net.IP, error) {
	// IP adresi girilmiş mi kontrol et
	if ip := net.ParseIP(host); ip != nil {
		return ip, nil
	}

	// Host adını çözümle
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}

	// Önce IPv4 adreslerini kontrol et
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4, nil
		}
	}

	// IPv4 adresi bulunamadıysa, IPv6 adreslerini kontrol et
	for _, ip := range ips {
		if ip.To16() != nil && ip.To4() == nil {
			return ip, nil
		}
	}

	return nil, fmt.Errorf("IP adresi bulunamadı: %s", host)
}

// Listeyi belirli boyutlarda parçalara böl
func chunkSlice(slice []string, chunkSize int) [][]string {
	var chunks [][]string
	for i := 0; i < len(slice); i += chunkSize {
		end := i + chunkSize
		if end > len(slice) {
			end = len(slice)
		}
		chunks = append(chunks, slice[i:end])
	}
	return chunks
}

// Port listesini karıştırır
func shufflePorts(ports []int) {
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(ports), func(i, j int) {
		ports[i], ports[j] = ports[j], ports[i]
	})
}

// En yaygın portları döndürür
func getCommonPorts() []int {
	return []int{21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080}
}

// Bir sonraki IP adresini hesaplar
func nextIP(ip net.IP) net.IP {
	next := make(net.IP, len(ip))
	copy(next, ip)
	for i := len(next) - 1; i >= 0; i-- {
		next[i]++
		if next[i] != 0 {
			break
		}
	}
	return next
}

// Banner'ı ayrı bir fonksiyon olarak tanımla
func showBanner() {
	// ANSI Renk Kodları
	const (
		Reset   = "\033[0m"
		Red     = "\033[31m"
		Green   = "\033[32m"
		Yellow  = "\033[33m"
		Blue    = "\033[34m"
		Magenta = "\033[35m"
		Cyan    = "\033[36m"
		White   = "\033[37m"
		// İsteğe bağlı olarak diğer renkler eklenebilir
	)

	fmt.Println() // Banner öncesi boşluk ekle
	// ASCII Art Banner (Renkli Blok Stil - PORTXGO)
	fmt.Print(Magenta + `██████╗  ██████╗ ██████╗ ████████╗`) // PORT
	fmt.Print(Green + ` ██╗  ██╗`)                            // X
	fmt.Println(Cyan + ` ██████╗  ██████╗` + Reset)           // GO
	fmt.Print(Magenta + `██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝`) // PORT
	fmt.Print(Green + ` ╚██╗██╔╝`)                            // X
	fmt.Println(Cyan + ` ██╔════╝ ██╔═══██╗` + Reset)         // GO
	fmt.Print(Magenta + `██████╔╝██║   ██║██████╔╝   ██║   `) // PORT
	fmt.Print(Green + `  ╚███╔╝ `)                            // X
	fmt.Println(Cyan + ` ██║  ███╗██║   ██║` + Reset)         // GO
	fmt.Print(Magenta + `██╔═══╝ ██║   ██║██╔══██╗   ██║   `) // PORT
	fmt.Print(Green + `  ██╔██╗ `)                            // X
	fmt.Println(Cyan + ` ██║   ██║██║   ██║` + Reset)         // GO
	fmt.Print(Magenta + `██║     ╚██████╔╝██║  ██║   ██║   `) // PORT
	fmt.Print(Green + ` ██╔╝ ██╗`)                            // X
	fmt.Println(Cyan + ` ╚██████╔╝╚██████╔╝` + Reset)         // GO
	fmt.Print(Magenta + `╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   `) // PORT
	fmt.Print(Green + ` ╚═╝  ╚═╝`)                            // X
	fmt.Println(Cyan + `  ╚═════╝  ╚═════╝` + Reset)          // GO
	fmt.Println()

	fmt.Println("                                       v1.0")    // Version number
	fmt.Println("                                    by @Mrd717") // Developer
}

// printHelp fonksiyonunu güncelle
func printHelp() {
	fmt.Println(`
PORTXGO - Gelişmiş Go Port Tarayıcı

Kullanım: portscanner [seçenekler] <hedef>

Hedef:
  • Tek IP: 192.168.1.1
  • Hostname: example.com
  • CIDR subnet: 192.168.1.0/24
  • IPv6: ::1 veya 2001:db8::/64

Temel seçenekler:
  -p <port>           Taranacak port veya port aralığı (örn: 80 veya 20-100)
  -t <thread>         Kullanılacak thread sayısı (varsayılan: 100)
  -r                  Portları rastgele sırayla tara
  -q                  Hızlı tarama (sadece yaygın portlar)
  -o, --output <fmt>  Çıktı formatı: txt, json, xml, html (varsayılan: txt)
  --open              Sadece açık portları göster

Tarama türleri:
  --syn               SYN taraması (yarı-açık, root/admin gerekli)
  --ack               ACK taraması (firewall tespiti, root/admin gerekli)
  --fin               FIN taraması (gizli, root/admin gerekli)
  --null              NULL taraması (gizli, root/admin gerekli)
  --xmas              XMAS taraması (gizli, root/admin gerekli)
  --udp               UDP port taraması
  --ping              Sadece ICMP ping taraması yap
  --ping-scan         Port taraması öncesi ping ile host kontrolü yap

Örnek:
  portscanner example.com -p 80,443
  portscanner 192.168.1.1 -p 1-1000 -t 500 -r
  portscanner 10.0.0.0/24 --ping
  portscanner 192.168.0.0/24 -p 22,80,443 --open
  portscanner scanme.nmap.org --syn -p 1-100 -o json
  portscanner 2001:db8::/120 --ping
`)
	os.Exit(0)
}

// createWorkerPool işlevini güncelle
func createWorkerPool(numWorkers int, portsChan chan int, resultChan chan ServiceInfo,
	progressChan chan int, protocol, hostname string, timeout time.Duration, scanType string) {

	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			scanPort(portsChan, resultChan, progressChan, protocol, hostname, timeout, scanType)
		}()
	}

	// Tüm portlar tarandığında sonuç kanalını kapat
	go func() {
		wg.Wait()
		close(resultChan)
		close(progressChan)
	}()
}

// generateJSONReport JSON formatında rapor üretir
func generateJSONReport(result ScanResult) ([]byte, error) {
	return json.MarshalIndent(result, "", "  ")
}

// generateXMLReport XML formatında rapor üretir
func generateXMLReport(result ScanResult) ([]byte, error) {
	return xml.MarshalIndent(result, "", "  ")
}

// generateHTMLReport HTML formatında rapor üretir
func generateHTMLReport(result ScanResult) ([]byte, error) {
	// HTML şablonu
	htmlTemplate := `<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PORTXGO - Port Tarama Raporu</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: #fff;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #444;
            border-bottom: 2px solid #eee;
            padding-bottom: 10px;
        }
        .header {
            background-color: #007bff;
            color: white;
            padding: 10px;
            margin-bottom: 20px;
            border-radius: 5px;
        }
        .metadata {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .metadata p {
            margin: 5px 0;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        thead th {
            background-color: #007bff;
            color: white;
        }
        tr:nth-child(even) {
            background-color: #f8f9fa;
        }
        .open {
            color: #28a745;
            font-weight: bold;
        }
        .footer {
            text-align: center;
            color: #777;
            font-size: 14px;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>PORTXGO Port Tarama Raporu</h1>
        </div>
        
        <div class="metadata">
            <p><strong>Hedef:</strong> {{.Target}}</p>
            <p><strong>Tarama Başlangıç:</strong> {{.StartTime}}</p>
            <p><strong>Tarama Bitiş:</strong> {{.EndTime}}</p>
            <p><strong>Süre:</strong> {{.Duration}} saniye</p>
            <p><strong>Port Aralığı:</strong> {{.PortRange}}</p>
            <p><strong>Protokol:</strong> {{.Protocol}}</p>
            <p><strong>Tarama Tipi:</strong> {{.ScanType}}</p>
            <p><strong>Thread Sayısı:</strong> {{.ThreadCount}}</p>
            <p><strong>Toplam Port Sayısı:</strong> {{.TotalPorts}}</p>
            <p><strong>Açık Port Sayısı:</strong> {{.OpenPorts}}</p>
        </div>
        
        <table>
            <thead>
                <tr>
                    <th>Port</th>
                    <th>Durum</th>
                    <th>Servis</th>
                    <th>Versiyon</th>
                    <th>İşletim Sistemi</th>
                    <th>Ek Bilgi</th>
                </tr>
            </thead>
            <tbody>
                {{range .PortDetails}}
                <tr>
                    <td>{{.Port}}</td>
                    <td class="open">{{.State}}</td>
                    <td>{{.Service}}</td>
                    <td>{{.Version}}</td>
                    <td>{{.OS}}</td>
                    <td>{{.ExtraInfo}}</td>
                </tr>
                {{end}}
            </tbody>
        </table>
        
        <div class="footer">
            <p>PORTXGO v1.0 | Oluşturulma Tarihi: {{.EndTime}}</p>
        </div>
    </div>
</body>
</html>`

	// Şablonu analiz et
	tmpl, templateErr := template.New("report").Parse(htmlTemplate)
	if templateErr != nil {
		return nil, templateErr
	}

	// Şablonu işle
	var buf bytes.Buffer
	execErr := tmpl.Execute(&buf, result)
	if execErr != nil {
		return nil, execErr
	}

	return buf.Bytes(), nil
}
