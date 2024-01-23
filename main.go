package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/schollz/progressbar/v3"

	"github.com/3th1nk/cidr"
	"github.com/tevino/tcp-shaker"
	"golang.org/x/net/proxy"
)

var (
	MAX_PORT = 65536
	host     = flag.String("host", "scanme.nmap.org", "host to scan")
	port     = flag.Int("port", 443, "port to scan")
	checker  = tcp.NewChecker()
)

type PortScanner struct{}

func (ps *PortScanner) Dial(network, address string) (net.Conn, error) {
	timeout := time.Second * 1
	_, client := net.Pipe()
	err := checker.CheckAddr(address, timeout)
	return client, err
	// This is a fake implemention in non-Linux platforms
	// return net.DialTimeout(network, address, timeout)
}

func ScanPort(d proxy.Dialer, host string, port int) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func buildSYNPacket(dstIP net.IP, dstPort int) []byte {
	buf := gopacket.NewSerializeBuffer()

	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(12345), // Use a random source port
		DstPort: layers.TCPPort(dstPort),
		SYN:     true,
	}

	ipLayer := &layers.IPv4{
		SrcIP:    net.IPv4(127, 0, 0, 1), // Use a dummy source IP address
		DstIP:    dstIP,
		Protocol: layers.IPProtocolTCP,
	}

	err := gopacket.SerializeLayers(buf, opts, ipLayer, tcpLayer)
	if err != nil {
		log.Fatal(err)
	}

	return buf.Bytes()
}

func VanillaScan(d proxy.Dialer, host string) []int {
	wg := &sync.WaitGroup{}
	ch := make(chan int)
	availablePorts := []int{}

	bar := progressbar.Default(int64(MAX_PORT), "Vanilla scanning ports 1..65536")
	for i := 1; i < MAX_PORT; i++ {
		wg.Add(1)
		go func(wg *sync.WaitGroup, ch chan int, port int, b *progressbar.ProgressBar) {
			if ok := ScanPort(d, host, port); ok {
				ch <- port
			}
			wg.Done()
			b.Add(1)
		}(wg, ch, i, bar)
	}
	go func() {
		wg.Wait()
		close(ch)
	}()

	for port := range ch {
		availablePorts = append(availablePorts, port)
	}

	return availablePorts
}

// TODO: add interesting ports 22 ssh, 443 https, etc.
func PrintAllowedPorts(host string, ports []int) string {
	s := fmt.Sprintf(`
HOST: %s
Open ports:
`, host)

	for _, p := range ports {
		s += fmt.Sprintf("  - %d\n", p)
	}

	return s
}

// TODO: add cmd pattern: https://medium.com/@MTrax/golang-command-pattern-931c44e7fa11#:~:text=The%20%E2%80%9CCommand%20Pattern%E2%80%9D%20is%20one%20of%20the%20design%20patterns%20introduced,requests%2C%20and%20support%20undoable%20operations.
func main() {
	flag.Parse()

	ctx, stopChecker := context.WithCancel(context.Background())
	defer stopChecker()
	go func() {
		if err := checker.CheckingLoop(ctx); err != nil {
			fmt.Println("checking loop stopped due to fatal error: ", err)
		}
	}()

	<-checker.WaitReady()

	c, err := cidr.Parse(*host)
	if err != nil {
		panic(err)
	}
	// TODO: parallelize per IP also
	c.Each(func(ip string) bool {
		fmt.Printf("Host IP: %s\n", ip)
		ports := VanillaScan(&PortScanner{}, ip)
		s := PrintAllowedPorts(ip, ports)
		fmt.Println(s)
		fmt.Printf("Number of ports open: %d\n", len(ports))
		return true
	})
}
