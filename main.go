package main

import (
	"flag"
	"fmt"
	"net"
	"sync"

	"golang.org/x/net/proxy"
)

type PortScanner struct{}

func (ps *PortScanner) Dial(network, address string) (net.Conn, error) {
	return net.Dial(network, address)
}

var (
	MAX_PORT = 65536
	host     = flag.String("host", "scanme.nmap.org", "host to scan")
	port     = flag.Int("port", 443, "port to scan")
)

func ScanPort(dialer proxy.Dialer, host string, port int) (int, bool) {
	addr := fmt.Sprintf("%s:%d", host, port)

	// TODO: use ip4:tcp not to complete tcp handshake
	// This will imply sending SYN packet and listening fot SYN+ACK or RST to validate
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return port, false
	}
	conn.Close()
	return port, true
}

func VanillaScan(d proxy.Dialer, host string) []int {
	wg := &sync.WaitGroup{}
	ch := make(chan int)
	availablePorts := []int{}

	// TODO: add progress bar
	for i := 1; i < MAX_PORT; i++ {
		wg.Add(1)
		go func(wg *sync.WaitGroup, ch chan int, port int) {
			if p, ok := ScanPort(d, host, port); ok {
				ch <- p
			}
			wg.Done()
		}(wg, ch, i)
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

	// TODO: host parse input

	ports := VanillaScan(&PortScanner{}, *host)
	s := PrintAllowedPorts(*host, ports)
	fmt.Println(s)
}
