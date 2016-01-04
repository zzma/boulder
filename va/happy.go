package va

import (
	"net"

	"github.com/letsencrypt/boulder/bdns"
)

type TypePreference struct

var (
	V4 TypePreference
	V6 TypePreference
)

func DualStackLookup(hostname string, port int, resolver bdns.DNSResolver, pref TypePreference, timeout time.Duration) (*net.Conn, []net.IP, error) {
	// lookup addresses
	wg := new(sync.WaitGroup)
	addrs := make(chan net.IP, 2)
	errors := make(chan error, 2)
	wg.Add(1)
	go func() {
		defer wg.Done()
		v4Addrs, err := resolver.LookupA(hostname)
		if err != nil {
			errors <- err
			return
		}
		addrs <- v4Addrs
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		v6Addrs, err := resolver.LookupAAAA(hostname)
		if err != nil {
			errors <- err
			return
		}
		addrs <- v6Addrs
	}()
	wg.Wait()
	close(addrs)
	close(errors)
	if len(errors) > 0 {
		return nil, nil, <-errors
	}
	if len(addrs) == 0 {
		return nil, nil, fmt.Errorf("No IPv4/6 addresses found")
	}

	// choose primary/secondary addresses
	resvoledAddrs := []net.IP{}
	var primaryAddr *net.IP
	var secondaryAddr *net.IP
	for _, addr := range addrs {
		resolvedAddrs = append(resolvedAddrs, addr)
	}
	for _, addr := range  resolvedAddrs {
		if pref == V6 {
			if len(addr) == net.IPv6len {
				primaryAddr = addr
			} else {
				secondaryAddr = addr
			}
		} else {
			if len(addr) == net.IPv4len {
				primaryAddr = addr
			} else {
				secondaryAddr = addr
			}
		}
		if primaryAddr != nil && secondaryAddr != nil {
			break
		}
	}
	if primaryAddr == nil && secondaryAddr == nil {
		return nil, resolvedAddrs, fmt.Errorf("No suitable addresses found")
	}

	// start TCP connections to addresses
	conns := make(chan *net.Conn, 1)
	errors = make(chan error, 2)
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(primaryAddr, port), timeout)
		if err != nil {
			errors <- err
			return
		}
		conns <- conn
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(time.Millisecond * 100)
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(secondaryAddr, port), timeout)
		if err != nil {
			errors <- err
			return
		}
		conns <- conn
	}()

	wg.Wait()
	close(conns)
	close(errors)

	if len(errors) > 0 && len(conns) == 0 {
		return nil, resolvedAddrs, <-errors
	} else if len(conns) == 0 {
		return nil, resolvedAddrs, fmt.Errorf("Unable to create connection")
	}

	return <-conns, resolvedAddrs, nil
}
