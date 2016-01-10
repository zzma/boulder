package va

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/letsencrypt/boulder/bdns"
)

func dialAddr(addr string, port int, timeout time.Duration, cancel chan struct{}, errors chan error, conns chan *net.Conn) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(addr, strconv.Itoa(port)), timeout)
	if err != nil {
		errors <- err
		return
	}
	select {
	case conns <- &conn:
		// won!
	case <-cancel:
		conn.Close()
	}
}
func DualStackLookup(hostname string, port int, resolver bdns.DNSResolver, timeout time.Duration) (*net.Conn, []net.IP, error) {
	// lookup addresses
	wg := new(sync.WaitGroup)
	allAddrs := make(chan []net.IP, 2)
	errors := make(chan error, 2)
	lookups := []func(string) ([]net.IP, error){
		resolver.LookupA,
		resolver.LookupAAAA,
	}
	for _, lookuper := range lookups {
		wg.Add(1)
		go func() {
			defer wg.Done()
			addrs, err := lookuper(hostname)
			if err != nil {
				errors <- err
				return
			}
			allAddrs <- addrs
		}()
	}
	wg.Wait()
	close(allAddrs)
	close(errors)
	if len(errors) > 0 && len(allAddrs) == 0 {
		return nil, nil, <-errors
	}
	if len(allAddrs) == 0 {
		return nil, nil, fmt.Errorf("No IPv4/6 addresses found")
	}

	// choose primary/secondary addresses
	resolvedAddrs := []net.IP{}
	var primaryAddr *net.IP
	var secondaryAddr *net.IP
	for addr := range allAddrs {
		if len(addr) == net.IPv6len && primaryAddr == nil {
			primaryAddr = &addr
		} else if secondaryAddr == nil {
			secondaryAddr = &addr
		}
		resolvedAddrs = append(resolvedAddrs, addr)
	}
	if primaryAddr == nil && secondaryAddr == nil {
		return nil, resolvedAddrs, fmt.Errorf("No suitable addresses found")
	}

	// start TCP connections to addresses
	conns := make(chan *net.Conn, 1)
	errors = make(chan error, 2)
	cancel := make(chan struct{}, 1)
	attempts := 0
	if primaryAddr != nil {
		attempts++
		go dialAddr(primaryAddr.String(), port, timeout, cancel, errors, conns)
	}
	if secondaryAddr != nil {
		attempts++
		go func() {
			if primaryAddr != nil {
				time.Sleep(time.Millisecond * 100)
			}
			dialAddr(secondaryAddr.String(), port, timeout, cancel, errors, conns)
		}
	}

	// wait for connection or errors
	var otherErr *error
	for {
		select {
		case conn := <-conns:
			cancel <- struct{}{}
			return conn, resolvedAddrs, nil
		case err := <-errors:
			if otherErr != nil && attempts == 2 {
				return nil, fmt.Errorf("Both connection attempts failed, [%s], [%s]", err.String(), otherErr.String())
			} else if attempts == 1 {
				return nil, resolvedAddrs, err
			} else {
				otherErr = err
			}
		}
	}
}
