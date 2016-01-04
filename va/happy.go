package va

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/letsencrypt/boulder/bdns"
)

type TypePreference int

var (
	V4 = TypePreference(0)
	V6 = TypePreference(1)
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

func partition(pref TypePreference, addr net.IP, primary *net.IP, secondary *net.IP) {
	if pref == V6 {
		if len(addr) == net.IPv6len {
			primary = &addr
		} else {
			secondary = &addr
		}
	} else {
		if len(addr) == net.IPv4len {
			primary = &addr
		} else {
			secondary = &addr
		}
	}
}

func DualStackLookup(hostname string, port int, resolver bdns.DNSResolver, pref TypePreference, timeout time.Duration) (*net.Conn, []net.IP, error) {
	// lookup addresses
	wg := new(sync.WaitGroup)
	allAddrs := make(chan net.IP, 2)
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
	if len(errors) > 0 {
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
		resolvedAddrs = append(resolvedAddrs, addr)
	}
	for _, addr := range resolvedAddrs {
		partition(pref, addr, primaryAddr, secondaryAddr)
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
	cancel := make(chan struct{}, 1)
	go dialAddr(primaryAddr.String(), port, timeout, cancel, errors, conns)
	go dialAddr(secondaryAddr.String(), port, timeout, cancel, errors, conns)

	select {
	case conn := <-conns:
		cancel <- struct{}{}
		return conn, resolvedAddrs, nil
	case err := <-errors:
		return nil, resolvedAddrs, err
	}
}
