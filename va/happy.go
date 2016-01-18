package va

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/golang.org/x/net/context"
	"github.com/letsencrypt/boulder/bdns"
)

// dialAddr does the actual dialing of a network address and returns
// a net.Conn or error via the provided channels
func dialAddr(addr *net.IP, port int, timeout time.Duration, cancel chan struct{}, errors chan error, conns chan *net.Conn, used *net.IP) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(addr.String(), strconv.Itoa(port)), timeout)
	if err != nil {
		errors <- err
		return
	}
	select {
	case conns <- &conn:
		// won!
		used = addr
	case <-cancel:
		conn.Close()
	}
}

// DualStackDial performs a Happy-Eyeballs (ish) attempt to connect to a host
// over both IPv4 and IPv6. Since this type of lookup is only used for resolution
// during validation it also returns all resolved addresses for the host and the
// specific IP address that the returned net.Conn connected to
func DualStackDial(hostname string, port int, timeout time.Duration, resolver bdns.DNSResolver) (*net.Conn, net.IP, []net.IP, error) {
	// Lookup A/AAAA records concurrently
	wg := new(sync.WaitGroup)
	allAddrs := make(chan []net.IP, 2)
	errors := make(chan error, 2)
	lookups := []func(context.Context, string) ([]net.IP, error){
		resolver.LookupA,
		resolver.LookupAAAA,
	}
	// TODO(#1292): add a proper deadline here
	ctx := context.TODO()
	for _, lookuper := range lookups {
		wg.Add(1)
		go func(l func(context.Context, string) ([]net.IP, error)) {
			defer wg.Done()
			addrs, err := l(ctx, hostname)
			if err != nil {
				errors <- err
				return
			}
			allAddrs <- addrs
		}(lookuper)
	}
	wg.Wait()
	close(allAddrs)
	close(errors)
	if len(errors) > 0 && len(allAddrs) == 0 {
		return nil, nil, nil, <-errors
	}
	if len(allAddrs) == 0 {
		return nil, nil, nil, fmt.Errorf("No IPv4/6 addresses found")
	}

	// Choose primary/secondary addresses
	resolvedAddrs := []net.IP{}
	var primaryAddr *net.IP
	var secondaryAddr *net.IP
	for addrs := range allAddrs {
		for _, addr := range addrs {
			if len(addr) == net.IPv6len && primaryAddr == nil {
				primaryAddr = &addr
			} else if secondaryAddr == nil {
				secondaryAddr = &addr
			}
			// Collect all resolved addresses for the ValidationRecord
			resolvedAddrs = append(resolvedAddrs, addr)
		}
	}
	if primaryAddr == nil && secondaryAddr == nil {
		// idk how this would happen but belt and bracers
		return nil, nil, resolvedAddrs, fmt.Errorf("No suitable addresses found")
	}

	// Start TCP connections to addresses
	conns := make(chan *net.Conn, 1)
	var usedAddr *net.IP
	errors = make(chan error, 2)
	cancel := make(chan struct{}, 1)
	attempts := 0
	if primaryAddr != nil {
		attempts++
		go dialAddr(primaryAddr, port, timeout, cancel, errors, conns, usedAddr)
	}
	if secondaryAddr != nil {
		attempts++
		go func() {
			if primaryAddr != nil {
				// If we are dialing both v6 and v4 give v6 a slight headstart
				time.Sleep(time.Millisecond * 100)
			}
			dialAddr(secondaryAddr, port, timeout, cancel, errors, conns, usedAddr)
		}()
	}

	// Wait for connection or errors
	var otherErr error
	for {
		select {
		case conn := <-conns:
			// Race is over, cancel other attempt and return connection, used address,
			// and all other resolved addresses
			cancel <- struct{}{}
			return conn, *usedAddr, resolvedAddrs, nil
		case err := <-errors:
			// If two attempts were made wait until two errors are returned before failing
			// out of the process. If only one attempt was made then fail immediately
			if otherErr != nil && attempts == 2 {
				return nil, nil, resolvedAddrs, fmt.Errorf("Both connection attempts failed, [%s], [%s]", err, otherErr)
			} else if attempts == 1 {
				return nil, nil, resolvedAddrs, err
			} else {
				otherErr = err
			}
		}
	}
}
