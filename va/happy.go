package va

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/golang.org/x/net/context"
	"github.com/letsencrypt/boulder/bdns"
)

type resolveResult struct {
	error
	addrs []net.IP
}

type dialResult struct {
	net.Conn
	error
	primary bool
}

// parallelResolve looks up both v4 and v6 IP addresses for a hostname
// concurrently and returns a flat slice containing all the addresses
// found
func parallelResolve(ctx context.Context, hostname string, resolver bdns.DNSResolver) ([]net.IP, error) {
	lookups := []func(context.Context, string) ([]net.IP, error){
		resolver.LookupA,
		resolver.LookupAAAA,
	}
	results := make(chan resolveResult)
	for _, lookuper := range lookups {
		go func(l func(context.Context, string) ([]net.IP, error)) {
			addrs, err := l(ctx, hostname)
			results <- resolveResult{err, addrs}
		}(lookuper)
	}
	allAddrs := []net.IP{}
	errors := []string{}
	for nracers := len(lookups); nracers > 0; nracers-- {
		res := <-results
		if res.error == nil {
			for _, addr := range res.addrs {
				allAddrs = append(allAddrs, addr)
			}
		} else {
			errors = append(errors, res.error.Error())
		}
	}
	if len(allAddrs) == 0 {
		if len(errors) != 0 {
			return nil, fmt.Errorf("Couldn't resolve any addresses, resolution failed: %s", strings.Join(errors, ", "))
		} else {
			return nil, fmt.Errorf("Couldn't resolve any addresses")
		}
	}
	return allAddrs, nil
}

// dialAddr does the actual dialing of a network address and returns
// a net.Conn or error via the provided channels
func dialAddr(addr net.IP, port int, timer *time.Timer, timeout time.Duration, cancel chan struct{}, results chan dialResult) {
	if timer != nil {
		select {
		case <-timer.C:
		case <-cancel:
			return
		}
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(addr.String(), strconv.Itoa(port)), timeout)
	select {
	case results <- dialResult{conn, err, timer == nil}:
		// won!
	case <-cancel:
		if conn != nil {
			conn.Close()
		}
	}
}

func selectAddrs(addrs []net.IP) (net.IP, net.IP, error) {
	var primary net.IP
	var secondary net.IP
	for _, addr := range addrs {
		if primary == nil && addr.To16() != nil && addr.To4() == nil {
			primary = addr
		} else if secondary == nil && addr.To4() != nil {
			secondary = addr
		}
	}
	if primary == nil && secondary == nil {
		// idk how this would happen but belt and bracers...
		return nil, nil, fmt.Errorf("No suitable addresses found")
	}
	return primary, secondary, nil
}

// DualStackDial performs a Happy-Eyeballs (ish) attempt to connect to a host
// over both IPv4 and IPv6. Since this type of lookup is only used for resolution
// during validation it also returns all resolved addresses for the host and the
// specific IP address that the returned net.Conn is for. (Most of the parallel
// dialing stuff is cribbed from go/src/net/dial.go)
func DualStackDial(hostname string, port int, timeout time.Duration, resolver bdns.DNSResolver) (net.Conn, net.IP, []net.IP, error) {
	finalDeadline := time.Now().Add(timeout)
	ctx, ctxCancel := context.WithDeadline(context.Background(), finalDeadline)
	defer ctxCancel()
	resolvedAddrs, err := parallelResolve(ctx, hostname, resolver)
	if err != nil {
		return nil, nil, nil, err
	}

	// Choose primary/secondary addresses
	primaryAddr, secondaryAddr, err := selectAddrs(resolvedAddrs)
	if err != nil {
		return nil, nil, nil, err
	}

	// bypass parallel futzing if only one was found
	if primaryAddr == nil || secondaryAddr == nil {
		var usedAddr net.IP
		if primaryAddr != nil {
			usedAddr = primaryAddr
		} else {
			usedAddr = secondaryAddr
		}
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(usedAddr.String(), strconv.Itoa(port)), timeout)
		return conn, usedAddr, resolvedAddrs, err
	}

	// Start TCP connections to addresses
	results := make(chan dialResult)
	cancel := make(chan struct{})
	defer close(cancel)
	dialTimeout := finalDeadline.Sub(time.Now())
	go dialAddr(primaryAddr, port, nil, dialTimeout, cancel, results)
	fallbackTimer := time.NewTimer(time.Millisecond * 100)
	go dialAddr(secondaryAddr, port, fallbackTimer, dialTimeout-(time.Millisecond*100), cancel, results)

	// Wait for connection or errors
	var primaryErr error
	for nracers := 2; nracers > 0; nracers-- {
		res := <-results
		// If we're still waiting for a connection, then hasten the delay.
		// Otherwise, disable the Timer and let cancel take over.
		if fallbackTimer.Stop() && res.error != nil {
			fallbackTimer.Reset(0)
		}
		if res.error == nil {
			var usedAddr net.IP
			if res.primary {
				usedAddr = primaryAddr
			} else {
				usedAddr = secondaryAddr
			}
			return res.Conn, usedAddr, resolvedAddrs, nil
		}
		if res.primary {
			primaryErr = res.error
		}
	}
	return nil, primaryAddr, resolvedAddrs, primaryErr
}
