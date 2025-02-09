package log

import (
	"fmt"
	"log"
	"log/syslog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jmhodges/clock"
	"github.com/zzma/boulder/test"
)

const stdoutLevel = 7
const syslogLevel = 7

func setup(t *testing.T) *impl {
	// Write all logs to UDP on a high port so as to not bother the system
	// which is running the test
	writer, err := syslog.Dial("udp", "127.0.0.1:65530", syslog.LOG_INFO|syslog.LOG_LOCAL0, "")
	test.AssertNotError(t, err, "Could not construct syslog object")

	logger, err := New(writer, stdoutLevel, syslogLevel)
	test.AssertNotError(t, err, "Could not construct syslog object")
	impl, ok := logger.(*impl)
	if !ok {
		t.Fatalf("Wrong type returned from New: %T", logger)
	}
	return impl
}

func TestConstruction(t *testing.T) {
	t.Parallel()
	_ = setup(t)
}

func TestSingleton(t *testing.T) {
	t.Parallel()
	log1 := Get()
	test.AssertNotNil(t, log1, "Logger shouldn't be nil")

	log2 := Get()
	test.AssertEquals(t, log1, log2)

	audit := setup(t)

	// Should not work
	err := Set(audit)
	test.AssertError(t, err, "Can't re-set")

	// Verify no change
	log4 := Get()

	// Verify that log4 != log3
	test.AssertNotEquals(t, log4, audit)

	// Verify that log4 == log2 == log1
	test.AssertEquals(t, log4, log2)
	test.AssertEquals(t, log4, log1)
}

func TestConstructionNil(t *testing.T) {
	t.Parallel()
	_, err := New(nil, stdoutLevel, syslogLevel)
	test.AssertError(t, err, "Nil shouldn't be permitted.")
}

func TestEmit(t *testing.T) {
	t.Parallel()
	log := setup(t)

	log.AuditInfo("test message")
}

func TestEmitEmpty(t *testing.T) {
	t.Parallel()
	log := setup(t)

	log.AuditInfo("")
}

func ExampleLogger() {
	// Write all logs to UDP on a high port so as to not bother the system
	// which is running the test
	writer, err := syslog.Dial("udp", "127.0.0.1:65530", syslog.LOG_INFO|syslog.LOG_LOCAL0, "")
	if err != nil {
		log.Fatal(err)
	}

	logger, err := New(writer, stdoutLevel, syslogLevel)
	if err != nil {
		log.Fatal(err)
	}
	impl, ok := logger.(*impl)
	if !ok {
		log.Fatalf("Wrong type returned from New: %T", logger)
	}

	bw, ok := impl.w.(*bothWriter)
	if !ok {
		log.Fatalf("Wrong type of impl's writer: %T\n", impl.w)
	}
	bw.clk = clock.NewFake()
	impl.AuditErr("Error Audit")
	impl.Warning("Warning Audit")
	// Output:
	// [31m[1mE000000 log.test [AUDIT] Error Audit[0m
	// [33mW000000 log.test Warning Audit[0m
}

func TestSyslogMethods(t *testing.T) {
	t.Parallel()
	impl := setup(t)

	impl.AuditInfo("audit-logger_test.go: audit-info")
	impl.AuditErr("audit-logger_test.go: audit-err")
	impl.Debug("audit-logger_test.go: debug")
	impl.Err("audit-logger_test.go: err")
	impl.Info("audit-logger_test.go: info")
	impl.Warning("audit-logger_test.go: warning")
	impl.AuditInfof("audit-logger_test.go: %s", "audit-info")
	impl.AuditErrf("audit-logger_test.go: %s", "audit-err")
	impl.Debugf("audit-logger_test.go: %s", "debug")
	impl.Errf("audit-logger_test.go: %s", "err")
	impl.Infof("audit-logger_test.go: %s", "info")
	impl.Warningf("audit-logger_test.go: %s", "warning")
}

func TestPanic(t *testing.T) {
	t.Parallel()
	impl := setup(t)
	defer impl.AuditPanic()
	panic("Test panic")
	// Can't assert anything here or golint gets angry
}

func TestAuditObject(t *testing.T) {
	t.Parallel()

	log := NewMock()

	// Test a simple object
	log.AuditObject("Prefix", "String")
	if len(log.GetAllMatching("[AUDIT]")) != 1 {
		t.Errorf("Failed to audit log simple object")
	}

	// Test a system object
	log.Clear()
	log.AuditObject("Prefix", t)
	if len(log.GetAllMatching("[AUDIT]")) != 1 {
		t.Errorf("Failed to audit log system object")
	}

	// Test a complex object
	log.Clear()
	type validObj struct {
		A string
		B string
	}
	var valid = validObj{A: "B", B: "C"}
	log.AuditObject("Prefix", valid)
	if len(log.GetAllMatching("[AUDIT]")) != 1 {
		t.Errorf("Failed to audit log complex object")
	}

	// Test logging an unserializable object
	log.Clear()
	type invalidObj struct {
		A chan string
	}

	var invalid = invalidObj{A: make(chan string)}
	log.AuditObject("Prefix", invalid)
	if len(log.GetAllMatching("[AUDIT]")) != 1 {
		t.Errorf("Failed to audit log unserializable object %v", log.GetAllMatching("[AUDIT]"))
	}
}

func TestTransmission(t *testing.T) {
	t.Parallel()

	l, err := newUDPListener("127.0.0.1:0")
	test.AssertNotError(t, err, "Failed to open log server")
	defer func() {
		err = l.Close()
		test.AssertNotError(t, err, "listener.Close returned error")
	}()

	fmt.Printf("Going to %s\n", l.LocalAddr().String())
	writer, err := syslog.Dial("udp", l.LocalAddr().String(), syslog.LOG_INFO|syslog.LOG_LOCAL0, "")
	test.AssertNotError(t, err, "Failed to find connect to log server")

	impl, err := New(writer, stdoutLevel, syslogLevel)
	test.AssertNotError(t, err, "Failed to construct audit logger")

	data := make([]byte, 128)

	impl.AuditInfo("audit-logger_test.go: audit-info")
	_, _, err = l.ReadFrom(data)
	test.AssertNotError(t, err, "Failed to find packet")

	impl.AuditErr("audit-logger_test.go: audit-err")
	_, _, err = l.ReadFrom(data)
	test.AssertNotError(t, err, "Failed to find packet")

	impl.Debug("audit-logger_test.go: debug")
	_, _, err = l.ReadFrom(data)
	test.AssertNotError(t, err, "Failed to find packet")

	impl.Err("audit-logger_test.go: err")
	_, _, err = l.ReadFrom(data)
	test.AssertNotError(t, err, "Failed to find packet")

	impl.Info("audit-logger_test.go: info")
	_, _, err = l.ReadFrom(data)
	test.AssertNotError(t, err, "Failed to find packet")

	impl.Warning("audit-logger_test.go: warning")
	_, _, err = l.ReadFrom(data)
	test.AssertNotError(t, err, "Failed to find packet")

	impl.AuditInfof("audit-logger_test.go: %s", "audit-info")
	_, _, err = l.ReadFrom(data)
	test.AssertNotError(t, err, "Failed to find packet")

	impl.AuditErrf("audit-logger_test.go: %s", "audit-err")
	_, _, err = l.ReadFrom(data)
	test.AssertNotError(t, err, "Failed to find packet")

	impl.Debugf("audit-logger_test.go: %s", "debug")
	_, _, err = l.ReadFrom(data)
	test.AssertNotError(t, err, "Failed to find packet")

	impl.Errf("audit-logger_test.go: %s", "err")
	_, _, err = l.ReadFrom(data)
	test.AssertNotError(t, err, "Failed to find packet")

	impl.Infof("audit-logger_test.go: %s", "info")
	_, _, err = l.ReadFrom(data)
	test.AssertNotError(t, err, "Failed to find packet")

	impl.Warningf("audit-logger_test.go: %s", "warning")
	_, _, err = l.ReadFrom(data)
	test.AssertNotError(t, err, "Failed to find packet")
}

func TestSyslogLevels(t *testing.T) {
	t.Parallel()

	l, err := newUDPListener("127.0.0.1:0")
	test.AssertNotError(t, err, "Failed to open log server")
	defer func() {
		err = l.Close()
		test.AssertNotError(t, err, "listener.Close returned error")
	}()

	fmt.Printf("Going to %s\n", l.LocalAddr().String())
	writer, err := syslog.Dial("udp", l.LocalAddr().String(), syslog.LOG_INFO|syslog.LOG_LOCAL0, "")
	test.AssertNotError(t, err, "Failed to find connect to log server")

	// create a logger with syslog level debug
	impl, err := New(writer, stdoutLevel, int(syslog.LOG_DEBUG))
	test.AssertNotError(t, err, "Failed to construct audit logger")

	data := make([]byte, 512)

	// debug messages should be sent to the logger
	impl.Debug("log_test.go: debug")
	_, _, err = l.ReadFrom(data)
	test.AssertNotError(t, err, "Failed to find packet")
	test.Assert(t, strings.Contains(string(data), "log_test.go: debug"), "Failed to find log message")

	// create a logger with syslog level info
	impl, err = New(writer, stdoutLevel, int(syslog.LOG_INFO))
	test.AssertNotError(t, err, "Failed to construct audit logger")

	// debug messages should not be sent to the logger
	impl.Debug("log_test.go: debug")
	n, _, err := l.ReadFrom(data)
	if n != 0 && err == nil {
		t.Error("Failed to withhold debug log message")
	}
}

func newUDPListener(addr string) (*net.UDPConn, error) {
	l, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}
	err = l.SetDeadline(time.Now().Add(100 * time.Millisecond))
	if err != nil {
		return nil, err
	}
	err = l.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if err != nil {
		return nil, err
	}
	err = l.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
	if err != nil {
		return nil, err
	}
	return l.(*net.UDPConn), nil
}
