// demo run's reading of gateway.log: each read continues where the last one
// ended, an over-long line is skipped rather than ending the start, and later
// admission changes are reported. Also the start-up refusals of a busy
// address or another port offset, and the bound on a child's log.

package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGatewayLogContinuesAndSkipsLongLines(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "gateway.log")
	earlier := `{"msg":"protected admission","admission":"ready"}` + "\n"
	long := strings.Repeat("x", logLine+10) + "\n"
	start := `{"msg":"protected admission","admission":"bootstrap_locked"}` + "\n" + `{"msg":"protected ad`
	if err := os.WriteFile(path, []byte(earlier+long+start), 0o600); err != nil {
		t.Fatal(err)
	}
	log := &gatewayLog{path: path, offset: int64(len(earlier))}
	events, err := log.next()
	if err != nil || admission(events) != "bootstrap_locked" {
		t.Fatalf("start: %q %v", admission(events), err)
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	file.WriteString(`mission unavailable","reason":"generation_expired"}` + "\n")
	file.Close()
	events, err = log.next()
	if err != nil || admission(events) != "" {
		t.Fatalf("second read repeated the start: %v %v", events, err)
	}
	if changes := admissionChanges(events); len(changes) != 1 || !strings.Contains(changes[0], "generation_expired") {
		t.Fatalf("changes %q", changes)
	}
}

func TestCheckFreeRefusesABoundAddress(t *testing.T) {
	t.Parallel()
	// 127.0.0.2 avoids ephemeral port collisions with parallel tests on 127.0.0.1.
	listener, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := checkFree([]string{address}); err == nil {
		t.Fatal("an address in use counted as free")
	}
	listener.Close()
	if err := checkFree([]string{address}); err != nil {
		t.Fatalf("a closed address: %v", err)
	}
}

func TestCheckOffsetRefusesAnotherOffset(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write := func(admin string) {
		if err := os.WriteFile(filepath.Join(dir, configFile), indented(map[string]any{"gateway": map[string]string{"admin_listen": admin}}), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(adminListen)
	if err := checkOffset(dir); err != nil {
		t.Fatalf("same offset: %v", err)
	}
	write("127.0.0.1:1")
	if err := checkOffset(dir); err == nil || !strings.Contains(err.Error(), "EAT_PORT_OFFSET") {
		t.Fatalf("another offset: %v", err)
	}
}

func TestChildLogIsBounded(t *testing.T) {
	t.Parallel()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "child.log"), make([]byte, logLimit), 0o600); err != nil {
		t.Fatal(err)
	}
	c := newChildren(dir, 1)
	start, err := c.start("child", binary, "-test.run=^$")
	if err != nil {
		t.Fatal(err)
	}
	<-c.exited
	c.received()
	previous, err := os.Stat(filepath.Join(dir, "child.previous.log"))
	if err != nil || previous.Size() != logLimit || start != 0 {
		t.Fatalf("the full log was not moved aside: %v, start %d", err, start)
	}
}
