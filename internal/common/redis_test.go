package common

import (
	"bufio"
	"context"
	"net"
	"testing"
	"time"

	"lumid_identity/internal/config"
)

// fakeRedis answers every RESP command with +PONG — enough for PING.
func fakeRedis(t *testing.T, ln net.Listener) {
	t.Helper()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					// A command is "*<n>" followed by n bulk strings; answer once per command.
					if len(line) > 0 && line[0] == '*' {
						if _, err := c.Write([]byte("+PONG\r\n")); err != nil {
							return
						}
					}
				}
			}(conn)
		}
	}()
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// Redis down at startup must not be fatal, and the SAME client must work once Redis appears
// (go-redis reconnects lazily) — no process restart needed.
func TestOpenRedisDownAtStartupThenRecovers(t *testing.T) {
	addr := freeAddr(t)
	cfg := &config.Config{}
	cfg.Redis.Addr = addr

	start := time.Now()
	err := OpenRedis(cfg, 1500*time.Millisecond)
	if err == nil {
		t.Fatal("expected an error while nothing listens")
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("OpenRedis waited %v, want it bounded by the wait budget", took)
	}
	if Redis == nil {
		t.Fatal("client must be set even when Redis is unreachable")
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skipf("could not re-bind %s: %v", addr, err)
	}
	defer ln.Close()
	fakeRedis(t, ln)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := Redis.Ping(ctx).Err(); err != nil {
		t.Fatalf("same client should reconnect once Redis is up: %v", err)
	}
}

func TestOpenRedisUpReturnsNil(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	fakeRedis(t, ln)
	cfg := &config.Config{}
	cfg.Redis.Addr = ln.Addr().String()
	if err := OpenRedis(cfg, time.Second); err != nil {
		t.Fatalf("expected nil with Redis up, got %v", err)
	}
}
