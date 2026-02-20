package main

import (
	"io"
	"github.com/jftuga/mtool/v2/internal/netcmd"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestNetCheck(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	t.Run("open port", func(t *testing.T) {
		dur, err := netcmd.NetCheck(ln.Addr().String(), 2*time.Second)
		if err != nil {
			t.Errorf("expected open port, got error: %v", err)
		}
		if dur <= 0 {
			t.Error("expected positive duration")
		}
	})

	t.Run("closed port", func(t *testing.T) {
		_, err := netcmd.NetCheck("127.0.0.1:1", 500*time.Millisecond)
		if err == nil {
			t.Error("expected error for closed port")
		}
	})
}

func TestNetScan(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	openPorts, err := netcmd.NetScan("127.0.0.1", port, port, 2*time.Second)
	if err != nil {
		t.Fatalf("NetScan: %v", err)
	}
	if len(openPorts) != 1 || openPorts[0] != port {
		t.Errorf("expected [%d], got %v", port, openPorts)
	}
}

func TestNetWait(t *testing.T) {
	t.Run("port opens", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		err = netcmd.NetWait(ln.Addr().String(), 2*time.Second)
		if err != nil {
			t.Errorf("expected success, got: %v", err)
		}
	})

	t.Run("timeout", func(t *testing.T) {
		err := netcmd.NetWait("127.0.0.1:1", 1*time.Second)
		if err == nil {
			t.Error("expected timeout error")
		}
	})
}

func TestNetEcho(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()
	defer ln.Close()

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	defer conn.Close()

	msg := "hello echo\n"
	conn.Write([]byte(msg))
	conn.(*net.TCPConn).CloseWrite()

	buf, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("reading: %v", err)
	}
	if string(buf) != msg {
		t.Errorf("expected %q, got %q", msg, string(buf))
	}
}
