package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestHTTPServerHasTimeouts(t *testing.T) {
	server := newHTTPServer(":0", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if server.ReadHeaderTimeout <= 0 {
		t.Fatal("ReadHeaderTimeout is not configured")
	}
	if server.ReadTimeout <= 0 {
		t.Fatal("ReadTimeout is not configured")
	}
	if server.WriteTimeout <= 0 {
		t.Fatal("WriteTimeout is not configured")
	}
	if server.IdleTimeout <= 0 {
		t.Fatal("IdleTimeout is not configured")
	}
}

func TestServeDrainsActiveRequestOnCancellation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	started := make(chan struct{})
	release := make(chan struct{})
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		_, _ = io.WriteString(w, "ok")
	})
	server := newHTTPServer(listener.Addr().String(), handler)
	shutdownStarted := make(chan struct{})
	server.RegisterOnShutdown(func() { close(shutdownStarted) })
	ctx, cancel := context.WithCancel(t.Context())
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- serve(ctx, server, listener)
	}()

	requestDone := make(chan error, 1)
	go func() {
		client := &http.Client{Timeout: time.Second}
		resp, err := client.Get("http://" + listener.Addr().String())
		if err == nil {
			_, err = io.ReadAll(resp.Body)
			_ = resp.Body.Close()
		}
		requestDone <- err
	}()
	<-started
	cancel()
	<-shutdownStarted

	select {
	case err := <-serveDone:
		t.Fatalf("server stopped before active request drained: %v", err)
	default:
	}

	close(release)
	if err := <-requestDone; err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if err := <-serveDone; err != nil {
		t.Fatalf("serve: %v", err)
	}
}
