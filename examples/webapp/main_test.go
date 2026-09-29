package main

import (
	"strings"
	"testing"
)

func TestBrowserBaseURL(t *testing.T) {
	if defaultListenAddr != "localhost:8443" {
		t.Fatalf("default listen address = %q, want loopback", defaultListenAddr)
	}

	tests := []struct {
		name    string
		addr    string
		useTLS  bool
		want    string
		wantErr string
	}{
		{name: "default", addr: defaultListenAddr, useTLS: true, want: "https://localhost:8443"},
		{name: "legacy wildcard", addr: ":8443", useTLS: true, want: "https://localhost:8443"},
		{name: "IPv4", addr: "127.0.0.1:8080", want: "http://localhost:8080"},
		{name: "IPv6", addr: "[::1]:8080", useTLS: true, want: "https://localhost:8080"},
		{name: "missing port", addr: "localhost", wantErr: "missing port"},
		{name: "unbracketed IPv6", addr: "::1:8080", wantErr: "too many colons"},
		{name: "empty port", addr: "localhost:", wantErr: "port must be an integer"},
		{name: "dynamic port", addr: "localhost:0", wantErr: "port must be an integer"},
		{name: "invalid port", addr: "localhost:http", wantErr: "port must be an integer"},
		{name: "out of range port", addr: "localhost:65536", wantErr: "port must be an integer"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := browserBaseURL(tt.addr, tt.useTLS)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("browserBaseURL(%q) error = %v, want %q", tt.addr, err, tt.wantErr)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("browserBaseURL(%q) = %q, %v; want %q", tt.addr, got, err, tt.want)
			}
		})
	}
}
