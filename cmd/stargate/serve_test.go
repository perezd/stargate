package main

import "testing"

func TestIsLoopbackAddr(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:9099", true},
		{"127.0.0.1:0", true},
		{"[::1]:9099", true},
		{"localhost:9099", false}, // hostnames rejected, only literal IPs
		{"0.0.0.0:9099", false},
		{":9099", false},
		{"192.168.1.1:9099", false},
		{"10.0.0.1:9099", false},
		{"invalid", false},
	}
	for _, tc := range tests {
		t.Run(tc.addr, func(t *testing.T) {
			got := isLoopbackAddr(tc.addr)
			if got != tc.want {
				t.Errorf("isLoopbackAddr(%q) = %v, want %v", tc.addr, got, tc.want)
			}
		})
	}
}
