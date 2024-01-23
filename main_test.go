package main

import (
	"errors"
	"net"
	"strconv"
	"testing"

	"github.com/matryer/is"
)

type MockDialer struct{}

func (m *MockDialer) Dial(network, address string) (net.Conn, error) {
	_, client := net.Pipe()
	allowedPorts := []int{80, 443, 1053}

	_, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return client, err
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return client, err
	}

	for _, p := range allowedPorts {
		if port == p {
			return client, nil
		}
	}

	return client, errors.New("closed port")
}

func TestScanPort(t *testing.T) {
	tt := []struct {
		port int
		out  bool
	}{
		{
			port: 80,
			out:  true,
		},
		{
			port: 2,
			out:  false,
		},
	}

	for _, tc := range tt {
		_, actual := ScanPort(&MockDialer{}, "test", tc.port)
		if actual != tc.out {
			t.Fatalf("test failed for port: %d", tc.port)
		}
	}
}

// Tests all ports (16bit ints) and returns which ones are open
func TestVanillaScan(t *testing.T) {
	is := is.New(t)
	expected := []int{80, 443, 1053}
	actual := VanillaScan(&MockDialer{}, "test")
	is.Equal(expected, actual)
}

func TestStringFormat(t *testing.T) {
	is := is.New(t)
	expected := `
HOST: test
Open ports:
  - 1
  - 2
  - 3
`
	actual := PrintAllowedPorts("test", []int{1, 2, 3})
	is.Equal(expected, actual)
}
