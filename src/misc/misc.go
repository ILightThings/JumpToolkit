package misc

import (
	"math/big"
	"net"
)

func IP4toInt(IPv4Address string) int64 {
	ip := net.ParseIP(IPv4Address)
	IPv4Int := big.NewInt(0)
	IPv4Int.SetBytes(ip.To4())
	return IPv4Int.Int64()
}

func TestingSecrets() {}
