package runzero

import "net"

func IsPrivateIPAddress(ips string) bool {
	ip := net.ParseIP(ips)
	if ip == nil {
		return false
	}
	return ip.IsPrivate()
}

func IsPrivateCIDR(cidr string) bool {
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return ip.IsPrivate()
}

func IsPublicIPAddress(ips string) bool {
	return !IsPrivateIPAddress(ips)
}

func IsPublicCIDR(cidr string) bool {
	return !IsPrivateCIDR(cidr)
}
