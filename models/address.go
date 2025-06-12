package models

import (
	"net"
	"regexp"
	"strings"
)

type AddressObject struct {
	Name        string `json:"name" yaml:"name"`
	IPNetmask   string `json:"ip_netmask,omitempty" yaml:"ip_netmask,omitempty"`
	IPRange     string `json:"ip_range,omitempty" yaml:"ip_range,omitempty"`
	FQDN        string `json:"fqdn,omitempty" yaml:"fqdn,omitempty"`
	Scope       string `json:"scope" yaml:"scope"`
	DeviceGroup string `json:"device_group,omitempty" yaml:"device_group,omitempty"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

type AddressReference struct {
	ObjectName   string `json:"object_name" yaml:"object_name"`
	SourceType   string `json:"source_type" yaml:"source_type"`
	SourceName   string `json:"source_name" yaml:"source_name"`
	Context      string `json:"context" yaml:"context"`
	DeviceGroup  string `json:"device_group,omitempty" yaml:"device_group,omitempty"`
	LineNumber   int    `json:"line_number" yaml:"line_number"`
}

type RedundantAddressPair struct {
	SourceAddress    string   `json:"source_address" yaml:"source_address"`
	DuplicateAddress string   `json:"duplicate_address" yaml:"duplicate_address"`
	IPValue          string   `json:"ip_value" yaml:"ip_value"`
	SourceScope      string   `json:"source_scope" yaml:"source_scope"`
	DuplicateScope   string   `json:"duplicate_scope" yaml:"duplicate_scope"`
	DeviceGroups     []string `json:"device_groups" yaml:"device_groups"`
}

var (
	ipv4Regex = regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:/(?:3[0-2]|[1-2]?[0-9]))?$`)
	ipv6Regex = regexp.MustCompile(`^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}(?:/(?:12[0-8]|1[0-1][0-9]|[1-9]?[0-9]))?$|^::1(?:/(?:12[0-8]|1[0-1][0-9]|[1-9]?[0-9]))?$`)
)

func (a *AddressObject) GetIP() string {
	if a.IPNetmask != "" {
		return a.IPNetmask
	}
	if a.IPRange != "" {
		parts := strings.Split(a.IPRange, "-")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	return ""
}

func (a *AddressObject) GetNetworkCIDR() (*net.IPNet, error) {
	ip := a.GetIP()
	if ip == "" {
		return nil, nil
	}
	
	if !strings.Contains(ip, "/") {
		ip += "/32"
	}
	
	_, ipNet, err := net.ParseCIDR(ip)
	return ipNet, err
}

func (a *AddressObject) IsRedundantWith(other *AddressObject) bool {
	if a.GetIP() == "" || other.GetIP() == "" {
		return false
	}
	
	net1, err1 := a.GetNetworkCIDR()
	net2, err2 := other.GetNetworkCIDR()
	
	if err1 != nil || err2 != nil {
		return false
	}
	
	return net1.String() == net2.String()
}

func ValidateIPAddress(ip string) bool {
	if ip == "" {
		return false
	}
	
	if ipv4Regex.MatchString(ip) {
		return true
	}
	
	if ipv6Regex.MatchString(ip) {
		return true
	}
	
	_, _, err := net.ParseCIDR(ip)
	return err == nil
}

func NormalizeIPAddress(ip string) string {
	if ip == "" {
		return ""
	}
	
	if !strings.Contains(ip, "/") {
		if net.ParseIP(ip) != nil {
			return ip + "/32"
		}
	}
	
	_, ipNet, err := net.ParseCIDR(ip)
	if err == nil {
		return ipNet.String()
	}
	
	return ip
}