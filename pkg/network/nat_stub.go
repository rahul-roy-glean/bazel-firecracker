//go:build !linux
// +build !linux

package network

import (
	"fmt"
	"net"

	"github.com/sirupsen/logrus"
)

// NATNetwork is a stub on non-Linux platforms.
type NATNetwork struct{}

// NATConfig holds configuration for NAT network setup.
type NATConfig struct {
	BridgeName    string
	Subnet        string
	ExternalIface string
	Logger        *logrus.Logger
}

// TapDevice represents a TAP network device.
type TapDevice struct {
	Name       string
	IP         net.IP
	Gateway    net.IP
	Subnet     *net.IPNet
	MAC        string
	BridgeName string
}

// NetworkConfig holds network configuration to inject into microVM.
type NetworkConfig struct {
	IP        string `json:"ip"`
	Gateway   string `json:"gateway"`
	Netmask   string `json:"netmask"`
	DNS       string `json:"dns"`
	Interface string `json:"interface"`
	MAC       string `json:"mac"`
}

func NewNATNetwork(_ NATConfig) (*NATNetwork, error) {
	return nil, fmt.Errorf("NAT networking is only supported on Linux")
}

func (n *NATNetwork) Setup() error {
	return fmt.Errorf("NAT networking is only supported on Linux")
}

func (n *NATNetwork) Cleanup() error {
	return nil
}

func (n *NATNetwork) CreateTapForVM(_ string) (*TapDevice, error) {
	return nil, fmt.Errorf("TAP devices are only supported on Linux")
}

func (n *NATNetwork) ReleaseTap(_ string) error {
	return nil
}

func (n *NATNetwork) GetGateway() net.IP {
	return nil
}

func (n *NATNetwork) GetSubnet() *net.IPNet {
	return nil
}

func (n *NATNetwork) GetBridgeName() string {
	return ""
}

func (n *NATNetwork) BlockEgress(_ net.IP) error {
	return fmt.Errorf("NAT networking is only supported on Linux")
}

func (n *NATNetwork) UnblockEgress(_ net.IP) error {
	return fmt.Errorf("NAT networking is only supported on Linux")
}

func (t *TapDevice) GetNetworkConfig() NetworkConfig {
	return NetworkConfig{}
}
