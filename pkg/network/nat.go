//go:build linux
// +build linux

package network

import (
	"fmt"
	"net"
	"os/exec"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

// NATNetwork manages NAT networking for microVMs
type NATNetwork struct {
	bridgeName    string
	subnet        *net.IPNet
	gateway       net.IP
	allocatedIPs  map[string]net.IP
	nextIPOffset  uint32
	externalIface string
	mu            sync.Mutex
	logger        *logrus.Entry
}

// NATConfig holds configuration for NAT network setup
type NATConfig struct {
	BridgeName    string
	Subnet        string // CIDR notation, e.g., "172.16.0.0/24"
	ExternalIface string // External interface for NAT, e.g., "eth0"
	Logger        *logrus.Logger
}

// NewNATNetwork creates a new NAT network manager
func NewNATNetwork(cfg NATConfig) (*NATNetwork, error) {
	_, subnet, err := net.ParseCIDR(cfg.Subnet)
	if err != nil {
		return nil, fmt.Errorf("invalid subnet CIDR: %w", err)
	}

	gateway := incrementIP(subnet.IP, 1)

	logger := cfg.Logger
	if logger == nil {
		logger = logrus.New()
	}

	return &NATNetwork{
		bridgeName:    cfg.BridgeName,
		subnet:        subnet,
		gateway:       gateway,
		allocatedIPs:  make(map[string]net.IP),
		nextIPOffset:  2, // Start at .2, .1 is gateway
		externalIface: cfg.ExternalIface,
		logger:        logger.WithField("component", "nat-network"),
	}, nil
}

// Setup initializes the bridge and NAT rules
func (n *NATNetwork) Setup() error {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.logger.WithFields(logrus.Fields{
		"bridge":    n.bridgeName,
		"subnet":    n.subnet.String(),
		"gateway":   n.gateway.String(),
		"ext_iface": n.externalIface,
	}).Info("Setting up NAT network")

	// Create bridge
	if err := n.createBridge(); err != nil {
		return fmt.Errorf("failed to create bridge: %w", err)
	}

	// Setup NAT rules
	if err := n.setupNAT(); err != nil {
		return fmt.Errorf("failed to setup NAT: %w", err)
	}

	return nil
}

// createBridge creates the bridge interface
func (n *NATNetwork) createBridge() error {
	// Check if bridge already exists
	link, err := netlink.LinkByName(n.bridgeName)
	if err == nil {
		n.logger.WithField("bridge", n.bridgeName).Debug("Bridge already exists")
		// Ensure it's up
		return netlink.LinkSetUp(link)
	}

	// Create new bridge
	bridge := &netlink.Bridge{
		LinkAttrs: netlink.LinkAttrs{
			Name: n.bridgeName,
		},
	}

	if err := netlink.LinkAdd(bridge); err != nil {
		return fmt.Errorf("failed to add bridge: %w", err)
	}

	// Get the link again to get full attributes
	link, err = netlink.LinkByName(n.bridgeName)
	if err != nil {
		return fmt.Errorf("failed to get bridge link: %w", err)
	}

	// Add IP address to bridge
	ones, _ := n.subnet.Mask.Size()
	addr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   n.gateway,
			Mask: net.CIDRMask(ones, 32),
		},
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		// Ignore "file exists" error
		if err.Error() != "file exists" {
			return fmt.Errorf("failed to add address to bridge: %w", err)
		}
	}

	// Bring bridge up
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to bring up bridge: %w", err)
	}

	n.logger.WithField("bridge", n.bridgeName).Info("Bridge created successfully")
	return nil
}

// setupNAT configures iptables NAT rules
func (n *NATNetwork) setupNAT() error {
	subnetCIDR := n.subnet.String()

	// Enable IP forwarding (also done in startup script, but ensure it's set)
	if err := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run(); err != nil {
		n.logger.WithError(err).Warn("Failed to enable IP forwarding via sysctl")
	}

	// Add MASQUERADE rule for outbound NAT
	masqueradeRule := []string{
		"-t", "nat", "-C", "POSTROUTING",
		"-s", subnetCIDR,
		"-o", n.externalIface,
		"-j", "MASQUERADE",
	}
	if err := exec.Command("iptables", masqueradeRule...).Run(); err != nil {
		// Rule doesn't exist, add it
		addRule := []string{
			"-t", "nat", "-A", "POSTROUTING",
			"-s", subnetCIDR,
			"-o", n.externalIface,
			"-j", "MASQUERADE",
		}
		if err := exec.Command("iptables", addRule...).Run(); err != nil {
			return fmt.Errorf("failed to add MASQUERADE rule: %w", err)
		}
	}

	// Add FORWARD rules
	forwardOutRule := []string{
		"-C", "FORWARD",
		"-i", n.bridgeName,
		"-o", n.externalIface,
		"-j", "ACCEPT",
	}
	if err := exec.Command("iptables", forwardOutRule...).Run(); err != nil {
		addRule := []string{
			"-A", "FORWARD",
			"-i", n.bridgeName,
			"-o", n.externalIface,
			"-j", "ACCEPT",
		}
		if err := exec.Command("iptables", addRule...).Run(); err != nil {
			return fmt.Errorf("failed to add forward out rule: %w", err)
		}
	}

	forwardInRule := []string{
		"-C", "FORWARD",
		"-i", n.externalIface,
		"-o", n.bridgeName,
		"-m", "state", "--state", "RELATED,ESTABLISHED",
		"-j", "ACCEPT",
	}
	if err := exec.Command("iptables", forwardInRule...).Run(); err != nil {
		addRule := []string{
			"-A", "FORWARD",
			"-i", n.externalIface,
			"-o", n.bridgeName,
			"-m", "state", "--state", "RELATED,ESTABLISHED",
			"-j", "ACCEPT",
		}
		if err := exec.Command("iptables", addRule...).Run(); err != nil {
			return fmt.Errorf("failed to add forward in rule: %w", err)
		}
	}

	n.logger.Info("NAT rules configured successfully")
	return nil
}

// TapDevice represents a TAP network device
type TapDevice struct {
	Name       string
	IP         net.IP
	Gateway    net.IP
	Subnet     *net.IPNet
	MAC        string
	BridgeName string
}

// CreateTapForVM creates a TAP device for a microVM
func (n *NATNetwork) CreateTapForVM(vmID string) (*TapDevice, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	tapName := fmt.Sprintf("tap-%s", vmID[:8])

	// Allocate IP
	ip, err := n.allocateIP(vmID)
	if err != nil {
		return nil, fmt.Errorf("failed to allocate IP: %w", err)
	}

	// Generate MAC address
	mac := generateMAC(ip)

	n.logger.WithFields(logrus.Fields{
		"tap":   tapName,
		"vm_id": vmID,
		"ip":    ip.String(),
		"mac":   mac,
	}).Debug("Creating TAP device")

	// Create TAP device
	tap := &netlink.Tuntap{
		LinkAttrs: netlink.LinkAttrs{
			Name: tapName,
		},
		Mode:  netlink.TUNTAP_MODE_TAP,
		Flags: netlink.TUNTAP_DEFAULTS,
	}

	if err := netlink.LinkAdd(tap); err != nil {
		n.releaseIP(vmID)
		return nil, fmt.Errorf("failed to create TAP device: %w", err)
	}

	// Get the link
	link, err := netlink.LinkByName(tapName)
	if err != nil {
		n.releaseIP(vmID)
		return nil, fmt.Errorf("failed to get TAP link: %w", err)
	}

	// Attach to bridge
	bridge, err := netlink.LinkByName(n.bridgeName)
	if err != nil {
		netlink.LinkDel(link)
		n.releaseIP(vmID)
		return nil, fmt.Errorf("failed to get bridge: %w", err)
	}

	if err := netlink.LinkSetMaster(link, bridge); err != nil {
		netlink.LinkDel(link)
		n.releaseIP(vmID)
		return nil, fmt.Errorf("failed to attach TAP to bridge: %w", err)
	}

	// Bring TAP up
	if err := netlink.LinkSetUp(link); err != nil {
		netlink.LinkDel(link)
		n.releaseIP(vmID)
		return nil, fmt.Errorf("failed to bring up TAP: %w", err)
	}

	n.logger.WithFields(logrus.Fields{
		"tap": tapName,
		"ip":  ip.String(),
	}).Info("TAP device created successfully")

	return &TapDevice{
		Name:       tapName,
		IP:         ip,
		Gateway:    n.gateway,
		Subnet:     n.subnet,
		MAC:        mac,
		BridgeName: n.bridgeName,
	}, nil
}

// ReleaseTap removes a TAP device and releases its IP
func (n *NATNetwork) ReleaseTap(vmID string) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	tapName := fmt.Sprintf("tap-%s", vmID[:8])

	n.logger.WithFields(logrus.Fields{
		"tap":   tapName,
		"vm_id": vmID,
	}).Debug("Releasing TAP device")

	// Delete TAP device
	link, err := netlink.LinkByName(tapName)
	if err == nil {
		if err := netlink.LinkDel(link); err != nil {
			n.logger.WithError(err).Warn("Failed to delete TAP device")
		}
	}

	// Release IP
	n.releaseIP(vmID)

	return nil
}

// GetOrCreateTapSlot gets or creates a TAP device for a specific slot number.
// This is used for snapshot-based restore where the TAP device name must match
// what was used when creating the snapshot.
//
// Snapshots bind to specific TAP device names - Firecracker does NOT support
// changing the host_dev_name after snapshot load. Therefore, we use slot-based
// TAP names (tap-slot-0, tap-slot-1, etc.) that persist across snapshot/restore cycles.
func (n *NATNetwork) GetOrCreateTapSlot(slot int, vmID string) (*TapDevice, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	tapName := fmt.Sprintf("tap-slot-%d", slot)

	// Allocate IP based on slot (deterministic: slot 0 = .2, slot 1 = .3, etc.)
	slotIP := incrementIP(n.subnet.IP, uint32(slot+2))
	mac := generateMAC(slotIP)

	n.logger.WithFields(logrus.Fields{
		"tap":   tapName,
		"slot":  slot,
		"vm_id": vmID,
		"ip":    slotIP.String(),
		"mac":   mac,
	}).Debug("Getting or creating TAP slot")

	// Check if TAP already exists
	link, err := netlink.LinkByName(tapName)
	if err == nil {
		// TAP exists, ensure it's up and on the bridge
		if err := netlink.LinkSetUp(link); err != nil {
			return nil, fmt.Errorf("failed to bring up existing TAP: %w", err)
		}
		n.logger.WithField("tap", tapName).Debug("Using existing TAP device")
		n.allocatedIPs[vmID] = slotIP
		return &TapDevice{
			Name:       tapName,
			IP:         slotIP,
			Gateway:    n.gateway,
			Subnet:     n.subnet,
			MAC:        mac,
			BridgeName: n.bridgeName,
		}, nil
	}

	// Create new TAP device
	tap := &netlink.Tuntap{
		LinkAttrs: netlink.LinkAttrs{
			Name: tapName,
		},
		Mode:  netlink.TUNTAP_MODE_TAP,
		Flags: netlink.TUNTAP_DEFAULTS,
	}

	if err := netlink.LinkAdd(tap); err != nil {
		return nil, fmt.Errorf("failed to create TAP device: %w", err)
	}

	// Get the link
	link, err = netlink.LinkByName(tapName)
	if err != nil {
		return nil, fmt.Errorf("failed to get TAP link: %w", err)
	}

	// Attach to bridge
	bridge, err := netlink.LinkByName(n.bridgeName)
	if err != nil {
		netlink.LinkDel(link)
		return nil, fmt.Errorf("failed to get bridge: %w", err)
	}

	if err := netlink.LinkSetMaster(link, bridge); err != nil {
		netlink.LinkDel(link)
		return nil, fmt.Errorf("failed to attach TAP to bridge: %w", err)
	}

	// Bring TAP up
	if err := netlink.LinkSetUp(link); err != nil {
		netlink.LinkDel(link)
		return nil, fmt.Errorf("failed to bring up TAP: %w", err)
	}

	n.allocatedIPs[vmID] = slotIP
	n.logger.WithFields(logrus.Fields{
		"tap":  tapName,
		"slot": slot,
		"ip":   slotIP.String(),
	}).Info("TAP slot created successfully")

	return &TapDevice{
		Name:       tapName,
		IP:         slotIP,
		Gateway:    n.gateway,
		Subnet:     n.subnet,
		MAC:        mac,
		BridgeName: n.bridgeName,
	}, nil
}

// ReleaseTapSlot releases a TAP slot but does NOT delete the TAP device.
// The TAP device persists for reuse with future snapshot restores.
func (n *NATNetwork) ReleaseTapSlot(slot int, vmID string) {
	n.mu.Lock()
	defer n.mu.Unlock()

	tapName := fmt.Sprintf("tap-slot-%d", slot)
	n.logger.WithFields(logrus.Fields{
		"tap":   tapName,
		"slot":  slot,
		"vm_id": vmID,
	}).Debug("Releasing TAP slot (keeping TAP device)")

	// Release IP allocation but keep the TAP device for reuse
	n.releaseIP(vmID)
}

// allocateIP allocates an IP address for a VM
func (n *NATNetwork) allocateIP(vmID string) (net.IP, error) {
	if ip, exists := n.allocatedIPs[vmID]; exists {
		return ip, nil
	}

	// Calculate max IPs in subnet
	ones, bits := n.subnet.Mask.Size()
	maxIPs := uint32(1<<(bits-ones)) - 2 // Subtract network and broadcast

	if n.nextIPOffset > maxIPs {
		return nil, fmt.Errorf("no more IPs available in subnet")
	}

	ip := incrementIP(n.subnet.IP, n.nextIPOffset)
	n.allocatedIPs[vmID] = ip
	n.nextIPOffset++

	return ip, nil
}

// releaseIP releases an allocated IP address
func (n *NATNetwork) releaseIP(vmID string) {
	delete(n.allocatedIPs, vmID)
}

// GetGateway returns the gateway IP
func (n *NATNetwork) GetGateway() net.IP {
	return n.gateway
}

// GetSubnet returns the subnet
func (n *NATNetwork) GetSubnet() *net.IPNet {
	return n.subnet
}

// GetBridgeName returns the bridge name
func (n *NATNetwork) GetBridgeName() string {
	return n.bridgeName
}

// BlockEgress blocks internet egress for the given VM IP by inserting iptables
// rules ahead of the general ACCEPT forward rules.
func (n *NATNetwork) BlockEgress(ip net.IP) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("invalid IPv4 address: %s", ip.String())
	}

	ipStr := ip4.String()
	n.logger.WithFields(logrus.Fields{
		"ip":        ipStr,
		"ext_iface": n.externalIface,
	}).Info("Blocking VM egress")

	outCheck := []string{"-C", "FORWARD", "-i", n.bridgeName, "-s", ipStr, "-o", n.externalIface, "-j", "DROP"}
	if err := exec.Command("iptables", outCheck...).Run(); err != nil {
		outAdd := []string{"-I", "FORWARD", "1", "-i", n.bridgeName, "-s", ipStr, "-o", n.externalIface, "-j", "DROP"}
		if err := exec.Command("iptables", outAdd...).Run(); err != nil {
			return fmt.Errorf("failed to insert egress drop rule: %w", err)
		}
	}

	inCheck := []string{"-C", "FORWARD", "-i", n.externalIface, "-d", ipStr, "-o", n.bridgeName, "-j", "DROP"}
	if err := exec.Command("iptables", inCheck...).Run(); err != nil {
		inAdd := []string{"-I", "FORWARD", "1", "-i", n.externalIface, "-d", ipStr, "-o", n.bridgeName, "-j", "DROP"}
		if err := exec.Command("iptables", inAdd...).Run(); err != nil {
			return fmt.Errorf("failed to insert ingress drop rule: %w", err)
		}
	}

	return nil
}

// UnblockEgress removes iptables rules that block internet egress for the given VM IP.
func (n *NATNetwork) UnblockEgress(ip net.IP) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("invalid IPv4 address: %s", ip.String())
	}

	ipStr := ip4.String()
	n.logger.WithFields(logrus.Fields{
		"ip":        ipStr,
		"ext_iface": n.externalIface,
	}).Info("Unblocking VM egress")

	outRule := []string{"-D", "FORWARD", "-i", n.bridgeName, "-s", ipStr, "-o", n.externalIface, "-j", "DROP"}
	_ = exec.Command("iptables", outRule...).Run()

	inRule := []string{"-D", "FORWARD", "-i", n.externalIface, "-d", ipStr, "-o", n.bridgeName, "-j", "DROP"}
	_ = exec.Command("iptables", inRule...).Run()

	return nil
}

// Cleanup removes the bridge and NAT rules
func (n *NATNetwork) Cleanup() error {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.logger.Info("Cleaning up NAT network")

	// Remove bridge
	link, err := netlink.LinkByName(n.bridgeName)
	if err == nil {
		if err := netlink.LinkDel(link); err != nil {
			n.logger.WithError(err).Warn("Failed to delete bridge")
		}
	}

	// Remove NAT rules
	subnetCIDR := n.subnet.String()
	exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING",
		"-s", subnetCIDR, "-o", n.externalIface, "-j", "MASQUERADE").Run()
	exec.Command("iptables", "-D", "FORWARD",
		"-i", n.bridgeName, "-o", n.externalIface, "-j", "ACCEPT").Run()
	exec.Command("iptables", "-D", "FORWARD",
		"-i", n.externalIface, "-o", n.bridgeName,
		"-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT").Run()

	return nil
}

// incrementIP increments an IP address by offset
func incrementIP(ip net.IP, offset uint32) net.IP {
	ip = ip.To4()
	if ip == nil {
		return nil
	}

	result := make(net.IP, 4)
	copy(result, ip)

	for i := 3; i >= 0 && offset > 0; i-- {
		sum := uint32(result[i]) + offset
		result[i] = byte(sum & 0xff)
		offset = sum >> 8
	}

	return result
}

// generateMAC generates a MAC address based on IP
func generateMAC(ip net.IP) string {
	ip = ip.To4()
	if ip == nil {
		return "02:00:00:00:00:01"
	}
	return fmt.Sprintf("02:FC:%02x:%02x:%02x:%02x", ip[0], ip[1], ip[2], ip[3])
}

// NetworkConfig holds network configuration to inject into microVM
type NetworkConfig struct {
	IP        string `json:"ip"`
	Gateway   string `json:"gateway"`
	Netmask   string `json:"netmask"`
	DNS       string `json:"dns"`
	Interface string `json:"interface"`
	MAC       string `json:"mac"`
}

// GetNetworkConfig returns the network configuration for a TAP device
func (t *TapDevice) GetNetworkConfig() NetworkConfig {
	ones, _ := t.Subnet.Mask.Size()
	return NetworkConfig{
		IP:        fmt.Sprintf("%s/%d", t.IP.String(), ones),
		Gateway:   t.Gateway.String(),
		Netmask:   net.IP(t.Subnet.Mask).String(),
		DNS:       "8.8.8.8",
		Interface: "eth0",
		MAC:       t.MAC,
	}
}
