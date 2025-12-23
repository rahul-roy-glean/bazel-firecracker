package firecracker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
)

// Client provides an interface to the Firecracker API
type Client struct {
	socketPath string
	httpClient *http.Client
	vmID       string
	process    *exec.Cmd
	mu         sync.Mutex
	logger     *logrus.Entry
}

// Config for creating a new Firecracker client
type Config struct {
	SocketPath     string
	VMID           string
	FirecrackerBin string
	JailerBin      string
	UseJailer      bool
	Logger         *logrus.Logger
}

// NewClient creates a new Firecracker API client
func NewClient(cfg Config) *Client {
	logger := cfg.Logger
	if logger == nil {
		logger = logrus.New()
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", cfg.SocketPath)
		},
	}

	return &Client{
		socketPath: cfg.SocketPath,
		vmID:       cfg.VMID,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		},
		logger: logger.WithField("vm_id", cfg.VMID),
	}
}

// doRequest performs an HTTP request to the Firecracker API
func (c *Client) doRequest(ctx context.Context, method, path string, body interface{}) error {
	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(jsonBody)
	}

	url := fmt.Sprintf("http://localhost%s", path)
	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		var apiErr APIError
		if err := json.Unmarshal(respBody, &apiErr); err == nil && apiErr.FaultMessage != "" {
			return &apiErr
		}
		return fmt.Errorf("API error: status %d, body: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// doRequestWithResponse performs a request and returns the response body
func (c *Client) doRequestWithResponse(ctx context.Context, method, path string, body interface{}, result interface{}) error {
	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(jsonBody)
	}

	url := fmt.Sprintf("http://localhost%s", path)
	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		var apiErr APIError
		if err := json.Unmarshal(respBody, &apiErr); err == nil && apiErr.FaultMessage != "" {
			return &apiErr
		}
		return fmt.Errorf("API error: status %d, body: %s", resp.StatusCode, string(respBody))
	}

	if result != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("failed to unmarshal response: %w", err)
		}
	}

	return nil
}

// GetInstanceInfo retrieves information about the microVM instance
func (c *Client) GetInstanceInfo(ctx context.Context) (*InstanceInfo, error) {
	var info InstanceInfo
	if err := c.doRequestWithResponse(ctx, http.MethodGet, "/", nil, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

// SetMachineConfig configures the VM's vCPUs and memory
func (c *Client) SetMachineConfig(ctx context.Context, cfg MachineConfig) error {
	c.logger.WithFields(logrus.Fields{
		"vcpus":  cfg.VCPUCount,
		"mem_mb": cfg.MemSizeMib,
	}).Debug("Setting machine config")
	return c.doRequest(ctx, http.MethodPut, "/machine-config", cfg)
}

// SetBootSource configures the kernel and boot arguments
func (c *Client) SetBootSource(ctx context.Context, boot BootSource) error {
	c.logger.WithField("kernel", boot.KernelImagePath).Debug("Setting boot source")
	return c.doRequest(ctx, http.MethodPut, "/boot-source", boot)
}

// AddDrive adds a block device to the VM
func (c *Client) AddDrive(ctx context.Context, drive Drive) error {
	c.logger.WithFields(logrus.Fields{
		"drive_id":    drive.DriveID,
		"path":        drive.PathOnHost,
		"is_root":     drive.IsRootDevice,
		"is_readonly": drive.IsReadOnly,
	}).Debug("Adding drive")
	return c.doRequest(ctx, http.MethodPut, fmt.Sprintf("/drives/%s", drive.DriveID), drive)
}

// AddNetworkInterface adds a network interface to the VM
func (c *Client) AddNetworkInterface(ctx context.Context, iface NetworkInterface) error {
	c.logger.WithFields(logrus.Fields{
		"iface_id":  iface.IfaceID,
		"host_dev":  iface.HostDevName,
		"guest_mac": iface.GuestMAC,
	}).Debug("Adding network interface")
	return c.doRequest(ctx, http.MethodPut, fmt.Sprintf("/network-interfaces/%s", iface.IfaceID), iface)
}

// PatchNetworkInterface patches an existing network interface (used after snapshot restore)
func (c *Client) PatchNetworkInterface(ctx context.Context, ifaceID, hostDevName string) error {
	c.logger.WithFields(logrus.Fields{
		"iface_id": ifaceID,
		"host_dev": hostDevName,
	}).Debug("Patching network interface")
	patch := map[string]string{"iface_id": ifaceID, "host_dev_name": hostDevName}
	return c.doRequest(ctx, http.MethodPatch, fmt.Sprintf("/network-interfaces/%s", ifaceID), patch)
}

// SetVsock configures a vsock device for host-guest communication
func (c *Client) SetVsock(ctx context.Context, vsock Vsock) error {
	c.logger.WithFields(logrus.Fields{
		"guest_cid": vsock.GuestCID,
		"uds_path":  vsock.UDSPath,
	}).Debug("Setting vsock")
	return c.doRequest(ctx, http.MethodPut, "/vsock", vsock)
}

// SetMMDSConfig configures the MicroVM Metadata Service
func (c *Client) SetMMDSConfig(ctx context.Context, cfg MMDSConfig) error {
	c.logger.Debug("Setting MMDS config")
	return c.doRequest(ctx, http.MethodPut, "/mmds/config", cfg)
}

// PutMMDSData puts data into the MMDS
func (c *Client) PutMMDSData(ctx context.Context, data interface{}) error {
	c.logger.Debug("Putting MMDS data")
	return c.doRequest(ctx, http.MethodPut, "/mmds", data)
}

// PatchMMDSData patches data in the MMDS
func (c *Client) PatchMMDSData(ctx context.Context, data interface{}) error {
	c.logger.Debug("Patching MMDS data")
	return c.doRequest(ctx, http.MethodPatch, "/mmds", data)
}

// SetLogger configures logging for the microVM
func (c *Client) SetLogger(ctx context.Context, logger Logger) error {
	return c.doRequest(ctx, http.MethodPut, "/logger", logger)
}

// SetMetrics configures metrics output for the microVM
func (c *Client) SetMetrics(ctx context.Context, metrics Metrics) error {
	return c.doRequest(ctx, http.MethodPut, "/metrics", metrics)
}

// StartInstance starts the microVM
func (c *Client) StartInstance(ctx context.Context) error {
	c.logger.Info("Starting microVM instance")
	action := map[string]string{"action_type": "InstanceStart"}
	return c.doRequest(ctx, http.MethodPut, "/actions", action)
}

// PauseVM pauses the microVM
func (c *Client) PauseVM(ctx context.Context) error {
	c.logger.Info("Pausing microVM")
	state := VMState{State: "Paused"}
	return c.doRequest(ctx, http.MethodPatch, "/vm", state)
}

// ResumeVM resumes a paused microVM
func (c *Client) ResumeVM(ctx context.Context) error {
	c.logger.Info("Resuming microVM")
	state := VMState{State: "Resumed"}
	return c.doRequest(ctx, http.MethodPatch, "/vm", state)
}

// CreateSnapshot creates a snapshot of the microVM
func (c *Client) CreateSnapshot(ctx context.Context, params SnapshotCreateParams) error {
	c.logger.WithFields(logrus.Fields{
		"snapshot_path": params.SnapshotPath,
		"mem_path":      params.MemFilePath,
		"type":          params.SnapshotType,
	}).Info("Creating snapshot")

	if params.SnapshotType == "" {
		params.SnapshotType = "Full"
	}

	return c.doRequest(ctx, http.MethodPut, "/snapshot/create", params)
}

// LoadSnapshot loads a snapshot into the microVM
func (c *Client) LoadSnapshot(ctx context.Context, params SnapshotLoadParams) error {
	c.logger.WithFields(logrus.Fields{
		"snapshot_path": params.SnapshotPath,
		"mem_path":      params.MemFilePath,
		"resume":        params.ResumeVM,
	}).Info("Loading snapshot")

	return c.doRequest(ctx, http.MethodPut, "/snapshot/load", params)
}

// WaitForSocket waits for the Firecracker socket to become available
func (c *Client) WaitForSocket(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		conn, err := net.DialTimeout("unix", c.socketPath, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for socket %s", c.socketPath)
}

// StartFirecracker starts the Firecracker process
func (c *Client) StartFirecracker(ctx context.Context, firecrackerBin string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.process != nil {
		return fmt.Errorf("firecracker process already running")
	}

	// Ensure socket directory exists
	socketDir := filepath.Dir(c.socketPath)
	if err := os.MkdirAll(socketDir, 0755); err != nil {
		return fmt.Errorf("failed to create socket directory: %w", err)
	}

	// Remove existing socket if present
	os.Remove(c.socketPath)

	c.logger.WithFields(logrus.Fields{
		"binary": firecrackerBin,
		"socket": c.socketPath,
	}).Info("Starting Firecracker process")

	cmd := exec.CommandContext(ctx, firecrackerBin,
		"--api-sock", c.socketPath,
		"--id", c.vmID,
	)

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start firecracker: %w", err)
	}

	c.process = cmd

	// Wait for socket to be ready
	if err := c.WaitForSocket(ctx, 10*time.Second); err != nil {
		c.StopFirecracker()
		return fmt.Errorf("firecracker socket not ready: %w", err)
	}

	return nil
}

// StopFirecracker stops the Firecracker process
func (c *Client) StopFirecracker() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.process == nil {
		return nil
	}

	c.logger.Info("Stopping Firecracker process")

	// Try graceful shutdown first
	if err := c.process.Process.Signal(syscall.SIGTERM); err != nil {
		c.logger.WithError(err).Warn("Failed to send SIGTERM")
	}

	// Wait briefly for graceful shutdown
	done := make(chan error, 1)
	go func() {
		done <- c.process.Wait()
	}()

	select {
	case <-done:
		// Process exited
	case <-time.After(5 * time.Second):
		// Force kill
		c.logger.Warn("Forcing kill of Firecracker process")
		c.process.Process.Kill()
		<-done
	}

	c.process = nil
	os.Remove(c.socketPath)

	return nil
}

// IsRunning checks if the Firecracker process is running
func (c *Client) IsRunning() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.process != nil && c.process.ProcessState == nil
}

// VMID returns the VM ID
func (c *Client) VMID() string {
	return c.vmID
}

// SocketPath returns the socket path
func (c *Client) SocketPath() string {
	return c.socketPath
}


