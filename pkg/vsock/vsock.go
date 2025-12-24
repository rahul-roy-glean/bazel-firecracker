package vsock

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	// DefaultPort is the default vsock port for host-guest communication
	DefaultPort = 10000

	// WarmupCompleteMessage is sent by guest when warmup finishes
	WarmupCompleteMessage = "WARMUP_COMPLETE"
)

// WarmupStatus represents the warmup status from the guest
type WarmupStatus struct {
	Complete    bool      `json:"complete"`
	Phase       string    `json:"phase"`
	Message     string    `json:"message,omitempty"`
	Error       string    `json:"error,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
	BazelInfo   *BazelInfo `json:"bazel_info,omitempty"`
}

// BazelInfo holds bazel warmup information
type BazelInfo struct {
	Version           string `json:"version,omitempty"`
	OutputBase        string `json:"output_base,omitempty"`
	ExternalsFetched  int    `json:"externals_fetched,omitempty"`
	AnalysisCompleted bool   `json:"analysis_completed,omitempty"`
}

// Listener listens for vsock connections from the guest
type Listener struct {
	udsPath  string
	listener net.Listener
	logger   *logrus.Entry
}

// NewListener creates a new vsock listener using the Unix domain socket provided by Firecracker
func NewListener(udsPath string, logger *logrus.Logger) (*Listener, error) {
	if logger == nil {
		logger = logrus.New()
	}

	return &Listener{
		udsPath: udsPath,
		logger:  logger.WithField("component", "vsock-listener"),
	}, nil
}

// Start starts listening on the UDS path
func (l *Listener) Start() error {
	// Remove existing socket if present
	os.Remove(l.udsPath)

	listener, err := net.Listen("unix", l.udsPath)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", l.udsPath, err)
	}

	l.listener = listener
	l.logger.WithField("path", l.udsPath).Info("Vsock listener started")
	return nil
}

// WaitForWarmup waits for the guest to signal warmup completion
func (l *Listener) WaitForWarmup(ctx context.Context, timeout time.Duration) (*WarmupStatus, error) {
	if l.listener == nil {
		return nil, fmt.Errorf("listener not started")
	}

	l.logger.Info("Waiting for warmup signal from guest...")

	statusCh := make(chan *WarmupStatus, 1)
	errCh := make(chan error, 1)

	go func() {
		for {
			conn, err := l.listener.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					l.logger.WithError(err).Debug("Accept error")
					continue
				}
			}

			go l.handleConnection(conn, statusCh, errCh)
		}
	}()

	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	select {
	case status := <-statusCh:
		return status, nil
	case err := <-errCh:
		return nil, err
	case <-timeoutCtx.Done():
		return nil, fmt.Errorf("timeout waiting for warmup: %w", timeoutCtx.Err())
	}
}

func (l *Listener) handleConnection(conn net.Conn, statusCh chan<- *WarmupStatus, errCh chan<- error) {
	defer conn.Close()

	l.logger.Debug("Guest connected via vsock")

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()
		l.logger.WithField("message", line).Debug("Received from guest")

		// Try to parse as JSON status
		var status WarmupStatus
		if err := json.Unmarshal([]byte(line), &status); err == nil {
			if status.Complete {
				l.logger.Info("Received warmup complete signal")
				select {
				case statusCh <- &status:
				default:
				}
				return
			}
			l.logger.WithField("phase", status.Phase).Info("Warmup progress")
			continue
		}

		// Handle simple text message
		if line == WarmupCompleteMessage {
			l.logger.Info("Received warmup complete signal (text)")
			select {
			case statusCh <- &WarmupStatus{Complete: true, Timestamp: time.Now()}:
			default:
			}
			return
		}
	}

	if err := scanner.Err(); err != nil {
		l.logger.WithError(err).Debug("Connection read error")
	}
}

// Close closes the listener
func (l *Listener) Close() error {
	if l.listener != nil {
		l.listener.Close()
	}
	os.Remove(l.udsPath)
	return nil
}

// GuestClient is used by the guest (thaw-agent) to communicate with the host
type GuestClient struct {
	port   uint32
	logger *logrus.Entry
}

// NewGuestClient creates a client for guest-to-host vsock communication
func NewGuestClient(port uint32, logger *logrus.Logger) *GuestClient {
	if logger == nil {
		logger = logrus.New()
	}
	return &GuestClient{
		port:   port,
		logger: logger.WithField("component", "vsock-guest-client"),
	}
}

// SendStatus sends a warmup status to the host
func (c *GuestClient) SendStatus(status *WarmupStatus) error {
	conn, err := c.connect()
	if err != nil {
		return err
	}
	defer conn.Close()

	data, err := json.Marshal(status)
	if err != nil {
		return fmt.Errorf("failed to marshal status: %w", err)
	}

	_, err = conn.Write(append(data, '\n'))
	return err
}

// SignalComplete sends a simple completion signal
func (c *GuestClient) SignalComplete() error {
	conn, err := c.connect()
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = conn.Write([]byte(WarmupCompleteMessage + "\n"))
	return err
}

func (c *GuestClient) connect() (net.Conn, error) {
	// In a real implementation, this would use the vsock AF_VSOCK socket
	// For now, we use a Unix socket at a well-known path (set by Firecracker)
	// The vsock UDS path is: /path/to/vsock.sock_<port>
	//
	// Inside the guest, vsock connections go through /dev/vsock with the
	// special CID 2 (VMADDR_CID_HOST) to reach the host.
	//
	// For simplicity in the guest, we'll use the vsock device directly.
	addr := fmt.Sprintf("/dev/vsock")
	
	// Check if vsock device exists
	if _, err := os.Stat(addr); err != nil {
		return nil, fmt.Errorf("vsock device not available: %w", err)
	}

	// Connect to host (CID 2) on our port
	// This requires the mdlayher/vsock package for proper vsock support
	// For now, return an error indicating vsock needs to be set up
	return nil, fmt.Errorf("vsock guest connection requires /dev/vsock - ensure vsock is enabled in VM config")
}

