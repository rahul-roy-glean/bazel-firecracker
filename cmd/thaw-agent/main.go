package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

var (
	mmdsEndpoint  = flag.String("mmds-endpoint", "http://169.254.169.254", "MMDS endpoint")
	workspaceDir  = flag.String("workspace-dir", "/workspace", "Workspace directory")
	runnerDir     = flag.String("runner-dir", "/home/runner", "GitHub runner directory")
	logLevel      = flag.String("log-level", "info", "Log level")
	readyFile     = flag.String("ready-file", "/var/run/thaw-agent/ready", "Ready signal file")
	skipNetwork   = flag.Bool("skip-network", false, "Skip network configuration")
	skipGitSync   = flag.Bool("skip-git-sync", false, "Skip git sync")
	skipRunner    = flag.Bool("skip-runner", false, "Skip GitHub runner registration")
)

// MMDSData represents the data structure from MMDS
type MMDSData struct {
	Latest struct {
		Meta struct {
			RunnerID    string `json:"runner_id"`
			HostID      string `json:"host_id"`
			Environment string `json:"environment"`
		} `json:"meta"`
		Network struct {
			IP        string `json:"ip"`
			Gateway   string `json:"gateway"`
			Netmask   string `json:"netmask"`
			DNS       string `json:"dns"`
			Interface string `json:"interface"`
			MAC       string `json:"mac"`
		} `json:"network"`
		Job struct {
			Repo              string            `json:"repo"`
			Branch            string            `json:"branch"`
			Commit            string            `json:"commit"`
			GitHubRunnerToken string            `json:"github_runner_token"`
			Labels            map[string]string `json:"labels"`
		} `json:"job"`
		Snapshot struct {
			Version string `json:"version"`
		} `json:"snapshot"`
	} `json:"latest"`
}

var log *logrus.Logger

func main() {
	flag.Parse()

	// Setup logger
	log = logrus.New()
	log.SetFormatter(&logrus.JSONFormatter{})
	level, err := logrus.ParseLevel(*logLevel)
	if err != nil {
		level = logrus.InfoLevel
	}
	log.SetLevel(level)

	log.Info("Thaw agent starting...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Wait for MMDS to be available
	log.Info("Waiting for MMDS...")
	mmdsData, err := waitForMMDS(ctx)
	if err != nil {
		log.WithError(err).Fatal("Failed to get MMDS data")
	}

	log.WithFields(logrus.Fields{
		"runner_id": mmdsData.Latest.Meta.RunnerID,
		"host_id":   mmdsData.Latest.Meta.HostID,
		"repo":      mmdsData.Latest.Job.Repo,
		"branch":    mmdsData.Latest.Job.Branch,
	}).Info("MMDS data received")

	// Configure network
	if !*skipNetwork {
		log.Info("Configuring network...")
		if err := configureNetwork(mmdsData); err != nil {
			log.WithError(err).Error("Failed to configure network")
		}
	}

	// Regenerate hostname
	log.Info("Regenerating hostname...")
	if err := regenerateHostname(mmdsData.Latest.Meta.RunnerID); err != nil {
		log.WithError(err).Warn("Failed to regenerate hostname")
	}

	// Resync clock
	log.Info("Resyncing clock...")
	if err := resyncClock(); err != nil {
		log.WithError(err).Warn("Failed to resync clock")
	}

	// Sync git repository
	if !*skipGitSync && mmdsData.Latest.Job.Repo != "" {
		log.Info("Syncing git repository...")
		if err := syncGitRepo(mmdsData); err != nil {
			log.WithError(err).Error("Failed to sync git repo")
		}
	}

	// Register GitHub runner
	if !*skipRunner && mmdsData.Latest.Job.GitHubRunnerToken != "" {
		log.Info("Registering GitHub runner...")
		if err := registerGitHubRunner(mmdsData); err != nil {
			log.WithError(err).Error("Failed to register GitHub runner")
		}
	}

	// Signal ready
	log.Info("Signaling ready...")
	if err := signalReady(); err != nil {
		log.WithError(err).Error("Failed to signal ready")
	}

	log.Info("Thaw agent complete")
}

func waitForMMDS(ctx context.Context) (*MMDSData, error) {
	client := &http.Client{Timeout: 5 * time.Second}

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		req, err := http.NewRequestWithContext(ctx, "GET", *mmdsEndpoint+"/latest", nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			log.WithError(err).Debug("MMDS not ready, retrying...")
			time.Sleep(100 * time.Millisecond)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			time.Sleep(100 * time.Millisecond)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}

		var data MMDSData
		// MMDS returns data wrapped in "latest" key
		if err := json.Unmarshal(body, &data); err != nil {
			// Try unwrapping if the response is the inner structure
			var inner struct {
				Meta struct {
					RunnerID    string `json:"runner_id"`
					HostID      string `json:"host_id"`
					Environment string `json:"environment"`
				} `json:"meta"`
				Network struct {
					IP        string `json:"ip"`
					Gateway   string `json:"gateway"`
					Netmask   string `json:"netmask"`
					DNS       string `json:"dns"`
					Interface string `json:"interface"`
					MAC       string `json:"mac"`
				} `json:"network"`
				Job struct {
					Repo              string            `json:"repo"`
					Branch            string            `json:"branch"`
					Commit            string            `json:"commit"`
					GitHubRunnerToken string            `json:"github_runner_token"`
					Labels            map[string]string `json:"labels"`
				} `json:"job"`
				Snapshot struct {
					Version string `json:"version"`
				} `json:"snapshot"`
			}
			if err := json.Unmarshal(body, &inner); err != nil {
				return nil, fmt.Errorf("failed to parse MMDS data: %w", err)
			}
			data.Latest = inner
		}

		return &data, nil
	}
}

func configureNetwork(data *MMDSData) error {
	net := data.Latest.Network
	if net.IP == "" {
		return fmt.Errorf("no IP address in MMDS data")
	}

	iface := net.Interface
	if iface == "" {
		iface = "eth0"
	}

	// Flush existing addresses
	exec.Command("ip", "addr", "flush", "dev", iface).Run()

	// Add IP address
	if err := exec.Command("ip", "addr", "add", net.IP, "dev", iface).Run(); err != nil {
		return fmt.Errorf("failed to add IP address: %w", err)
	}

	// Bring interface up
	if err := exec.Command("ip", "link", "set", iface, "up").Run(); err != nil {
		return fmt.Errorf("failed to bring interface up: %w", err)
	}

	// Add default route
	if net.Gateway != "" {
		exec.Command("ip", "route", "del", "default").Run()
		if err := exec.Command("ip", "route", "add", "default", "via", net.Gateway).Run(); err != nil {
			return fmt.Errorf("failed to add default route: %w", err)
		}
	}

	// Configure DNS
	if net.DNS != "" {
		resolv := fmt.Sprintf("nameserver %s\n", net.DNS)
		if err := os.WriteFile("/etc/resolv.conf", []byte(resolv), 0644); err != nil {
			return fmt.Errorf("failed to write resolv.conf: %w", err)
		}
	}

	log.WithFields(logrus.Fields{
		"interface": iface,
		"ip":        net.IP,
		"gateway":   net.Gateway,
		"dns":       net.DNS,
	}).Info("Network configured")

	return nil
}

func regenerateHostname(runnerID string) error {
	hostname := fmt.Sprintf("runner-%s", runnerID[:8])
	
	if err := os.WriteFile("/etc/hostname", []byte(hostname+"\n"), 0644); err != nil {
		return err
	}

	return exec.Command("hostname", hostname).Run()
}

func resyncClock() error {
	// Try to sync with NTP
	if err := exec.Command("hwclock", "--hctosys").Run(); err != nil {
		log.WithError(err).Debug("hwclock sync failed, trying ntpdate")
	}

	// Try ntpdate if available
	exec.Command("ntpdate", "-u", "pool.ntp.org").Run()

	return nil
}

func syncGitRepo(data *MMDSData) error {
	job := data.Latest.Job
	if job.Repo == "" {
		return nil
	}

	// Change to workspace
	if err := os.Chdir(*workspaceDir); err != nil {
		return fmt.Errorf("failed to change to workspace: %w", err)
	}

	// Check if repo exists
	if _, err := os.Stat(".git"); os.IsNotExist(err) {
		log.Warn("No git repo in workspace, skipping sync")
		return nil
	}

	// Fetch updates
	log.WithField("branch", job.Branch).Info("Fetching git updates")
	if err := exec.Command("git", "fetch", "origin", job.Branch).Run(); err != nil {
		return fmt.Errorf("git fetch failed: %w", err)
	}

	// Checkout specific commit or branch
	target := job.Commit
	if target == "" {
		target = "origin/" + job.Branch
	}

	log.WithField("target", target).Info("Checking out")
	if err := exec.Command("git", "checkout", "-f", target).Run(); err != nil {
		return fmt.Errorf("git checkout failed: %w", err)
	}

	// Clean workspace
	exec.Command("git", "clean", "-fd").Run()

	return nil
}

func registerGitHubRunner(data *MMDSData) error {
	job := data.Latest.Job
	if job.GitHubRunnerToken == "" {
		return fmt.Errorf("no GitHub runner token")
	}

	runnerPath := *runnerDir

	// Extract repo URL for registration
	repoURL := job.Repo
	if !strings.HasPrefix(repoURL, "https://") {
		repoURL = "https://github.com/" + repoURL
	}

	// Build labels
	var labels []string
	for k, v := range job.Labels {
		labels = append(labels, fmt.Sprintf("%s=%s", k, v))
	}
	labelsStr := strings.Join(labels, ",")

	// Configure runner
	configCmd := exec.Command(
		filepath.Join(runnerPath, "config.sh"),
		"--url", repoURL,
		"--token", job.GitHubRunnerToken,
		"--name", data.Latest.Meta.RunnerID[:8],
		"--labels", labelsStr,
		"--unattended",
		"--replace",
		"--ephemeral",
	)
	configCmd.Dir = runnerPath
	configCmd.Stdout = os.Stdout
	configCmd.Stderr = os.Stderr

	log.Info("Configuring GitHub runner...")
	if err := configCmd.Run(); err != nil {
		return fmt.Errorf("runner config failed: %w", err)
	}

	// Start runner in background
	runCmd := exec.Command(filepath.Join(runnerPath, "run.sh"))
	runCmd.Dir = runnerPath
	runCmd.Stdout = os.Stdout
	runCmd.Stderr = os.Stderr

	log.Info("Starting GitHub runner...")
	if err := runCmd.Start(); err != nil {
		return fmt.Errorf("failed to start runner: %w", err)
	}

	return nil
}

func signalReady() error {
	readyDir := filepath.Dir(*readyFile)
	if err := os.MkdirAll(readyDir, 0755); err != nil {
		return err
	}

	return os.WriteFile(*readyFile, []byte(time.Now().Format(time.RFC3339)), 0644)
}

