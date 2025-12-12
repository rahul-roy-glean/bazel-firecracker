package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
)

// GitHubWebhookHandler handles GitHub webhook events
type GitHubWebhookHandler struct {
	scheduler     *Scheduler
	hostRegistry  *HostRegistry
	webhookSecret string
	logger        *logrus.Entry
}

// NewGitHubWebhookHandler creates a new webhook handler
func NewGitHubWebhookHandler(s *Scheduler, hr *HostRegistry, logger *logrus.Logger) *GitHubWebhookHandler {
	return &GitHubWebhookHandler{
		scheduler:     s,
		hostRegistry:  hr,
		webhookSecret: os.Getenv("GITHUB_WEBHOOK_SECRET"),
		logger:        logger.WithField("component", "github-webhook"),
	}
}

// WorkflowJobEvent represents a GitHub workflow_job webhook event
type WorkflowJobEvent struct {
	Action      string `json:"action"`
	WorkflowJob struct {
		ID         int64    `json:"id"`
		RunID      int64    `json:"run_id"`
		Status     string   `json:"status"`
		Conclusion string   `json:"conclusion"`
		Name       string   `json:"name"`
		Labels     []string `json:"labels"`
		RunnerID   int64    `json:"runner_id"`
		RunnerName string   `json:"runner_name"`
		HeadBranch string   `json:"head_branch"`
		HeadSHA    string   `json:"head_sha"`
	} `json:"workflow_job"`
	Repository struct {
		ID       int64  `json:"id"`
		Name     string `json:"name"`
		FullName string `json:"full_name"`
		CloneURL string `json:"clone_url"`
	} `json:"repository"`
	Organization struct {
		Login string `json:"login"`
	} `json:"organization"`
	Sender struct {
		Login string `json:"login"`
	} `json:"sender"`
}

// HandleWebhook handles incoming GitHub webhooks
func (h *GitHubWebhookHandler) HandleWebhook(w http.ResponseWriter, r *http.Request) {
	// Verify request method
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.logger.WithError(err).Error("Failed to read request body")
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	// Verify signature
	if h.webhookSecret != "" {
		signature := r.Header.Get("X-Hub-Signature-256")
		if !h.verifySignature(body, signature) {
			h.logger.Warn("Invalid webhook signature")
			http.Error(w, "Invalid signature", http.StatusUnauthorized)
			return
		}
	}

	// Check event type
	eventType := r.Header.Get("X-GitHub-Event")
	deliveryID := r.Header.Get("X-GitHub-Delivery")

	h.logger.WithFields(logrus.Fields{
		"event_type":  eventType,
		"delivery_id": deliveryID,
	}).Debug("Received webhook")

	// Handle different event types
	switch eventType {
	case "workflow_job":
		h.handleWorkflowJob(r.Context(), body, w)
	case "ping":
		h.handlePing(w)
	default:
		h.logger.WithField("event_type", eventType).Debug("Ignoring unhandled event type")
		w.WriteHeader(http.StatusOK)
	}
}

// verifySignature verifies the GitHub webhook signature
func (h *GitHubWebhookHandler) verifySignature(body []byte, signature string) bool {
	if !strings.HasPrefix(signature, "sha256=") {
		return false
	}

	sig := strings.TrimPrefix(signature, "sha256=")
	mac := hmac.New(sha256.New, []byte(h.webhookSecret))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(sig), []byte(expected))
}

// handleWorkflowJob handles workflow_job events
func (h *GitHubWebhookHandler) handleWorkflowJob(ctx context.Context, body []byte, w http.ResponseWriter) {
	var event WorkflowJobEvent
	if err := json.Unmarshal(body, &event); err != nil {
		h.logger.WithError(err).Error("Failed to parse workflow_job event")
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	h.logger.WithFields(logrus.Fields{
		"action":   event.Action,
		"job_id":   event.WorkflowJob.ID,
		"job_name": event.WorkflowJob.Name,
		"repo":     event.Repository.FullName,
		"branch":   event.WorkflowJob.HeadBranch,
		"labels":   event.WorkflowJob.Labels,
	}).Info("Handling workflow_job event")

	switch event.Action {
	case "queued":
		h.handleJobQueued(ctx, &event, w)
	case "in_progress":
		h.handleJobInProgress(ctx, &event, w)
	case "completed":
		h.handleJobCompleted(ctx, &event, w)
	default:
		h.logger.WithField("action", event.Action).Debug("Ignoring workflow_job action")
		w.WriteHeader(http.StatusOK)
	}
}

// handleJobQueued handles a queued job
func (h *GitHubWebhookHandler) handleJobQueued(ctx context.Context, event *WorkflowJobEvent, w http.ResponseWriter) {
	// Check if this job should use our runners
	if !h.shouldHandleJob(event) {
		h.logger.Debug("Job does not match our labels, ignoring")
		w.WriteHeader(http.StatusOK)
		return
	}

	h.logger.WithFields(logrus.Fields{
		"job_id": event.WorkflowJob.ID,
		"repo":   event.Repository.FullName,
	}).Info("Allocating runner for queued job")

	// Request runner allocation
	req := AllocateRunnerRequest{
		RequestID: fmt.Sprintf("gh-%d", event.WorkflowJob.ID),
		Repo:      event.Repository.FullName,
		Branch:    event.WorkflowJob.HeadBranch,
		Commit:    event.WorkflowJob.HeadSHA,
		Labels:    labelsToMap(event.WorkflowJob.Labels),
	}

	resp, err := h.scheduler.AllocateRunner(ctx, req)
	if err != nil {
		h.logger.WithError(err).Error("Failed to allocate runner")
		// Don't return error to GitHub - they'll retry
		w.WriteHeader(http.StatusOK)
		return
	}

	h.logger.WithFields(logrus.Fields{
		"runner_id": resp.RunnerID,
		"host_id":   resp.HostID,
	}).Info("Runner allocated successfully")

	w.WriteHeader(http.StatusOK)
}

// handleJobInProgress handles a job that started running
func (h *GitHubWebhookHandler) handleJobInProgress(ctx context.Context, event *WorkflowJobEvent, w http.ResponseWriter) {
	h.logger.WithFields(logrus.Fields{
		"job_id":      event.WorkflowJob.ID,
		"runner_name": event.WorkflowJob.RunnerName,
	}).Info("Job started running")

	// Update runner status in registry
	// The runner name should match our runner ID
	if event.WorkflowJob.RunnerName != "" {
		// Find runner by name and update status
		// runner, _ := h.hostRegistry.GetRunnerByName(event.WorkflowJob.RunnerName)
		// if runner != nil {
		//     runner.Status = "busy"
		//     runner.JobID = fmt.Sprintf("%d", event.WorkflowJob.ID)
		// }
	}

	w.WriteHeader(http.StatusOK)
}

// handleJobCompleted handles a completed job
func (h *GitHubWebhookHandler) handleJobCompleted(ctx context.Context, event *WorkflowJobEvent, w http.ResponseWriter) {
	h.logger.WithFields(logrus.Fields{
		"job_id":      event.WorkflowJob.ID,
		"conclusion":  event.WorkflowJob.Conclusion,
		"runner_name": event.WorkflowJob.RunnerName,
	}).Info("Job completed")

	// Release the runner
	if event.WorkflowJob.RunnerName != "" {
		// Find and release runner
		// Since we use ephemeral runners, the runner will self-terminate
		// But we should clean up our records
	}

	w.WriteHeader(http.StatusOK)
}

// shouldHandleJob checks if this job should be handled by our runners
func (h *GitHubWebhookHandler) shouldHandleJob(event *WorkflowJobEvent) bool {
	// Check for our custom label
	for _, label := range event.WorkflowJob.Labels {
		if label == "firecracker" || label == "self-hosted" {
			return true
		}
	}
	return false
}

// handlePing handles ping events
func (h *GitHubWebhookHandler) handlePing(w http.ResponseWriter) {
	h.logger.Info("Received ping event")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("pong"))
}

// labelsToMap converts a slice of labels to a map
func labelsToMap(labels []string) map[string]string {
	m := make(map[string]string)
	for _, label := range labels {
		m[label] = "true"
	}
	return m
}

// GenerateRunnerToken generates a JIT runner registration token
func (h *GitHubWebhookHandler) GenerateRunnerToken(ctx context.Context, repo string) (string, error) {
	// In production, call GitHub API:
	// POST /repos/{owner}/{repo}/actions/runners/registration-token
	// or for org runners:
	// POST /orgs/{org}/actions/runners/registration-token

	// This requires a GitHub App or PAT with admin:org or repo scope

	h.logger.WithField("repo", repo).Debug("Generating runner token")

	// Placeholder - implement actual GitHub API call
	return "placeholder-token", nil
}
