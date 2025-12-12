package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func (s *ControlPlaneServer) HandleQuarantineRunner(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	runnerID := r.URL.Query().Get("runner_id")
	if runnerID == "" {
		http.Error(w, "missing runner_id", http.StatusBadRequest)
		return
	}

	reason := r.URL.Query().Get("reason")
	blockEgress := parseBoolQuery(r, "block_egress", true)
	pauseVM := parseBoolQuery(r, "pause_vm", true)

	runner, err := s.hostRegistry.GetRunner(runnerID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	host, err := s.hostRegistry.GetHost(runner.HostID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	hostHTTP, err := hostAgentHTTPAddress(host.GRPCAddress)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	u := url.URL{
		Scheme: "http",
		Host:   hostHTTP,
		Path:   "/api/v1/runners/quarantine",
	}
	q := u.Query()
	q.Set("runner_id", runnerID)
	if reason != "" {
		q.Set("reason", reason)
	}
	q.Set("block_egress", strconv.FormatBool(blockEgress))
	q.Set("pause_vm", strconv.FormatBool(pauseVM))
	u.RawQuery = q.Encode()

	s.proxyPOST(w, r, u.String())
}

func (s *ControlPlaneServer) HandleUnquarantineRunner(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	runnerID := r.URL.Query().Get("runner_id")
	if runnerID == "" {
		http.Error(w, "missing runner_id", http.StatusBadRequest)
		return
	}

	unblockEgress := parseBoolQuery(r, "unblock_egress", true)
	resumeVM := parseBoolQuery(r, "resume_vm", true)

	runner, err := s.hostRegistry.GetRunner(runnerID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	host, err := s.hostRegistry.GetHost(runner.HostID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	hostHTTP, err := hostAgentHTTPAddress(host.GRPCAddress)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	u := url.URL{
		Scheme: "http",
		Host:   hostHTTP,
		Path:   "/api/v1/runners/unquarantine",
	}
	q := u.Query()
	q.Set("runner_id", runnerID)
	q.Set("unblock_egress", strconv.FormatBool(unblockEgress))
	q.Set("resume_vm", strconv.FormatBool(resumeVM))
	u.RawQuery = q.Encode()

	s.proxyPOST(w, r, u.String())
}

func (s *ControlPlaneServer) proxyPOST(w http.ResponseWriter, r *http.Request, targetURL string) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, targetURL, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	} else {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func parseBoolQuery(r *http.Request, key string, defaultVal bool) bool {
	raw := r.URL.Query().Get(key)
	if raw == "" {
		return defaultVal
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return defaultVal
	}
	return v
}

func hostAgentHTTPAddress(grpcAddress string) (string, error) {
	addr := strings.TrimSpace(grpcAddress)
	addr = strings.TrimPrefix(addr, "dns:///")
	addr = strings.TrimPrefix(addr, "http://")
	addr = strings.TrimPrefix(addr, "https://")

	host, _, err := net.SplitHostPort(addr)
	if err == nil {
		return net.JoinHostPort(host, "8080"), nil
	}

	if strings.Contains(addr, "/") {
		return "", fmt.Errorf("unsupported host address: %s", grpcAddress)
	}

	return net.JoinHostPort(addr, "8080"), nil
}
