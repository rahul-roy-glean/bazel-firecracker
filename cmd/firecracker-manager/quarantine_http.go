package main

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/sirupsen/logrus"

	"github.com/rahul-roy-glean/bazel-firecracker/pkg/runner"
)

func quarantineRunnerHandler(mgr *runner.Manager, logger *logrus.Logger) http.HandlerFunc {
	log := logger.WithField("component", "http-quarantine")
	return func(w http.ResponseWriter, r *http.Request) {
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

		dir, err := mgr.QuarantineRunner(r.Context(), runnerID, runner.QuarantineOptions{
			Reason:      reason,
			BlockEgress: &blockEgress,
			PauseVM:     &pauseVM,
		})
		if err != nil {
			log.WithError(err).WithField("runner_id", runnerID).Warn("Quarantine runner failed")
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"success":        false,
				"error":          err.Error(),
				"runner_id":      runnerID,
				"quarantine_dir": dir,
			})
			return
		}

		writeJSONResponse(w, http.StatusOK, map[string]any{
			"success":        true,
			"runner_id":      runnerID,
			"quarantine_dir": dir,
		})
	}
}

func unquarantineRunnerHandler(mgr *runner.Manager, logger *logrus.Logger) http.HandlerFunc {
	log := logger.WithField("component", "http-quarantine")
	return func(w http.ResponseWriter, r *http.Request) {
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

		err := mgr.UnquarantineRunner(r.Context(), runnerID, runner.UnquarantineOptions{
			UnblockEgress: &unblockEgress,
			ResumeVM:      &resumeVM,
		})
		if err != nil {
			log.WithError(err).WithField("runner_id", runnerID).Warn("Unquarantine runner failed")
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"success":   false,
				"error":     err.Error(),
				"runner_id": runnerID,
			})
			return
		}

		writeJSONResponse(w, http.StatusOK, map[string]any{
			"success":   true,
			"runner_id": runnerID,
		})
	}
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

func writeJSONResponse(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
