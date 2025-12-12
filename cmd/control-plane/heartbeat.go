package main

import (
	"encoding/json"
	"io"
	"net/http"
)

type hostHeartbeatRequest struct {
	InstanceName    string `json:"instance_name"`
	Zone            string `json:"zone"`
	GRPCAddress     string `json:"grpc_address"`
	HTTPAddress     string `json:"http_address"`
	TotalSlots      int    `json:"total_slots"`
	UsedSlots       int    `json:"used_slots"`
	IdleRunners     int    `json:"idle_runners"`
	BusyRunners     int    `json:"busy_runners"`
	SnapshotVersion string `json:"snapshot_version"`
	Draining        bool   `json:"draining"`
}

type hostHeartbeatResponse struct {
	Acknowledged bool   `json:"acknowledged"`
	ShouldDrain  bool   `json:"should_drain"`
	Error        string `json:"error,omitempty"`
}

func (s *ControlPlaneServer) HandleHostHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	var req hostHeartbeatRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.InstanceName == "" {
		http.Error(w, "missing instance_name", http.StatusBadRequest)
		return
	}

	_, shouldDrain, err := s.hostRegistry.UpsertHeartbeat(r.Context(), HostHeartbeat{
		InstanceName:    req.InstanceName,
		Zone:            req.Zone,
		GRPCAddress:     req.GRPCAddress,
		HTTPAddress:     req.HTTPAddress,
		TotalSlots:      req.TotalSlots,
		UsedSlots:       req.UsedSlots,
		IdleRunners:     req.IdleRunners,
		BusyRunners:     req.BusyRunners,
		SnapshotVersion: req.SnapshotVersion,
	})
	if err != nil {
		writeJSON(w, http.StatusOK, hostHeartbeatResponse{
			Acknowledged: false,
			Error:        err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, hostHeartbeatResponse{
		Acknowledged: true,
		ShouldDrain:  shouldDrain,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
