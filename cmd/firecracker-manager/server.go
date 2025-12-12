package main

import (
	"context"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/rahul-roy-glean/bazel-firecracker/pkg/runner"
)

// HostAgentServer implements the HostAgent gRPC service
type HostAgentServer struct {
	UnimplementedHostAgentServer
	manager *runner.Manager
	logger  *logrus.Entry
}

// NewHostAgentServer creates a new HostAgentServer
func NewHostAgentServer(mgr *runner.Manager, logger *logrus.Logger) *HostAgentServer {
	return &HostAgentServer{
		manager: mgr,
		logger:  logger.WithField("service", "host-agent"),
	}
}

// AllocateRunner allocates a new runner
func (s *HostAgentServer) AllocateRunner(ctx context.Context, req *AllocateRunnerRequest) (*AllocateRunnerResponse, error) {
	s.logger.WithFields(logrus.Fields{
		"request_id": req.RequestId,
		"repo":       req.Repo,
		"branch":     req.Branch,
	}).Info("AllocateRunner request")

	allocReq := runner.AllocateRequest{
		RequestID:         req.RequestId,
		Repo:              req.Repo,
		Branch:            req.Branch,
		Commit:            req.Commit,
		GitHubRunnerToken: req.GithubRunnerToken,
		Labels:            req.Labels,
	}

	if req.Resources != nil {
		allocReq.Resources = runner.Resources{
			VCPUs:    int(req.Resources.Vcpus),
			MemoryMB: int(req.Resources.MemoryMb),
			DiskGB:   int(req.Resources.DiskGb),
		}
	}

	r, err := s.manager.AllocateRunner(ctx, allocReq)
	if err != nil {
		s.logger.WithError(err).Error("Failed to allocate runner")
		return &AllocateRunnerResponse{
			Error: err.Error(),
		}, nil
	}

	return &AllocateRunnerResponse{
		Runner: runnerToProto(r),
	}, nil
}

// ReleaseRunner releases a runner
func (s *HostAgentServer) ReleaseRunner(ctx context.Context, req *ReleaseRunnerRequest) (*ReleaseRunnerResponse, error) {
	s.logger.WithFields(logrus.Fields{
		"runner_id": req.RunnerId,
		"destroy":   req.Destroy,
	}).Info("ReleaseRunner request")

	err := s.manager.ReleaseRunner(req.RunnerId, req.Destroy)
	if err != nil {
		s.logger.WithError(err).Error("Failed to release runner")
		return &ReleaseRunnerResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	return &ReleaseRunnerResponse{
		Success: true,
	}, nil
}

// GetHostStatus returns the host status
func (s *HostAgentServer) GetHostStatus(ctx context.Context, req *GetHostStatusRequest) (*HostStatus, error) {
	status := s.manager.GetStatus()

	return &HostStatus{
		TotalSlots:      int32(status.TotalSlots),
		UsedSlots:       int32(status.UsedSlots),
		IdleRunners:     int32(status.IdleRunners),
		BusyRunners:     int32(status.BusyRunners),
		SnapshotVersion: status.SnapshotVersion,
	}, nil
}

// Heartbeat handles heartbeat requests
func (s *HostAgentServer) Heartbeat(ctx context.Context, req *HeartbeatRequest) (*HeartbeatResponse, error) {
	return &HeartbeatResponse{
		Acknowledged: true,
	}, nil
}

// SyncSnapshot triggers a snapshot sync
func (s *HostAgentServer) SyncSnapshot(ctx context.Context, req *SyncSnapshotRequest) (*SyncSnapshotResponse, error) {
	s.logger.WithField("version", req.Version).Info("SyncSnapshot request")

	err := s.manager.SyncSnapshot(ctx, req.Version)
	if err != nil {
		s.logger.WithError(err).Error("Failed to sync snapshot")
		return &SyncSnapshotResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	return &SyncSnapshotResponse{
		Success:       true,
		SyncedVersion: req.Version,
	}, nil
}

// ListRunners lists all runners
func (s *HostAgentServer) ListRunners(ctx context.Context, req *ListRunnersRequest) (*ListRunnersResponse, error) {
	var stateFilter runner.State
	switch req.StateFilter {
	case RunnerState_RUNNER_STATE_IDLE:
		stateFilter = runner.StateIdle
	case RunnerState_RUNNER_STATE_BUSY:
		stateFilter = runner.StateBusy
	case RunnerState_RUNNER_STATE_INITIALIZING:
		stateFilter = runner.StateInitializing
	}

	runners := s.manager.ListRunners(stateFilter)

	var protoRunners []*Runner
	for _, r := range runners {
		protoRunners = append(protoRunners, runnerToProto(r))
	}

	return &ListRunnersResponse{
		Runners: protoRunners,
	}, nil
}

// GetRunner gets a specific runner
func (s *HostAgentServer) GetRunner(ctx context.Context, req *GetRunnerRequest) (*Runner, error) {
	r, err := s.manager.GetRunner(req.RunnerId)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}

	return runnerToProto(r), nil
}

func (s *HostAgentServer) QuarantineRunner(ctx context.Context, req *QuarantineRunnerRequest) (*QuarantineRunnerResponse, error) {
	s.logger.WithFields(logrus.Fields{
		"runner_id":    req.RunnerId,
		"block_egress": req.BlockEgress,
		"pause_vm":     req.PauseVm,
	}).Info("QuarantineRunner request")

	var blockEgress *bool
	if req.BlockEgress {
		v := true
		blockEgress = &v
	}
	var pauseVM *bool
	if req.PauseVm {
		v := true
		pauseVM = &v
	}

	dir, err := s.manager.QuarantineRunner(ctx, req.RunnerId, runner.QuarantineOptions{
		Reason:      req.Reason,
		BlockEgress: blockEgress,
		PauseVM:     pauseVM,
	})
	if err != nil {
		return &QuarantineRunnerResponse{Success: false, Error: err.Error()}, nil
	}
	return &QuarantineRunnerResponse{Success: true, QuarantineDir: dir}, nil
}

func (s *HostAgentServer) UnquarantineRunner(ctx context.Context, req *UnquarantineRunnerRequest) (*UnquarantineRunnerResponse, error) {
	s.logger.WithFields(logrus.Fields{
		"runner_id":      req.RunnerId,
		"unblock_egress": req.UnblockEgress,
		"resume_vm":      req.ResumeVm,
	}).Info("UnquarantineRunner request")

	var unblockEgress *bool
	if req.UnblockEgress {
		v := true
		unblockEgress = &v
	}
	var resumeVM *bool
	if req.ResumeVm {
		v := true
		resumeVM = &v
	}

	if err := s.manager.UnquarantineRunner(ctx, req.RunnerId, runner.UnquarantineOptions{
		UnblockEgress: unblockEgress,
		ResumeVM:      resumeVM,
	}); err != nil {
		return &UnquarantineRunnerResponse{Success: false, Error: err.Error()}, nil
	}
	return &UnquarantineRunnerResponse{Success: true}, nil
}

// runnerToProto converts a runner to protobuf
func runnerToProto(r *runner.Runner) *Runner {
	state := RunnerState_RUNNER_STATE_UNSPECIFIED
	switch r.State {
	case runner.StateCold:
		state = RunnerState_RUNNER_STATE_COLD
	case runner.StateBooting:
		state = RunnerState_RUNNER_STATE_BOOTING
	case runner.StateInitializing:
		state = RunnerState_RUNNER_STATE_INITIALIZING
	case runner.StateIdle:
		state = RunnerState_RUNNER_STATE_IDLE
	case runner.StateBusy:
		state = RunnerState_RUNNER_STATE_BUSY
	case runner.StateDraining:
		state = RunnerState_RUNNER_STATE_DRAINING
	case runner.StateQuarantined:
		state = RunnerState_RUNNER_STATE_QUARANTINED
	case runner.StateRetiring:
		state = RunnerState_RUNNER_STATE_RETIRING
	case runner.StateTerminated:
		state = RunnerState_RUNNER_STATE_TERMINATED
	}

	proto := &Runner{
		Id:              r.ID,
		HostId:          r.HostID,
		State:           state,
		InternalIp:      r.InternalIP.String(),
		GithubRunnerId:  r.GitHubRunnerID,
		JobId:           r.JobID,
		SnapshotVersion: r.SnapshotVersion,
		CreatedAt:       timestamppb.New(r.CreatedAt),
		Resources: &Resources{
			Vcpus:    int32(r.Resources.VCPUs),
			MemoryMb: int32(r.Resources.MemoryMB),
			DiskGb:   int32(r.Resources.DiskGB),
		},
	}

	if !r.StartedAt.IsZero() {
		proto.StartedAt = timestamppb.New(r.StartedAt)
	}

	return proto
}

// Proto types placeholders - these would normally be generated from proto
type AllocateRunnerRequest struct {
	RequestId         string
	Repo              string
	Branch            string
	Commit            string
	Resources         *Resources
	Labels            map[string]string
	GithubRunnerToken string
}

type AllocateRunnerResponse struct {
	Runner *Runner
	Error  string
}

type ReleaseRunnerRequest struct {
	RunnerId string
	Destroy  bool
}

type ReleaseRunnerResponse struct {
	Success bool
	Error   string
}

type GetHostStatusRequest struct{}

type HostStatus struct {
	HostId          string
	InstanceName    string
	Zone            string
	State           HostState
	TotalSlots      int32
	UsedSlots       int32
	IdleRunners     int32
	BusyRunners     int32
	CpuUsage        float64
	MemoryUsage     float64
	DiskUsage       float64
	SnapshotVersion string
}

type HeartbeatRequest struct {
	HostId string
	Status *HostStatus
}

type HeartbeatResponse struct {
	Acknowledged       bool
	SnapshotVersion    string
	ShouldSyncSnapshot bool
	ShouldDrain        bool
}

type SyncSnapshotRequest struct {
	Version string
}

type SyncSnapshotResponse struct {
	Success       bool
	Error         string
	SyncedVersion string
}

type ListRunnersRequest struct {
	StateFilter RunnerState
}

type ListRunnersResponse struct {
	Runners []*Runner
}

type GetRunnerRequest struct {
	RunnerId string
}

type QuarantineRunnerRequest struct {
	RunnerId    string
	Reason      string
	BlockEgress bool
	PauseVm     bool
}

type QuarantineRunnerResponse struct {
	Success       bool
	Error         string
	QuarantineDir string
}

type UnquarantineRunnerRequest struct {
	RunnerId      string
	UnblockEgress bool
	ResumeVm      bool
}

type UnquarantineRunnerResponse struct {
	Success bool
	Error   string
}

type Runner struct {
	Id              string
	HostId          string
	State           RunnerState
	InternalIp      string
	GithubRunnerId  string
	JobId           string
	SnapshotVersion string
	CreatedAt       *timestamppb.Timestamp
	StartedAt       *timestamppb.Timestamp
	Resources       *Resources
}

type Resources struct {
	Vcpus    int32
	MemoryMb int32
	DiskGb   int32
}

type RunnerState int32

const (
	RunnerState_RUNNER_STATE_UNSPECIFIED  RunnerState = 0
	RunnerState_RUNNER_STATE_COLD         RunnerState = 1
	RunnerState_RUNNER_STATE_BOOTING      RunnerState = 2
	RunnerState_RUNNER_STATE_INITIALIZING RunnerState = 3
	RunnerState_RUNNER_STATE_IDLE         RunnerState = 4
	RunnerState_RUNNER_STATE_BUSY         RunnerState = 5
	RunnerState_RUNNER_STATE_DRAINING     RunnerState = 6
	RunnerState_RUNNER_STATE_QUARANTINED  RunnerState = 7
	RunnerState_RUNNER_STATE_RETIRING     RunnerState = 8
	RunnerState_RUNNER_STATE_TERMINATED   RunnerState = 9
)

type HostState int32

const (
	HostState_HOST_STATE_UNSPECIFIED HostState = 0
	HostState_HOST_STATE_STARTING    HostState = 1
	HostState_HOST_STATE_READY       HostState = 2
	HostState_HOST_STATE_DRAINING    HostState = 3
	HostState_HOST_STATE_UNHEALTHY   HostState = 4
)

// UnimplementedHostAgentServer for forward compatibility
type UnimplementedHostAgentServer struct{}

func (UnimplementedHostAgentServer) AllocateRunner(context.Context, *AllocateRunnerRequest) (*AllocateRunnerResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AllocateRunner not implemented")
}
func (UnimplementedHostAgentServer) ReleaseRunner(context.Context, *ReleaseRunnerRequest) (*ReleaseRunnerResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ReleaseRunner not implemented")
}
func (UnimplementedHostAgentServer) GetHostStatus(context.Context, *GetHostStatusRequest) (*HostStatus, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetHostStatus not implemented")
}
func (UnimplementedHostAgentServer) Heartbeat(context.Context, *HeartbeatRequest) (*HeartbeatResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Heartbeat not implemented")
}
func (UnimplementedHostAgentServer) SyncSnapshot(context.Context, *SyncSnapshotRequest) (*SyncSnapshotResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SyncSnapshot not implemented")
}
func (UnimplementedHostAgentServer) ListRunners(context.Context, *ListRunnersRequest) (*ListRunnersResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListRunners not implemented")
}
func (UnimplementedHostAgentServer) GetRunner(context.Context, *GetRunnerRequest) (*Runner, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetRunner not implemented")
}
func (UnimplementedHostAgentServer) QuarantineRunner(context.Context, *QuarantineRunnerRequest) (*QuarantineRunnerResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method QuarantineRunner not implemented")
}
func (UnimplementedHostAgentServer) UnquarantineRunner(context.Context, *UnquarantineRunnerRequest) (*UnquarantineRunnerResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UnquarantineRunner not implemented")
}

// RegisterHostAgentServer registers the service
func RegisterHostAgentServer(s *grpc.Server, srv *HostAgentServer) {
	// In production, this would use the generated registration function
}
