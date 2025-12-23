package main

import (
	"context"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/rahul-roy-glean/bazel-firecracker/api/proto/runner"
	"github.com/rahul-roy-glean/bazel-firecracker/pkg/runner"
)

// HostAgentServer implements the HostAgent gRPC service
type HostAgentServer struct {
	pb.UnimplementedHostAgentServer
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
func (s *HostAgentServer) AllocateRunner(ctx context.Context, req *pb.AllocateRunnerRequest) (*pb.AllocateRunnerResponse, error) {
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
		return &pb.AllocateRunnerResponse{
			Error: err.Error(),
		}, nil
	}

	return &pb.AllocateRunnerResponse{
		Runner: runnerToProto(r),
	}, nil
}

// ReleaseRunner releases a runner
func (s *HostAgentServer) ReleaseRunner(ctx context.Context, req *pb.ReleaseRunnerRequest) (*pb.ReleaseRunnerResponse, error) {
	s.logger.WithFields(logrus.Fields{
		"runner_id": req.RunnerId,
		"destroy":   req.Destroy,
	}).Info("ReleaseRunner request")

	err := s.manager.ReleaseRunner(req.RunnerId, req.Destroy)
	if err != nil {
		s.logger.WithError(err).Error("Failed to release runner")
		return &pb.ReleaseRunnerResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	return &pb.ReleaseRunnerResponse{
		Success: true,
	}, nil
}

// GetHostStatus returns the host status
func (s *HostAgentServer) GetHostStatus(ctx context.Context, req *pb.GetHostStatusRequest) (*pb.HostStatus, error) {
	st := s.manager.GetStatus()

	return &pb.HostStatus{
		TotalSlots:      int32(st.TotalSlots),
		UsedSlots:       int32(st.UsedSlots),
		IdleRunners:     int32(st.IdleRunners),
		BusyRunners:     int32(st.BusyRunners),
		SnapshotVersion: st.SnapshotVersion,
	}, nil
}

// SyncSnapshot triggers a snapshot sync
func (s *HostAgentServer) SyncSnapshot(ctx context.Context, req *pb.SyncSnapshotRequest) (*pb.SyncSnapshotResponse, error) {
	s.logger.WithField("version", req.Version).Info("SyncSnapshot request")

	err := s.manager.SyncSnapshot(ctx, req.Version)
	if err != nil {
		s.logger.WithError(err).Error("Failed to sync snapshot")
		return &pb.SyncSnapshotResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	return &pb.SyncSnapshotResponse{
		Success:       true,
		SyncedVersion: req.Version,
	}, nil
}

// ListRunners lists all runners
func (s *HostAgentServer) ListRunners(ctx context.Context, req *pb.ListRunnersRequest) (*pb.ListRunnersResponse, error) {
	var stateFilter runner.State
	switch req.StateFilter {
	case pb.RunnerState_RUNNER_STATE_IDLE:
		stateFilter = runner.StateIdle
	case pb.RunnerState_RUNNER_STATE_BUSY:
		stateFilter = runner.StateBusy
	case pb.RunnerState_RUNNER_STATE_INITIALIZING:
		stateFilter = runner.StateInitializing
	}

	runners := s.manager.ListRunners(stateFilter)

	var protoRunners []*pb.Runner
	for _, r := range runners {
		protoRunners = append(protoRunners, runnerToProto(r))
	}

	return &pb.ListRunnersResponse{
		Runners: protoRunners,
	}, nil
}

// GetRunner gets a specific runner
func (s *HostAgentServer) GetRunner(ctx context.Context, req *pb.GetRunnerRequest) (*pb.Runner, error) {
	r, err := s.manager.GetRunner(req.RunnerId)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}

	return runnerToProto(r), nil
}

func (s *HostAgentServer) QuarantineRunner(ctx context.Context, req *pb.QuarantineRunnerRequest) (*pb.QuarantineRunnerResponse, error) {
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
		return &pb.QuarantineRunnerResponse{Success: false, Error: err.Error()}, nil
	}
	return &pb.QuarantineRunnerResponse{Success: true, QuarantineDir: dir}, nil
}

func (s *HostAgentServer) UnquarantineRunner(ctx context.Context, req *pb.UnquarantineRunnerRequest) (*pb.UnquarantineRunnerResponse, error) {
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
		return &pb.UnquarantineRunnerResponse{Success: false, Error: err.Error()}, nil
	}
	return &pb.UnquarantineRunnerResponse{Success: true}, nil
}

// runnerToProto converts a runner to protobuf
func runnerToProto(r *runner.Runner) *pb.Runner {
	state := pb.RunnerState_RUNNER_STATE_UNSPECIFIED
	switch r.State {
	case runner.StateCold:
		state = pb.RunnerState_RUNNER_STATE_COLD
	case runner.StateBooting:
		state = pb.RunnerState_RUNNER_STATE_BOOTING
	case runner.StateInitializing:
		state = pb.RunnerState_RUNNER_STATE_INITIALIZING
	case runner.StateIdle:
		state = pb.RunnerState_RUNNER_STATE_IDLE
	case runner.StateBusy:
		state = pb.RunnerState_RUNNER_STATE_BUSY
	case runner.StateDraining:
		state = pb.RunnerState_RUNNER_STATE_DRAINING
	case runner.StateQuarantined:
		state = pb.RunnerState_RUNNER_STATE_QUARANTINED
	case runner.StateRetiring:
		state = pb.RunnerState_RUNNER_STATE_RETIRING
	case runner.StateTerminated:
		state = pb.RunnerState_RUNNER_STATE_TERMINATED
	}

	proto := &pb.Runner{
		Id:              r.ID,
		HostId:          r.HostID,
		State:           state,
		InternalIp:      r.InternalIP.String(),
		GithubRunnerId:  r.GitHubRunnerID,
		JobId:           r.JobID,
		SnapshotVersion: r.SnapshotVersion,
		CreatedAt:       timestamppb.New(r.CreatedAt),
		Resources: &pb.Resources{
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
