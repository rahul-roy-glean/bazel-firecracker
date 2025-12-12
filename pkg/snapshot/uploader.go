package snapshot

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"cloud.google.com/go/storage"
	"github.com/sirupsen/logrus"
)

// Uploader handles uploading snapshots to GCS
type Uploader struct {
	gcsBucket string
	gcsClient *storage.Client
	logger    *logrus.Entry
}

// UploaderConfig holds configuration for snapshot uploader
type UploaderConfig struct {
	GCSBucket string
	Logger    *logrus.Logger
}

// NewUploader creates a new snapshot uploader
func NewUploader(ctx context.Context, cfg UploaderConfig) (*Uploader, error) {
	client, err := storage.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCS client: %w", err)
	}

	logger := cfg.Logger
	if logger == nil {
		logger = logrus.New()
	}

	return &Uploader{
		gcsBucket: cfg.GCSBucket,
		gcsClient: client,
		logger:    logger.WithField("component", "snapshot-uploader"),
	}, nil
}

// UploadSnapshot uploads a snapshot to GCS
func (u *Uploader) UploadSnapshot(ctx context.Context, localDir string, metadata SnapshotMetadata) error {
	version := metadata.Version
	u.logger.WithField("version", version).Info("Uploading snapshot to GCS")

	start := time.Now()

	// Files to upload
	files := []struct {
		local  string
		remote string
	}{
		{filepath.Join(localDir, "kernel.bin"), fmt.Sprintf("%s/kernel.bin", version)},
		{filepath.Join(localDir, "rootfs.img"), fmt.Sprintf("%s/rootfs.img", version)},
		{filepath.Join(localDir, "snapshot.mem"), fmt.Sprintf("%s/snapshot.mem", version)},
		{filepath.Join(localDir, "snapshot.state"), fmt.Sprintf("%s/snapshot.state", version)},
		{filepath.Join(localDir, "repo-cache-seed.img"), fmt.Sprintf("%s/repo-cache-seed.img", version)},
	}

	bucket := u.gcsClient.Bucket(u.gcsBucket)

	// Upload each file
	for _, f := range files {
		if err := u.uploadFile(ctx, bucket, f.local, f.remote); err != nil {
			return fmt.Errorf("failed to upload %s: %w", f.local, err)
		}
	}

	// Calculate total size
	var totalSize int64
	for _, f := range files {
		info, err := os.Stat(f.local)
		if err == nil {
			totalSize += info.Size()
		}
	}
	metadata.SizeBytes = totalSize

	// Upload metadata
	metadataJSON, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	metadataObj := bucket.Object(fmt.Sprintf("%s/metadata.json", version))
	writer := metadataObj.NewWriter(ctx)
	writer.ContentType = "application/json"
	if _, err := writer.Write(metadataJSON); err != nil {
		writer.Close()
		return fmt.Errorf("failed to write metadata: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("failed to close metadata writer: %w", err)
	}

	duration := time.Since(start)
	u.logger.WithFields(logrus.Fields{
		"version":    version,
		"duration":   duration,
		"size_bytes": totalSize,
	}).Info("Snapshot uploaded successfully")

	return nil
}

// uploadFile uploads a single file to GCS
func (u *Uploader) uploadFile(ctx context.Context, bucket *storage.BucketHandle, localPath, remotePath string) error {
	u.logger.WithFields(logrus.Fields{
		"local":  localPath,
		"remote": remotePath,
	}).Debug("Uploading file")

	file, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	obj := bucket.Object(remotePath)
	writer := obj.NewWriter(ctx)

	// Set content type based on extension
	switch filepath.Ext(localPath) {
	case ".json":
		writer.ContentType = "application/json"
	default:
		writer.ContentType = "application/octet-stream"
	}

	if _, err := io.Copy(writer, file); err != nil {
		writer.Close()
		return fmt.Errorf("failed to copy file: %w", err)
	}

	if err := writer.Close(); err != nil {
		return fmt.Errorf("failed to close writer: %w", err)
	}

	return nil
}

// UpdateCurrentPointer updates the "current" pointer to a new version
func (u *Uploader) UpdateCurrentPointer(ctx context.Context, version string) error {
	u.logger.WithField("version", version).Info("Updating current pointer")

	bucket := u.gcsClient.Bucket(u.gcsBucket)

	// Copy all files from version to current
	files := []string{"kernel.bin", "rootfs.img", "snapshot.mem", "snapshot.state", "repo-cache-seed.img", "metadata.json"}

	for _, file := range files {
		src := bucket.Object(fmt.Sprintf("%s/%s", version, file))
		dst := bucket.Object(fmt.Sprintf("current/%s", file))

		copier := dst.CopierFrom(src)
		if _, err := copier.Run(ctx); err != nil {
			return fmt.Errorf("failed to copy %s to current: %w", file, err)
		}
	}

	u.logger.Info("Current pointer updated successfully")
	return nil
}

// DeleteVersion deletes a snapshot version from GCS
func (u *Uploader) DeleteVersion(ctx context.Context, version string) error {
	u.logger.WithField("version", version).Info("Deleting snapshot version")

	bucket := u.gcsClient.Bucket(u.gcsBucket)

	// List and delete all objects with this prefix
	it := bucket.Objects(ctx, &storage.Query{Prefix: version + "/"})
	for {
		attrs, err := it.Next()
		if err != nil {
			break
		}
		if err := bucket.Object(attrs.Name).Delete(ctx); err != nil {
			u.logger.WithError(err).Warnf("Failed to delete %s", attrs.Name)
		}
	}

	return nil
}

// Close closes the uploader
func (u *Uploader) Close() error {
	if u.gcsClient != nil {
		return u.gcsClient.Close()
	}
	return nil
}
