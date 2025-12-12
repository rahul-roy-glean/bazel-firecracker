#!/usr/bin/env bash
set -euo pipefail

# Example installer for the Helm chart.
# Replace these with real values before running.

PROJECT_ID="${PROJECT_ID:-REPLACE_ME}"
ENV="${ENV:-dev}"
NAMESPACE="${NAMESPACE:-firecracker-runner}"
CONTROL_PLANE_DOMAIN="${CONTROL_PLANE_DOMAIN:-runners.example.com}"

# Optional: ensure kubectl is pointing at the right cluster.
# gcloud container clusters get-credentials firecracker-runner-${ENV}-control-plane --region us-central1 --project "${PROJECT_ID}"

helm upgrade --install firecracker-runner ../../deploy/helm/firecracker-runner \
  --namespace "${NAMESPACE}" --create-namespace \
  -f values.yaml \
  --set "image.repository=gcr.io/${PROJECT_ID}/firecracker-control-plane" \
  --set "serviceAccount.annotations.iam\\.gke\\.io/gcp-service-account=firecracker-runner-${ENV}-control-plane@${PROJECT_ID}.iam.gserviceaccount.com" \
  --set "config.gcsBucket=${PROJECT_ID}-firecracker-snapshots" \
  --set "ingress.hosts[0].host=${CONTROL_PLANE_DOMAIN}"

echo "Rendered manifests:"
helm template firecracker-runner ../../deploy/helm/firecracker-runner \
  --namespace "${NAMESPACE}" \
  -f values.yaml \
  --set "image.repository=gcr.io/${PROJECT_ID}/firecracker-control-plane" \
  --set "serviceAccount.annotations.iam\\.gke\\.io/gcp-service-account=firecracker-runner-${ENV}-control-plane@${PROJECT_ID}.iam.gserviceaccount.com" \
  --set "config.gcsBucket=${PROJECT_ID}-firecracker-snapshots" \
  --set "ingress.hosts[0].host=${CONTROL_PLANE_DOMAIN}" \
  >/tmp/firecracker-runner.rendered.yaml

echo "Wrote /tmp/firecracker-runner.rendered.yaml"


