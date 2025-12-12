## Helm example: `firecracker-runner`

This directory contains a minimal example for deploying the control plane using Helm.

### Files
- **`values.yaml`**: Example Helm values (replace `PROJECT_ID`, `ENV`, and domain placeholders).
- **`secrets.example.yaml`**: Example Kubernetes Secrets for DB + GitHub webhook secret.
- **`install.example.sh`**: Example `helm upgrade --install` command with the right `--set` escaping.

### Usage
1. Create secrets (edit first):

```bash
kubectl apply -f secrets.example.yaml
```

2. Install via Helm (edit env vars / placeholders first):

```bash
chmod +x install.example.sh
PROJECT_ID=your-project-id ENV=dev CONTROL_PLANE_DOMAIN=runners.example.com ./install.example.sh
```


