# Getting Started with Kagenti Operator

> **Note**: This guide assumes you have already installed the Kagenti platform using the [Kagenti installer](https://github.com/kagenti/kagenti/blob/main/deployments/ansible/README.md).

## Overview

The Kagenti Operator manages AI Agent deployments through two Custom Resources:

- **Agent**: Deploys an AI agent (required)
- **AgentBuild**: Builds container images from GitHub source (optional - only needed for build-from-source)

---

## Deploy an Agent from Existing Image

### Quick Example Deployment

```yaml
kubectl apply -f - <<EOF
apiVersion: agent.kagenti.dev/v1alpha1
kind: Agent
metadata:
  name: my-weather-agent
  namespace: team1
  labels:
    kagenti.io/framework: LangGraph
    kagenti.io/protocol: a2a
    kagenti.io/type: agent
    kagenti-enabled: "true"
spec:
  imageSource:
    image: "ghcr.io/kagenti/agent-examples/weather_service:v0.0.1-alpha.3"
  podTemplateSpec:
    spec:
      containers:
      - name: agent
        ports:
        - containerPort: 8000
        imagePullPolicy: Always
        env:
        - name: PORT
          value: "8000"
        - name: UV_CACHE_DIR
          value: /app/.cache/uv
EOF    
```

**Check Status**:
```bash

# Check status
kubectl get agent my-weather-agent -n team1

# View logs
kubectl logs -l app.kubernetes.io/name=my-weather-agent -n team1
```

---

## Build and Deploy from GitHub Source

### Step 1: Create AgentBuild

This builds a container image from your GitHub repository.

```yaml
apiVersion: agent.kagenti.dev/v1alpha1
kind: AgentBuild
metadata:
  name: my-agent-build
  namespace: team1
spec:
  source:
    sourceRepository: "github.com/myorg/my-agent.git"
    sourceRevision: "main"
    # For private repos (optional):
    # sourceCredentials:
    #   name: github-token-secret
  
  buildOutput:
    image: "my-agent"
    imageTag: "v1.0.0"
    imageRegistry: "registry.cr-system.svc.cluster.local:5000"
```

**Apply and monitor**:
```bash
kubectl apply -f my-agent-build.yaml

# Watch build progress
kubectl get agentbuild my-agent-build -n team1 -w

# Check when phase becomes "Succeeded"
```

### Step 2: Deploy Agent Using Built Image

```yaml
apiVersion: agent.kagenti.dev/v1alpha1
kind: Agent
metadata:
  name: my-agent
  namespace  team1
spec:
  imageSource:
    buildRef:
      name: my-agent-build  # References the AgentBuild above
  
  podTemplateSpec:
    spec:
      containers:
      - name: agent
        ports:
        - containerPort: 8000
```

**Deploy**:
```bash
kubectl apply -f my-agent.yaml

# Verify it's using the built image
kubectl get agent my-agent -n team1 -o yaml | grep builtImage
```

---

## Complete Example (Both in One File)

```yaml
---
# First: Build from source
apiVersion: agent.kagenti.dev/v1alpha1
kind: AgentBuild
metadata:
  name: weather-agent-build
  namespace: team1
spec:
  source:
    sourceRepository: "github.com/kagenti/agent-examples.git"
    sourceRevision: "main"
    sourceSubfolder: "weather-service"
  buildOutput:
    image: "weather-agent"
    imageTag: "v1.0.0"
    imageRegistry: "registry.cr-system.svc.cluster.local:5000"
---
# Second: Deploy using built image
apiVersion: agent.kagenti.dev/v1alpha1
kind: Agent
metadata:
  name: weather-agent
  namespace: team1
spec:
  imageSource:
    buildRef:
      name: weather-agent-build
  
  servicePorts:
  - name: http
    port: 8000
    targetPort: 8000
  
  podTemplateSpec:
    spec:
      containers:
      - name: agent
        ports:
        - containerPort: 8000
        env:
        - name: PORT
          value: "8000"
```

**Deploy both**:
```bash
kubectl apply -f weather-agent-example.yaml

# 1. Build will start first
kubectl get agentbuild weather-agent-build -n team1 -w

# 2. Once build succeeds, agent will deploy
kubectl get agent weather-agent -n team1
```

---

## Build Modes

The `mode` field determines which build pipeline to use:

| Mode | Use Case | Dockerfile Required |
|------|----------|---------------------|
| `dev` (default) | Auto-detects build method | Optional |
| `buildpack-dev` | Force Cloud Native Buildpacks | No |
| `dev-local` | Local registry | Optional |
| `dev-external` | External registry (ghcr.io, etc.) | Optional |

**Example with mode**:
```yaml
spec:
  mode: buildpack-dev  # No Dockerfile needed!
  source:
    sourceRepository: "github.com/myorg/python-app.git"
```

---

## Checking Status

### Agent Status

```bash
# List agents
kubectl get agents -n team1

# Detailed status
kubectl describe agent my-agent -n team1

# Check deployment phase
kubectl get agent my-agent -n team1 -o jsonpath='{.status.deploymentStatus.phase}'
# Should show: Ready
```

### AgentBuild Status

```bash
# List builds
kubectl get agentbuilds -n team1

# Check build phase
kubectl get agentbuild my-build -n team1 -o jsonpath='{.status.phase}'
# Phases: Pending → Building → Succeeded (or Failed)

# View build logs
PIPELINE=$(kubectl get agentbuild my-build -n team1 -o jsonpath='{.status.pipelineRunName}')
kubectl logs -f $(kubectl get pods -n team1 -l tekton.dev/pipelineRun=$PIPELINE -o name | head -1)
```

---

## Troubleshooting

### Agent Not Starting

```bash
# Check if using BuildRef
kubectl get agent my-agent -n team1 -o yaml | grep buildRef

# If yes, verify build succeeded
kubectl get agentbuild <referenced-build> -n team1 -o jsonpath='{.status.phase}'
# Should show: Succeeded

# Check events
kubectl get events -n team1 --field-selector involvedObject.name=my-agent
```

### Build Failing

```bash
# Check build status
kubectl get agentbuild my-build -n team1 -o yaml | grep -A10 status

# View build logs
kubectl get pods -n team1 -l app.kubernetes.io/component=my-build
kubectl logs <pod-name> -n team1
```

---

## Secrets (For Private Repos/Registries)

### GitHub Token
```bash
kubectl create secret generic github-token-secret \
  --from-literal=username=myusername \
  --from-literal=password=ghp_mytoken \
  -n team1
```

### Registry Credentials
```bash
kubectl create secret docker-registry ghcr-secret \
  --docker-server=ghcr.io \
  --docker-username=myusername \
  --docker-password=ghp_mytoken \
  -n team1
```

**Use in AgentBuild**:
```yaml
spec:
  source:
    sourceCredentials:
      name: github-token-secret
  buildOutput:
    imageRepoCredentials:
      name: ghcr-secret
```

---

## Next Steps

- **Custom Pipelines**: See [Pipeline Templates Guide](docs/pipeline-templates-guide.md)
- **Advanced Configuration**: See `config/samples/` for more examples
- **Webhook Details**: See [AgentBuild Webhook](docs/agentbuild-webhook.md)

---

## Quick Reference

**Minimal Agent (existing image)**:
```yaml
apiVersion: agent.kagenti.dev/v1alpha1
kind: Agent
metadata: {name: my-agent, namespace: kagenti}
spec:
  imageSource: {image: "nginx:alpine"}
  podTemplateSpec: {spec: {containers: [{name: agent}]}}
```

**Minimal AgentBuild** (auto-defaults):
```yaml
apiVersion: agent.kagenti.dev/v1alpha1
kind: AgentBuild
metadata: {name: my-build, namespace: kagenti}
spec:
  source: {sourceRepository: "github.com/org/repo.git"}
  buildOutput: {image: "app", imageTag: "v1", imageRegistry: "registry.cr-system.svc.cluster.local:5000"}
```

**Status Commands**:
```bash
kubectl get agent,agentbuild -n team1
kubectl describe agent <name> -n team1
kubectl logs -l app.kubernetes.io/name=<agent-name> -n team1