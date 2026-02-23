# API Reference

This document provides a comprehensive reference for the Kagenti Operator Custom Resource Definitions (CRDs).

## Custom Resources

- [AgentBuild](#agentbuild) — Builds container images from source code
- [AgentCard](#agentcard) — Fetches and stores agent metadata for dynamic discovery

---

## AgentBuild

The `AgentBuild` Custom Resource manages the build process for creating container images from source code using Tekton pipelines.

### API Group and Version

- **API Group:** `agent.kagenti.dev`
- **API Version:** `v1alpha1`
- **Kind:** `AgentBuild`

### Spec Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `source` | [SourceSpec](#sourcespec) | Yes | Source code configuration |
| `pipeline` | [PipelineSpec](#pipelinespec) | No | Pipeline configuration |
| `buildArgs` | [][ParameterSpec](#parameterspec) | No | Build arguments |
| `buildOutput` | [BuildOutput](#buildoutput) | No | Build artifact storage configuration |
| `cleanupAfterBuild` | boolean | No | Cleanup after build (default: true) |
| `mode` | string | No | Pipeline mode: `dev`, `buildpack-dev`, `dev-local`, `dev-external`, `preprod`, `prod`, `custom` (default: `dev`) |
| `labels` | map[string]string | No | Labels to add to build resources |
| `annotations` | map[string]string | No | Annotations to add to build resources |

#### SourceSpec

Configuration for the source code repository.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `sourceRepository` | string | Yes | Git repository URL (e.g., `github.com/myorg/my-agent.git`) |
| `sourceRevision` | string | No | Git revision (branch, tag, or commit) |
| `sourceSubfolder` | string | No | Subfolder within the repository |
| `repoUser` | string | No | Username for the Git repository |
| `sourceCredentials` | [LocalObjectReference](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#localobjectreference-v1-core) | No | Secret containing Git credentials |

#### PipelineSpec

Defines how the Tekton pipeline should be configured.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `namespace` | string | Yes | Namespace where pipeline ConfigMaps are located |
| `steps` | [][PipelineStepSpec](#pipelinestepspec) | No | Ordered list of pipeline steps |
| `parameters` | [][ParameterSpec](#parameterspec) | No | Global pipeline parameters |

#### PipelineStepSpec

Defines a single step in the build pipeline.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Step identifier |
| `configMap` | string | Yes | ConfigMap containing step definition |
| `enabled` | boolean | No | Whether step should be included (default: true) |
| `parameters` | [][ParameterSpec](#parameterspec) | No | Step-specific parameters |
| `requiredParameters` | []string | No | Parameter names that must be provided |
| `whenExpressions` | [][WhenExpression](#whenexpression) | No | Conditional execution rules |

#### ParameterSpec

Defines a parameter for the build or pipeline.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Parameter name |
| `value` | string | Yes | Parameter value |
| `required` | boolean | No | Whether parameter is required (templates only) |
| `description` | string | No | Help text for the parameter |

#### WhenExpression

Conditional execution rule for pipeline steps.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `input` | string | Yes | Value to evaluate (can reference task results) |
| `operator` | string | Yes | Comparison operator: `in` or `notin` |
| `values` | []string | Yes | Values to compare against |

#### BuildOutput

Configuration for where to store the built container image.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `image` | string | Yes | Name of the image to build |
| `imageTag` | string | Yes | Tag to apply to the built image |
| `imageRegistry` | string | Yes | Container registry URL |
| `imageRepoCredentials` | [LocalObjectReference](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#localobjectreference-v1-core) | No | Secret containing registry credentials |

### Status Fields

| Field | Type | Description |
|-------|------|-------------|
| `phase` | string | Current phase: `Pending`, `Building`, `Succeeded`, or `Failed` |
| `message` | string | Human-readable build message |
| `pipelineRunName` | string | Name of the Tekton PipelineRun |
| `lastBuildTime` | timestamp | When the build started |
| `completionTime` | timestamp | When the build completed |
| `builtImage` | string | Full image URL of the built image |
| `conditions` | [][Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#condition-v1-meta) | Overall status conditions |

### Examples

#### Basic Build from GitHub

```yaml
apiVersion: agent.kagenti.dev/v1alpha1
kind: AgentBuild
metadata:
  name: weather-agent-build
  namespace: default
spec:
  mode: dev

  source:
    sourceRepository: "github.com/kagenti/agent-examples.git"
    sourceRevision: "main"
    sourceSubfolder: "a2a/weather_service"
    sourceCredentials:
      name: github-token-secret

  buildOutput:
    image: "weather-agent"
    imageTag: "v1.0.0"
    imageRegistry: "ghcr.io/myorg"
    imageRepoCredentials:
      name: ghcr-secret
```

#### Build with Custom Pipeline Steps

```yaml
apiVersion: agent.kagenti.dev/v1alpha1
kind: AgentBuild
metadata:
  name: advanced-agent-build
  namespace: default
spec:
  mode: custom

  source:
    sourceRepository: "github.com/myorg/advanced-agent.git"
    sourceRevision: "v2.0.0"
    sourceCredentials:
      name: github-token-secret

  pipeline:
    namespace: kagenti-system
    steps:
      - name: fetch-source
        configMap: fetch-source-task
        enabled: true
      - name: run-tests
        configMap: test-task
        enabled: true
        parameters:
          - name: TEST_ARGS
            value: "--verbose"
      - name: build-image
        configMap: kaniko-build-task
        enabled: true
        parameters:
          - name: DOCKERFILE
            value: "./Dockerfile"
      - name: push-image
        configMap: push-image-task
        enabled: true

    parameters:
      - name: SOURCE_REPO_SECRET
        value: github-token-secret
      - name: BUILD_CONTEXT
        value: "."

  buildArgs:
    - name: PYTHON_VERSION
      value: "3.11"
    - name: BUILD_ENV
      value: "production"

  buildOutput:
    image: "advanced-agent"
    imageTag: "2.0.0"
    imageRegistry: "registry.example.com"
    imageRepoCredentials:
      name: registry-credentials

  cleanupAfterBuild: false
```

#### Build with Cloud Native Buildpacks

```yaml
apiVersion: agent.kagenti.dev/v1alpha1
kind: AgentBuild
metadata:
  name: buildpack-agent-build
  namespace: default
spec:
  mode: buildpack-dev

  source:
    sourceRepository: "github.com/myorg/python-agent.git"
    sourceRevision: "main"
    sourceCredentials:
      name: github-token-secret

  pipeline:
    namespace: kagenti-system
    parameters:
      - name: SOURCE_REPO_SECRET
        value: github-token-secret
      - name: BUILDER_IMAGE
        value: "paketobuildpacks/builder:base"

  buildOutput:
    image: "python-agent"
    imageTag: "latest"
    imageRegistry: "ghcr.io/myorg"
    imageRepoCredentials:
      name: ghcr-secret
```

---

## Common Patterns

### Using Secrets

#### GitHub Token Secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: github-token-secret
  namespace: default
type: Opaque
stringData:
  username: myuser
  password: ghp_xxxxxxxxxxxxxxxxxxxx
```

#### Container Registry Secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: ghcr-secret
  namespace: default
type: kubernetes.io/dockerconfigjson
stringData:
  .dockerconfigjson: |
    {
      "auths": {
        "ghcr.io": {
          "username": "myuser",
          "password": "ghp_xxxxxxxxxxxxxxxxxxxx",
          "auth": "base64-encoded-credentials"
        }
      }
    }
```

### Complete Build and Deploy Workflow

```yaml
# 1. Create secrets
---
apiVersion: v1
kind: Secret
metadata:
  name: github-token-secret
  namespace: default
type: Opaque
stringData:
  username: myuser
  password: ghp_xxxxxxxxxxxxxxxxxxxx

---
apiVersion: v1
kind: Secret
metadata:
  name: ghcr-secret
  namespace: default
type: kubernetes.io/dockerconfigjson
stringData:
  .dockerconfigjson: |
    {
      "auths": {
        "ghcr.io": {
          "username": "myuser",
          "password": "ghp_xxxxxxxxxxxxxxxxxxxx"
        }
      }
    }

# 2. Create build
---
apiVersion: agent.kagenti.dev/v1alpha1
kind: AgentBuild
metadata:
  name: my-agent-build
  namespace: default
spec:
  mode: dev
  source:
    sourceRepository: "github.com/myorg/my-agent.git"
    sourceRevision: "main"
    sourceCredentials:
      name: github-token-secret
  buildOutput:
    image: "my-agent"
    imageTag: "v1.0.0"
    imageRegistry: "ghcr.io/myorg"
    imageRepoCredentials:
      name: ghcr-secret

# 3. Deploy agent (standard Deployment)
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-agent
  namespace: default
  labels:
    kagenti.io/type: agent
    kagenti.io/protocol: a2a
    app.kubernetes.io/name: my-agent
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: my-agent
  template:
    metadata:
      labels:
        app.kubernetes.io/name: my-agent
    spec:
      containers:
      - name: agent
        image: "ghcr.io/myorg/my-agent:v1.0.0"  # Use builtImage from AgentBuild status
        ports:
        - containerPort: 8080

# 4. Create AgentCard for discovery
---
apiVersion: agent.kagenti.dev/v1alpha1
kind: AgentCard
metadata:
  name: my-agent-card
  namespace: default
spec:
  syncPeriod: 30s
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: my-agent
```

---

## Status and Monitoring

### Check Build Status

```bash
# List all builds
kubectl get agentbuilds

# Get detailed build status
kubectl describe agentbuild my-agent-build

# Check Tekton PipelineRun
kubectl get pipelineruns -l agent.kagenti.dev/agentbuild=my-agent-build

# View build logs
kubectl logs -l tekton.dev/pipelineRun=<pipelinerun-name>
```

### Common Status Conditions

#### AgentBuild Conditions

| Type | Status | Reason | Description |
|------|--------|--------|-------------|
| `Complete` | `True` | `BuildSucceeded` | Build completed successfully |
| `Complete` | `False` | `BuildFailed` | Build failed |
| `Complete` | `Unknown` | `BuildRunning` | Build in progress |

#### AgentCard Conditions

| Type | Status | Reason | Description |
|------|--------|--------|-------------|
| `Synced` | `True` | `SyncSucceeded` | Agent card fetched successfully |
| `Synced` | `False` | `SyncFailed` | Unable to fetch agent card |
| `Synced` | `False` | `AgentNotReady` | Agent not ready yet |
| `Synced` | `False` | `ProtocolNotSupported` | Unsupported protocol |
| `Synced` | `False` | `InvalidCard` | Card format invalid |
| `Ready` | `True` | `ReadyToServe` | Agent index ready for queries |
| `Ready` | `False` | `NotReady` | Agent index not ready |

---

## AgentCard

The `AgentCard` Custom Resource stores agent metadata for dynamic discovery and introspection. It synchronizes agent card data from deployed agents that implement supported protocols (currently A2A).

### API Group and Version

- **API Group:** `agent.kagenti.dev`
- **API Version:** `v1alpha1`
- **Kind:** `AgentCard`
- **Short Names:** `agentcards`, `cards`

### Spec Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `syncPeriod` | string | No | How often to re-fetch the agent card (default: "30s", format: "30s", "5m", etc.) |
| `targetRef` | [TargetRef](#targetref) | Yes | Identifies the workload backing this agent |
| `identityBinding` | [IdentityBinding](#identitybinding) | No | SPIFFE identity binding configuration |

#### TargetRef

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `apiVersion` | string | Yes | API version of the target resource (e.g., "apps/v1") |
| `kind` | string | Yes | Kind of the target resource (e.g., "Deployment", "StatefulSet") |
| `name` | string | Yes | Name of the target resource |

#### IdentityBinding

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `allowedSpiffeIDs` | []string | Yes | Allowlist of SPIFFE IDs permitted to bind to this agent |
| `strict` | boolean | No | Enable enforcement mode (default: false, audit-only) |

### Status Fields

| Field | Type | Description |
|-------|------|-------------|
| `card` | [AgentCardData](#agentcarddata) | Cached agent card data from the agent |
| `conditions` | [][Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#condition-v1-meta) | Current state of indexing process |
| `lastSyncTime` | timestamp | When the agent card was last successfully fetched |
| `protocol` | string | Detected agent protocol (e.g., "a2a") |
| `targetRef` | [TargetRef](#targetref) | Resolved reference to the backing workload |
| `validSignature` | boolean | Whether the agent card JWS signature is valid |
| `signatureVerificationDetails` | string | Human-readable details about the last signature verification |
| `signatureKeyId` | string | Key ID (`kid`) from the JWS protected header |
| `signatureSpiffeId` | string | SPIFFE ID from the JWS protected header (set only when signature is valid) |
| `signatureIdentityMatch` | boolean | `true` when both signature verification AND identity binding pass |
| `cardId` | string | SHA256 hash of card content for drift detection |
| `expectedSpiffeID` | string | SPIFFE ID used for binding evaluation |
| `bindingStatus` | [BindingStatus](#bindingstatus) | Result of identity binding evaluation |

#### BindingStatus

| Field | Type | Description |
|-------|------|-------------|
| `bound` | boolean | Whether the verified SPIFFE ID is in the allowlist |
| `reason` | string | Machine-readable reason (`Bound`, `NotBound`, `AgentNotFound`) |
| `message` | string | Human-readable description |
| `lastEvaluationTime` | timestamp | When the binding was last evaluated |

#### AgentCardData

Represents the A2A agent card structure based on the [A2A specification](https://a2a-protocol.org/).

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Human-readable name of the agent |
| `description` | string | What the agent does |
| `version` | string | Agent version |
| `url` | string | Endpoint where the agent can be reached |
| `capabilities` | [AgentCapabilities](#agentcapabilities) | Supported A2A features |
| `defaultInputModes` | []string | Default media types the agent accepts |
| `defaultOutputModes` | []string | Default media types the agent produces |
| `skills` | [][AgentSkill](#agentskill) | Skills/capabilities offered by the agent |
| `supportsAuthenticatedExtendedCard` | boolean | Whether agent has an extended card |
| `signatures` | [][AgentCardSignature](#agentcardsignature) | JWS signatures per A2A spec section 8.4.2 |

#### AgentCapabilities

| Field | Type | Description |
|-------|------|-------------|
| `streaming` | boolean | Whether the agent supports streaming responses |
| `pushNotifications` | boolean | Whether the agent supports push notifications |

#### AgentSkill

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Skill identifier |
| `description` | string | What this skill does |
| `inputModes` | []string | Media types this skill accepts |
| `outputModes` | []string | Media types this skill produces |
| `parameters` | [][SkillParameter](#skillparameter) | Parameters this skill accepts |

#### SkillParameter

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Parameter name |
| `type` | string | Parameter type (e.g., "string", "number", "boolean") |
| `description` | string | What this parameter is for |
| `required` | boolean | Whether this parameter must be provided |
| `default` | string | Default value for this parameter |

#### AgentCardSignature

| Field | Type | Description |
|-------|------|-------------|
| `protected` | string | Base64url-encoded JWS protected header (contains `alg`, `kid`, `spiffe_id`) |
| `signature` | string | Base64url-encoded JWS signature value |
| `header` | object | Optional unprotected JWS header parameters (e.g., `timestamp`) |

### Examples

#### Deploy Agent as a Standard Deployment (Recommended)

Create a standard Deployment with agent labels, and an AgentCard with `targetRef`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: weather-agent
  namespace: default
  labels:
    app.kubernetes.io/name: weather-agent
    kagenti.io/type: agent
    kagenti.io/protocol: a2a
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: weather-agent
  template:
    metadata:
      labels:
        app.kubernetes.io/name: weather-agent
    spec:
      containers:
      - name: agent
        image: "ghcr.io/kagenti/agent-examples/weather_service:v0.0.1-alpha.3"
        ports:
        - containerPort: 8000
        env:
        - name: PORT
          value: "8000"
---
apiVersion: agent.kagenti.dev/v1alpha1
kind: AgentCard
metadata:
  name: weather-agent-card
  namespace: default
spec:
  syncPeriod: 30s
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: weather-agent
```

The AgentCard can also be automatically created by the operator when agent labels are present on the Deployment.

#### View Discovered Agents

```bash
# List all agent cards
kubectl get agentcards

# Example output:
# NAME                        PROTOCOL   KIND         TARGET          AGENT             SYNCED   LASTSYNC   AGE
# weather-agent-deployment-card   a2a    Deployment   weather-agent   Weather Assistant  True     5m         10m

# Get detailed information
kubectl describe agentcard weather-agent-deployment-card
```

#### AgentCard Status Example

```yaml
apiVersion: agent.kagenti.dev/v1alpha1
kind: AgentCard
metadata:
  name: weather-agent-deployment-card
  namespace: default
  ownerReferences:
    - apiVersion: apps/v1
      kind: Deployment
      name: weather-agent
      controller: true
spec:
  syncPeriod: 30s
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: weather-agent
status:
  protocol: a2a
  lastSyncTime: "2025-12-19T10:30:00Z"
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: weather-agent

  card:
    name: "Weather Assistant"
    description: "Provides weather information using MCP tools"
    version: "1.0.0"
    url: "http://weather-agent.default.svc.cluster.local:8000"

    capabilities:
      streaming: true
      pushNotifications: false

    defaultInputModes:
      - text
    defaultOutputModes:
      - text

    skills:
      - name: "get-weather"
        description: "Get current weather for a city"
        inputModes:
          - text
        outputModes:
          - text
        parameters:
          - name: "city"
            type: "string"
            description: "City name to get weather for"
            required: true

  conditions:
    - type: Synced
      status: "True"
      reason: SyncSucceeded
      message: "Successfully fetched agent card for Weather Assistant"
      lastTransitionTime: "2025-12-19T10:30:00Z"
    - type: Ready
      status: "True"
      reason: ReadyToServe
      message: "Agent index is ready for queries"
      lastTransitionTime: "2025-12-19T10:30:00Z"
```

#### Query Agent Metadata

```bash
# Get agent name from card
kubectl get agentcard weather-agent-card \
  -o jsonpath='{.status.card.name}'

# List all skills
kubectl get agentcard weather-agent-card \
  -o jsonpath='{.status.card.skills[*].name}'

# Get agent endpoint
kubectl get agentcard weather-agent-card \
  -o jsonpath='{.status.card.url}'

# Check signature verification
kubectl get agentcard weather-agent-card \
  -o jsonpath='{.status.validSignature}'

# Check identity binding
kubectl get agentcard weather-agent-card \
  -o jsonpath='{.status.bindingStatus.bound}'
```

---

```yaml
apiVersion: agent.kagenti.dev/v1alpha1
kind: AgentCard
metadata:
  name: custom-agent-card
  namespace: default
spec:
  syncPeriod: "5m"  # Sync every 5 minutes instead of default 30s
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: custom-agent
```

### Common Status Conditions

#### AgentCard Conditions

| Type | Status | Reason | Description |
|------|--------|--------|-------------|
| `Synced` | `True` | `SyncSucceeded` | Agent card fetched successfully |
| `Synced` | `False` | `WorkloadNotFound` | Referenced workload does not exist |
| `Synced` | `False` | `WorkloadNotReady` | Workload is not ready to serve |
| `Synced` | `False` | `NoProtocol` | Workload missing `kagenti.io/protocol` label |
| `Synced` | `False` | `FetchFailed` | Failed to fetch agent card from endpoint |
| `Synced` | `False` | `SignatureInvalid` | Signature verification failed (enforce mode) |
| `Ready` | `True` | `ReadyToServe` | Agent index ready for queries |
| `SignatureVerified` | `True` | `SignatureValid` | JWS signature verified successfully |
| `SignatureVerified` | `False` | `SignatureInvalid` | JWS signature verification failed |
| `Bound` | `True` | `Bound` | SPIFFE ID is in the allowlist |
| `Bound` | `False` | `NotBound` | SPIFFE ID is not in the allowlist |

---

## Required Labels for Workload-Based Agents

For Deployments and StatefulSets to be automatically discovered by the operator, the following labels are required:

| Label | Value | Required | Description |
|-------|-------|----------|-------------|
| `kagenti.io/type` | `agent` | Yes | Identifies the workload as an agent |
| `kagenti.io/protocol` | `a2a`, `mcp`, etc. | Yes | Protocol for fetching agent card |
| `app.kubernetes.io/name` | `<agent-name>` | Recommended | Standard Kubernetes app name label |

---

## Additional Resources

- [Dynamic Agent Discovery](./dynamic-agent-discovery.md) — How AgentCard enables agent discovery
- [Signature Verification](./a2a-signature-verification.md) — JWS signature verification setup
- [Identity Binding](./identity-binding-quickstart.md) — SPIFFE identity binding guide
- [Architecture Documentation](./architecture.md) — Operator design and components
- [Developer Guide](./dev.md) — Contributing and development
- [Getting Started Tutorial](../GETTING_STARTED.md) — Detailed tutorials and examples
