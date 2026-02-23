# API Reference

This document provides a comprehensive reference for the Kagenti Operator Custom Resource Definitions (CRDs).

## Custom Resources

- [AgentCard](#agentcard) — Fetches and stores agent metadata for dynamic discovery
- [Agent](#agent) — **(Deprecated)** Deploys and manages AI agent workloads

---

## Agent

> **Deprecated:** The `Agent` Custom Resource is deprecated and will be removed in a future release. Use standard Kubernetes Deployments or StatefulSets with the `kagenti.io/type: agent` label instead. See the [Migration Guide](../../docs/migration/migrate-agent-crd-to-workloads.md) for details.

The `Agent` Custom Resource manages the deployment and lifecycle of AI agents in Kubernetes.

### API Group and Version

- **API Group:** `agent.kagenti.dev`
- **API Version:** `v1alpha1`
- **Kind:** `Agent`

### Spec Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `description` | string | No | Human-readable description of the agent |
| `podTemplateSpec` | [PodTemplateSpec](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#podtemplatespec-v1-core) | Yes | Complete pod specification with containers, volumes, etc. |
| `replicas` | integer | No | Desired number of agent replicas (default: 1) |
| `labels` | map[string]string | No | Labels to add to the agent resources |
| `annotations` | map[string]string | No | Annotations to add to the agent resources |
| `image` | string | Yes | Container image to use for the agent |
| `servicePorts` | [][ServicePort](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#serviceport-v1-core) | No | Service ports to expose (default: http on port 8080) |

### Status Fields

| Field | Type | Description |
|-------|------|-------------|
| `conditions` | [][Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#condition-v1-meta) | Overall status conditions |
| `deploymentStatus` | [DeploymentStatus](#deploymentstatus) | Deployment status information |

#### DeploymentStatus

| Field | Type | Description |
|-------|------|-------------|
| `phase` | string | Current phase: `Pending`, `Deploying`, `Ready`, or `Failed` |
| `deploymentMessage` | string | Human-readable deployment message |
| `completionTime` | timestamp | When the deployment completed |

### Examples

#### Deploy from Existing Image

```yaml
apiVersion: agent.kagenti.dev/v1alpha1
kind: Agent
metadata:
  name: weather-agent
  namespace: default
  labels:
    kagenti.io/framework: LangGraph
    kagenti.io/protocol: a2a
    kagenti.io/type: agent
spec:
  description: "Weather data processing agent"
  replicas: 1
  image: "ghcr.io/kagenti/agent-examples/weather_service:v0.0.1-alpha.3"

  servicePorts:
    - name: http
      port: 8000
      targetPort: 8000
      protocol: TCP

  podTemplateSpec:
    spec:
      containers:
      - name: agent
        ports:
        - containerPort: 8000
        env:
        - name: PORT
          value: "8000"
        - name: LLM_API_BASE
          value: "http://ollama.default.svc.cluster.local:11434/v1"
        - name: LLM_MODEL
          value: "llama3.2:3b-instruct-fp16"
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
```

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
| `targetRef` | [TargetRef](#targetref) | Yes | Identifies the workload backing this agent (duck typing) |
| `selector` | [AgentSelector](#agentselector) | No | **Deprecated.** Use `targetRef` instead. If both are set, `targetRef` takes precedence. |
| `identityBinding` | [IdentityBinding](#identitybinding) | No | SPIFFE identity binding configuration |

#### TargetRef

Identifies the workload backing this agent via duck typing. The referenced workload must have the `kagenti.io/type=agent` label.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `apiVersion` | string | Yes | API version of the target resource (e.g., `apps/v1`) |
| `kind` | string | Yes | Kind of the target resource (e.g., `Deployment`, `StatefulSet`) |
| `name` | string | Yes | Name of the target resource |

#### AgentSelector (Deprecated)

**Deprecated:** Use `targetRef` instead for explicit workload references.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `matchLabels` | map[string]string | Yes | Label selector to identify the backing workload |

#### IdentityBinding

Configures workload identity binding for an AgentCard. The SPIFFE ID is extracted from the leaf certificate's SAN URI in the `x5c` chain during signature verification.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `trustDomain` | string | No | Overrides the operator-level `--spire-trust-domain` for this AgentCard. If empty, the operator flag value is used. |
| `strict` | boolean | No | Enables enforcement mode: binding failures trigger network isolation. When false (default), results are recorded in status only (audit mode). |

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
| `protected` | string | Base64url-encoded JWS protected header (contains `alg`, `kid`, `typ`, `x5c`) |
| `signature` | string | Base64url-encoded JWS signature value |
| `header` | object | Optional unprotected JWS header parameters (e.g., `timestamp`) |

### Examples

#### Deploy Agent as a Standard Deployment (Recommended)

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
        kagenti.io/type: agent
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
apiVersion: v1
kind: Service
metadata:
  name: weather-agent
  namespace: default
spec:
  selector:
    app.kubernetes.io/name: weather-agent
  ports:
  - name: http
    port: 8000
    targetPort: 8000
```

An AgentCard is automatically created by the AgentCard Sync Controller.

#### Manually Create an AgentCard with targetRef

```yaml
apiVersion: agent.kagenti.dev/v1alpha1
kind: AgentCard
metadata:
  name: weather-agent-card
  namespace: default
spec:
  syncPeriod: "30s"
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: weather-agent
```

#### AgentCard with Identity Binding

```yaml
apiVersion: agent.kagenti.dev/v1alpha1
kind: AgentCard
metadata:
  name: weather-agent-card
  namespace: default
spec:
  syncPeriod: "30s"
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: weather-agent
  identityBinding:
    strict: true
```

#### View Discovered Agents

```bash
# List all agent cards
kubectl get agentcards

# Example output:
# NAME                            PROTOCOL   KIND         TARGET          AGENT            VERIFIED   BOUND   SYNCED   LASTSYNC   AGE
# weather-agent-deployment-card   a2a        Deployment   weather-agent   Weather Agent    true       true    True     30s        10m

# Get detailed information
kubectl describe agentcard weather-agent-deployment-card
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

## Status and Monitoring

### Check AgentCard Status

```bash
# List all agent cards
kubectl get agentcards

# Get detailed agent card status
kubectl describe agentcard my-agent-card
```

### Common Status Conditions

#### Agent Conditions (Deprecated)

| Type | Status | Reason | Description |
|------|--------|--------|-------------|
| `Ready` | `True` | `DeploymentReady` | Agent is deployed and running |
| `Ready` | `False` | `DeploymentNotReady` | Waiting for replicas to be ready |
| `DeploymentAvailable` | `True` | `DeploymentExists` | Deployment resource exists |
| `PodsScheduled` | `True` | `AllPodsScheduled` | All pods are scheduled |
| `PodsScheduled` | `False` | `PodsUnscheduled` | Some pods are unavailable |

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
- [Migration Guide](../../docs/migration/migrate-agent-crd-to-workloads.md) — Migrating from Agent CRD to workloads
