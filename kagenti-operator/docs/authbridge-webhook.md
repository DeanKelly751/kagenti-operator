# AuthBridge Webhook Design

The AuthBridge webhook is a Kubernetes mutating admission webhook that injects sidecar containers into agent and tool Pods. It runs as part of the kagenti-operator binary and intercepts Pod CREATE requests to add networking, identity, and registration sidecars.

## Sidecar Containers

The webhook can inject up to four containers:

| Container | Type | Purpose |
|-----------|------|---------|
| `envoy-proxy` | sidecar | Transparent proxy for outbound/inbound traffic with ext-proc filter for token exchange |
| `proxy-init` | init | iptables rules to redirect traffic through envoy-proxy |
| `spiffe-helper` | sidecar | Obtains and rotates SPIFFE SVIDs via the SPIRE workload API |
| `kagenti-client-registration` | sidecar | Registers the workload as an OAuth2 client in Keycloak |

`proxy-init` always follows `envoy-proxy` — if envoy is skipped, proxy-init is also skipped.

## Injection Trigger

Injection requires **all** of the following:

1. The Pod has label `kagenti.io/type=agent` (or `tool` with the `injectTools` gate enabled)
2. A matching **AgentRuntime CR** exists in the same namespace with `spec.targetRef.name` matching the workload name
3. The global feature gate is enabled
4. The Pod has not opted out via `kagenti.io/inject=disabled`
5. At least one sidecar passes the per-sidecar precedence chain

The AgentRuntime CR requirement means Pods deployed before the CR is created will **not** receive sidecars. The AgentRuntime CR acts as the explicit trigger for injection.

## Injection Precedence Chain

The webhook evaluates injection in two phases: **workload-level pre-filtering** and **per-sidecar precedence evaluation**.

### Phase 1: Workload-Level Pre-Filtering

These checks run first in `PodMutator.InjectAuthBridge()` (`internal/webhook/injector/pod_mutator.go`). Any "no" short-circuits the entire injection — no sidecars are added.

| Order | Check | Source | Skip condition |
|-------|-------|--------|----------------|
| 1 | Workload type | Pod label `kagenti.io/type` | Not `agent` or `tool` |
| 2 | Global kill switch | `featureGates.globalEnabled` | `false` |
| 3 | Tool gate | `featureGates.injectTools` | `kagenti.io/type=tool` and gate is `false` |
| 4 | Workload opt-out | Pod label `kagenti.io/inject` | Value is `disabled` |
| 5 | Per-sidecar precedence | See Phase 2 | All sidecars evaluate to skip |
| 6 | AgentRuntime CR | `ReadAgentRuntimeOverrides()` | No matching CR found in namespace |

### Phase 2: Per-Sidecar Precedence Evaluation

After pre-filtering passes, `PrecedenceEvaluator.Evaluate()` (`internal/webhook/injector/precedence.go`) runs a two-layer chain for each sidecar independently:

| Layer | Source | Effect |
|-------|--------|--------|
| 1 (highest) | Feature gate (`featureGates.<sidecar>`) | `false` disables the sidecar cluster-wide |
| 2 | Workload label (`kagenti.io/<sidecar>-inject`) | `false` disables the sidecar for this workload |

The per-sidecar labels are:

| Label | Controls |
|-------|----------|
| `kagenti.io/envoy-proxy-inject` | envoy-proxy + proxy-init |
| `kagenti.io/spiffe-helper-inject` | spiffe-helper |
| `kagenti.io/client-registration-inject` | client-registration |

If all sidecars evaluate to "skip", no mutation occurs (equivalent to a pre-filter rejection).

### Precedence Flow Diagram

```
Pod CREATE request
  │
  ├─ kagenti.io/type not agent|tool? ──→ ALLOW (no mutation)
  ├─ globalEnabled=false? ─────────────→ ALLOW (no mutation)
  ├─ type=tool and injectTools=false? ─→ ALLOW (no mutation)
  ├─ kagenti.io/inject=disabled? ──────→ ALLOW (no mutation)
  │
  ├─ Per-sidecar precedence evaluation
  │   ├─ envoy-proxy:  gate → label → inject?
  │   ├─ proxy-init:   follows envoy-proxy
  │   ├─ spiffe-helper: gate → label → inject?
  │   └─ client-registration: gate → label → inject?
  │
  ├─ No sidecars to inject? ───────────→ ALLOW (no mutation)
  ├─ No matching AgentRuntime CR? ─────→ ALLOW (no mutation)
  │
  └─ Build containers + volumes → PATCH
```

## Configuration Merge (3-Layer Config Resolution)

When the `perWorkloadConfigResolution` feature gate is enabled, the webhook resolves configuration values at admission time instead of deferring to kubelet's ConfigMapKeyRef/SecretKeyRef resolution. This merge happens in `ResolveConfig()` (`internal/webhook/injector/resolved_config.go`).

### Merge Layers

```
┌──────────────────────────────────────┐
│ Layer 3: AgentRuntime CR overrides   │  ← highest precedence
│   (spec.identity, spec.trace)        │
├──────────────────────────────────────┤
│ Layer 2: Namespace ConfigMaps        │
│   (authbridge-config, envoy-config,  │
│    spiffe-helper-config, etc.)       │
├──────────────────────────────────────┤
│ Layer 1: PlatformConfig              │  ← lowest precedence
│   (compiled defaults + config.yaml)  │
└──────────────────────────────────────┘
```

### Layer 1: PlatformConfig (compiled defaults + config file)

**Source**: `internal/webhook/config/defaults.go` (compiled defaults) merged with `/etc/kagenti/config.yaml` (file overrides).

**Loaded by**: `ConfigLoader` (`internal/webhook/config/loader.go`) with fsnotify hot-reload.

**Contains**: Container images, proxy ports/UID, resource requests/limits, token exchange defaults, SPIFFE trust domain/socket path, observability settings, per-sidecar enable/disable defaults.

**Merge behavior**: YAML file fields overlay onto compiled defaults. Missing fields retain compiled default values. The merged result is validated by `PlatformConfig.Validate()`.

### Layer 2: Namespace ConfigMaps

**Source**: Well-known ConfigMaps in the workload's namespace, read at admission time by `ReadNamespaceConfig()` (`internal/webhook/injector/namespace_config.go`).

| ConfigMap | Keys | Purpose |
|-----------|------|---------|
| `authbridge-config` | `KEYCLOAK_URL`, `KEYCLOAK_REALM`, `SPIRE_ENABLED`, `PLATFORM_CLIENT_IDS`, `TOKEN_URL`, `ISSUER`, `EXPECTED_AUDIENCE`, `TARGET_AUDIENCE`, `TARGET_SCOPES`, `DEFAULT_OUTBOUND_POLICY` | Identity and token exchange settings |
| `spiffe-helper-config` | `helper.conf` | SPIFFE helper configuration |
| `envoy-config` | `envoy.yaml` | Custom Envoy configuration (overrides template rendering) |
| `authproxy-routes` | `routes.yaml` | Auth proxy route definitions |

**Merge behavior**: Each ConfigMap is read independently. Missing ConfigMaps result in empty strings for those fields. Non-empty namespace values override PlatformConfig defaults.

### Layer 3: AgentRuntime CR Overrides

**Source**: The `AgentRuntime` CR matching the workload via `spec.targetRef.name`, read by `ReadAgentRuntimeOverrides()` (`internal/webhook/injector/agentruntime_config.go`).

**Overridable fields**:

| AgentRuntime field | ResolvedConfig field | Description |
|-------------------|---------------------|-------------|
| `spec.identity.spiffe.trustDomain` | `SpiffeTrustDomain` | SPIFFE trust domain |
| `spec.identity.clientRegistration.realm` | `KeycloakRealm` | Keycloak realm (future — not yet in CRD) |
| `spec.trace.endpoint` | `TraceEndpoint` | OpenTelemetry collector endpoint |
| `spec.trace.protocol` | `TraceProtocol` | `grpc` or `http` |
| `spec.trace.sampling.rate` | `TraceSamplingRate` | 0.0–1.0 sampling rate |

**Non-overridable fields** (always from PlatformConfig or namespace CMs):
- Container images, resource limits, proxy ports
- Token exchange settings (tokenURL, audience, scopes)
- Sidecar configuration files (envoy.yaml, helper.conf, routes.yaml)

**Merge behavior**: Only non-nil AgentRuntime override fields replace the value from lower layers. Nil fields (absent from the CR spec) leave the lower-layer value intact.

### Merge Code Path

```
PodMutator.InjectAuthBridge()                       ← pod_mutator.go
  │
  ├─ ReadAgentRuntimeOverrides(ctx, client, ns, name)  ← agentruntime_config.go
  │     Lists AgentRuntime CRs, matches spec.targetRef.name
  │     Returns *AgentRuntimeOverrides (nil if no match)
  │
  ├─ [if perWorkloadConfigResolution=true]
  │   ├─ ReadNamespaceConfig(ctx, client, ns)           ← namespace_config.go
  │   │     Reads 4 well-known ConfigMaps from namespace
  │   │     Returns *NamespaceConfig
  │   │
  │   ├─ ResolveConfig(platform, nsConfig, arOverrides) ← resolved_config.go
  │   │     Starts with namespace CM values
  │   │     Falls back to PlatformConfig for spiffeTrustDomain
  │   │     Applies AgentRuntime overrides (highest precedence)
  │   │     Returns *ResolvedConfig
  │   │
  │   └─ NewResolvedContainerBuilder(resolved)          ← container_builder.go
  │         Builds containers with literal env var values
  │
  └─ [if perWorkloadConfigResolution=false (default)]
      └─ NewContainerBuilder(platformConfig)            ← container_builder.go
            Builds containers with ValueFrom ConfigMapKeyRef/SecretKeyRef
            Kubelet resolves values at container start time
```

## Feature Gates

Feature gates are loaded from `/etc/kagenti/feature-gates/feature-gates.yaml` with fsnotify hot-reload. Defined in `internal/webhook/config/feature_gates.go`.

| Gate | Default | Effect |
|------|---------|--------|
| `globalEnabled` | `true` | Master kill switch — `false` disables all injection cluster-wide |
| `envoyProxy` | `true` | Enable/disable envoy-proxy + proxy-init injection |
| `spiffeHelper` | `true` | Enable/disable spiffe-helper injection |
| `clientRegistration` | `true` | Enable/disable client-registration injection |
| `injectTools` | `false` | Allow injection for `kagenti.io/type=tool` workloads |
| `perWorkloadConfigResolution` | `false` | Switch from ValueFrom refs to literal env var injection |

## Workload Name Derivation

At Pod CREATE time, the Pod name is often empty (generated by the API server). The webhook derives a workload name from `GenerateName` (set by the owning controller):

```
GenerateName="myapp-7d4f8b9c5-" → "myapp-7d4f8b9c5" (ReplicaSet name)
GenerateName="myapp-"           → "myapp" (StatefulSet name)
Name="my-bare-pod"              → "my-bare-pod" (bare Pod)
```

This name is used for:
- AgentRuntime CR `spec.targetRef.name` matching
- ServiceAccount creation (SPIFFE identity)
- Client registration naming

Implementation: `deriveWorkloadName()` in `internal/webhook/v1alpha1/authbridge_webhook.go`.

## Idempotency

The webhook is idempotent. If any injected container (`envoy-proxy`, `spiffe-helper`, `kagenti-client-registration`) or init container (`proxy-init`) is already present in the Pod spec, the webhook skips mutation entirely. This is checked by `isAlreadyInjected()` in `authbridge_webhook.go` before `InjectAuthBridge()` is called.

Additionally, each container and volume append in `InjectAuthBridge()` is guarded by `containerExists()`/`volumeExists()` checks.

The MutatingWebhookConfiguration uses `reinvocationPolicy: IfNeeded` so the webhook is re-invoked if another mutating webhook modifies the Pod after the initial mutation.

## Port Exclusion Annotations

Per-workload iptables overrides for proxy-init:

| Annotation | Effect |
|------------|--------|
| `kagenti.io/outbound-ports-exclude` | Comma-separated ports appended to the mandatory 8080 exclusion |
| `kagenti.io/inbound-ports-exclude` | Comma-separated ports excluded from inbound interception |

## Key Source Files

| File | Purpose |
|------|---------|
| `internal/webhook/v1alpha1/authbridge_webhook.go` | Admission handler, Pod decoding, workload name derivation, idempotency check |
| `internal/webhook/injector/pod_mutator.go` | Central orchestrator — pre-filtering, precedence evaluation, AgentRuntime gate, container/volume injection |
| `internal/webhook/injector/precedence.go` | Per-sidecar 2-layer precedence chain (feature gate > workload label) |
| `internal/webhook/injector/resolved_config.go` | 3-layer config merge: PlatformConfig < namespace CMs < AgentRuntime CR |
| `internal/webhook/injector/agentruntime_config.go` | Typed AgentRuntime CR lookup and override extraction |
| `internal/webhook/injector/namespace_config.go` | Reads well-known ConfigMaps from workload namespace |
| `internal/webhook/injector/container_builder.go` | Dual-mode container construction (ValueFrom vs literal env vars) |
| `internal/webhook/injector/volume_builder.go` | Volume definitions for both config resolution modes |
| `internal/webhook/config/types.go` | PlatformConfig struct definitions |
| `internal/webhook/config/defaults.go` | Compiled default values |
| `internal/webhook/config/feature_gates.go` | FeatureGates struct and defaults |
| `internal/webhook/config/loader.go` | ConfigLoader with fsnotify hot-reload |
| `internal/webhook/config/feature_gate_loader.go` | FeatureGateLoader with fsnotify hot-reload |
