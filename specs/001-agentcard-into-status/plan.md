# Implementation Plan: Consolidate AgentCard Data Into AgentRuntime Status

**Branch**: `001-agentcard-into-status` | **Date**: 2026-05-21 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `specs/001-agentcard-into-status/spec.md`

## Summary

Move A2A agent card discovery into the AgentRuntime controller's reconcile loop so operators can read card data, fetch metadata, and mTLS verification results from a single resource (`status.card` on AgentRuntime). Reuses the existing `agentcard.Fetcher` and `agentcard.AuthenticatedFetcher` interfaces and the `AgentCardData` struct. The feature is gated behind a `--enable-card-discovery` flag (default: disabled). AgentCard CRD remains functional with a deprecation warning.

## Technical Context

**Language/Version**: Go 1.25, controller-runtime v0.23.3
**Primary Dependencies**: controller-runtime, go-spiffe/v2, k8s.io/apimachinery
**Storage**: Kubernetes CRD status subresource (no external storage)
**Testing**: Ginkgo/Gomega (unit + integration), envtest for controller tests, e2e in `test/e2e/`
**Target Platform**: Kubernetes 1.31+
**Project Type**: Kubernetes operator (kubebuilder-based)
**Performance Goals**: Card fetch adds < 1s to reconcile; no periodic re-fetch (event-driven only)
**Constraints**: No new CRDs; feature-gated; backward compatible with existing AgentCard workflows
**Scale/Scope**: Hundreds of AgentRuntimes per cluster (card fetch is 1:1 with AgentRuntime)

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

Constitution is a template (not customized for this project). No gates to evaluate.
Project follows standard kubebuilder patterns: CRD types in `api/v1alpha1/`, controllers in `internal/controller/`, shared logic in `internal/` packages.

## Project Structure

### Documentation (this feature)

```text
specs/001-agentcard-into-status/
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── contracts/           # Phase 1 output (CRD status contract)
└── tasks.md             # Phase 2 output (/speckit.tasks)
```

### Source Code (repository root)

```text
kagenti-operator/
├── api/v1alpha1/
│   ├── agentruntime_types.go       # MODIFY: add CardStatus to AgentRuntimeStatus
│   ├── agentcard_types.go          # READ-ONLY: reuse AgentCardData struct
│   └── zz_generated.deepcopy.go    # REGENERATE: after type changes
├── internal/
│   ├── agentcard/
│   │   └── fetcher.go              # READ-ONLY: reuse Fetcher, AuthenticatedFetcher, SpiffeFetcher
│   ├── controller/
│   │   ├── agentruntime_controller.go      # MODIFY: add card fetch phase to reconcile
│   │   ├── agentruntime_controller_test.go # MODIFY: add card fetch tests
│   │   ├── agentcard_controller.go         # MODIFY: add deprecation warning log
│   │   └── agentcard_controller_test.go    # MODIFY: test deprecation warning
│   └── signature/                  # READ-ONLY: reuse VerificationResult, Provider
├── cmd/
│   └── main.go                     # MODIFY: add --enable-card-discovery flag, wire fetchers
├── config/
│   ├── crd/bases/                  # REGENERATE: CRD manifests after type changes
│   └── rbac/                       # MODIFY: add Service list/watch RBAC for agentruntime controller
└── test/
    ├── e2e/                        # MODIFY: add card discovery e2e scenarios
    └── integration/                # MODIFY: add card fetch integration tests
```

**Structure Decision**: Existing kubebuilder project structure. All changes extend existing files. No new packages or directories needed.

## Complexity Tracking

No constitution violations. No complexity justification needed.
