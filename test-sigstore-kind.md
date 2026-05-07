# Testing Sigstore SignedAgentCard Verification on Kind

## Prerequisites

1. **Install dependencies:**
   ```bash
   # Install sigstore-a2a
   pip install sigstore-a2a
   
   # Ensure kind is installed
   kind version
   
   # Ensure kubectl is configured
   kubectl version
   ```

2. **Create/verify kind cluster:**
   ```bash
   kind create cluster --name kagenti
   kubectl cluster-info --context kind-kagenti
   ```

## Step 1: Build and Deploy the Operator

```bash
cd kagenti-operator

# Install CRDs
make install

# Build operator image
make docker-build IMG=kagenti-operator:local

# Load into kind
kind load docker-image kagenti-operator:local --name kagenti

# Update values for testing
cat > /tmp/test-values.yaml <<EOF
controllerManager:
  container:
    image:
      repository: kagenti-operator
      tag: local
      pullPolicy: Never

sigstore:
  cardVerification:
    enabled: true
    auditMode: true  # Start in audit mode
    certificateIdentity: "https://github.com/DeanKelly751/kagenti-operator/.github/workflows/sign-agent-card.yml@refs/heads/main"
    certificateOIDCIssuer: "https://token.actions.githubusercontent.com"
    staging: false  # Use production Sigstore
EOF

# Deploy with Helm
helm install kagenti-operator ./charts/kagenti-operator \
  -f /tmp/test-values.yaml \
  --namespace kagenti-system \
  --create-namespace

# Verify operator is running
kubectl get pods -n kagenti-system
kubectl logs -n kagenti-system -l control-plane=controller-manager --tail=50
```

## Step 2: Generate a Signed AgentCard

```bash
# Sign the example card using GitHub Actions OIDC (requires running in CI)
# OR for local testing, create a signed card manually:

cd examples

# Create a test signed card (this requires OIDC token from GitHub Actions)
# For local testing, we'll use the workflow output instead

# Option A: Download from CI artifacts after pushing
git push origin feature/sigstore-a2a-signed-card-verification
# Wait for workflow to complete, then download signed-agent-card.json artifact

# Option B: Use a pre-existing signed card for testing
# Create a minimal signed card structure for testing
cat > signed-test-card.json <<'EOF'
{
  "agentCard": {
    "name": "Test Agent",
    "version": "1.0.0",
    "url": "http://test-agent:8000",
    "capabilities": {
      "streaming": true
    }
  },
  "attestations": {
    "signatureBundle": null
  }
}
EOF
```

## Step 3: Deploy Agent with Signed Card

```bash
# Create ConfigMap with signed agent card
kubectl create configmap test-agent-card-signed \
  --from-file=signed-agent-card.json=signed-test-card.json \
  -n default

# Create a test agent deployment
cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-agent
  namespace: default
  labels:
    kagenti.io/type: agent
spec:
  replicas: 1
  selector:
    matchLabels:
      app: test-agent
  template:
    metadata:
      labels:
        app: test-agent
        kagenti.io/type: agent
    spec:
      containers:
      - name: agent
        image: python:3.11-slim
        command: ["python", "-m", "http.server", "8000"]
        ports:
        - containerPort: 8000
          name: http
---
apiVersion: v1
kind: Service
metadata:
  name: test-agent
  namespace: default
spec:
  selector:
    app: test-agent
  ports:
  - port: 80
    targetPort: 8000
    name: http
EOF

# Wait for pod to be ready
kubectl wait --for=condition=ready pod -l app=test-agent -n default --timeout=60s
```

## Step 4: Create AgentCard CR

```bash
cat <<EOF | kubectl apply -f -
apiVersion: agent.kagenti.dev/v1alpha1
kind: AgentCard
metadata:
  name: test-agent-card
  namespace: default
spec:
  syncPeriod: "30s"
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: test-agent
  # Optional: override Sigstore verification settings
  sigstoreVerification:
    certificateIdentity: "https://github.com/DeanKelly751/kagenti-operator/.github/workflows/sign-agent-card.yml@refs/heads/main"
    certificateOIDCIssuer: "https://token.actions.githubusercontent.com"
EOF
```

## Step 5: Verify Sigstore Verification

```bash
# Check AgentCard status
kubectl get agentcard test-agent-card -n default -o yaml

# Look for Sigstore-specific status fields:
# - status.sigstoreBundleVerified
# - status.sigstoreIdentity
# - status.rekorLogIndex
# - status.slsaRepository
# - status.slsaCommitSHA

# Check controller logs
kubectl logs -n kagenti-system -l control-plane=controller-manager --tail=100 | grep -i sigstore

# Expected log patterns:
# - "Sigstore SignedAgentCard verification enabled"
# - "Sigstore bundle verification succeeded" (if card is signed)
# - "no attestations.signatureBundle" (if testing with null bundle)

# Verify conditions
kubectl get agentcard test-agent-card -n default -o jsonpath='{.status.conditions}' | jq
```

## Step 6: Test with Actually Signed Card

```bash
# Push changes to trigger GitHub Actions workflow
git add .
git commit -m "Test sigstore verification"
git push origin feature/sigstore-a2a-signed-card-verification

# Wait for workflow to complete
gh run watch

# Download signed artifact
gh run download --name signed-agent-card

# Update ConfigMap with real signed card
kubectl create configmap test-agent-card-signed \
  --from-file=signed-agent-card.json \
  -n default \
  --dry-run=client -o yaml | kubectl apply -f -

# Trigger reconciliation
kubectl annotate agentcard test-agent-card -n default \
  test-trigger="$(date +%s)" --overwrite

# Watch for verification
kubectl get agentcard test-agent-card -n default -w
```

## Step 7: Test Enforcement Mode

```bash
# Update operator to enable enforcement (non-audit) mode
helm upgrade kagenti-operator ./charts/kagenti-operator \
  --namespace kagenti-system \
  --set sigstore.cardVerification.auditMode=false \
  --reuse-values

# Restart operator pod
kubectl rollout restart deployment kagenti-controller-manager -n kagenti-system

# Verify that unsigned cards are rejected
# (status.conditions should show SigstoreVerificationFailed)
```

## Troubleshooting

### Operator not starting
```bash
# Check events
kubectl get events -n kagenti-system --sort-by='.lastTimestamp'

# Check init containers logs if any
kubectl logs -n kagenti-system <pod-name> -c <init-container-name>
```

### Sigstore verification failing
```bash
# Verify trust root is accessible
kubectl logs -n kagenti-system -l control-plane=controller-manager | grep "trusted root"

# Check certificate identity mismatch
kubectl logs -n kagenti-system -l control-plane=controller-manager | grep "certificate identity"

# Verify Sigstore bundle format
kubectl get configmap test-agent-card-signed -n default -o jsonpath='{.data.signed-agent-card\.json}' | jq '.attestations.signatureBundle'
```

### ConfigMap fetcher issues
```bash
# Check that fetcher is looking for the right ConfigMap
kubectl logs -n kagenti-system -l control-plane=controller-manager | grep "ConfigMap"

# Verify ConfigMap exists and has correct key
kubectl get configmap -n default | grep agent-card
kubectl describe configmap test-agent-card-signed -n default
```

## Metrics to Check

```bash
# If metrics are enabled, check Sigstore-specific metrics:
kubectl port-forward -n kagenti-system svc/kagenti-controller-manager-metrics 8443:8443

# In another terminal:
curl -k https://localhost:8443/metrics | grep sigstore
# Look for:
# - kagenti_sigstore_verification_total
# - kagenti_sigstore_verification_duration_seconds
# - kagenti_sigstore_trusted_root_age_seconds
```
