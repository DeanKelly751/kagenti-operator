# Sigstore CI/CD Demo for Kagenti

This directory contains sample manifests for demonstrating Sigstore signature verification with kagenti-operator.

## Files

| File | Description |
|------|-------------|
| `unsigned-agent-card.json` | The AgentCard before signing |
| `signed-agent-card-example.json` | Example structure of a signed AgentCard |
| `weather-agent-deployment.yaml` | Kubernetes manifests (Deployment, Service, ConfigMaps) |
| `weather-agent-agentcard.yaml` | AgentCard CR that triggers verification |

## Quick Start

### 1. Sign the AgentCard (via GitHub Actions)

Use the workflow in the main documentation to sign `unsigned-agent-card.json` in your CI/CD pipeline. This produces a signed card with:
- Fulcio certificate in `header.x5c`
- Rekor log index in `header.rekor_log_index`

### 2. Update the ConfigMap

Replace the placeholder values in `weather-agent-deployment.yaml` ConfigMap with your actual signed card:

```bash
# After downloading signed-agent-card.json from GitHub Actions artifact:
kubectl create configmap weather-agent-card \
  --from-file=agent.json=signed-agent-card.json \
  --dry-run=client -o yaml > temp-configmap.yaml

# Apply the rest of the deployment
kubectl apply -f weather-agent-deployment.yaml
```

Or manually edit the ConfigMap in `weather-agent-deployment.yaml` with the signed card content.

### 3. Deploy the Agent

```bash
kubectl apply -f weather-agent-deployment.yaml
kubectl apply -f weather-agent-agentcard.yaml
```

### 4. Watch Verification

```bash
# Watch operator logs for Sigstore verification
kubectl logs -f deployment/kagenti-operator -n kagenti-system | grep -i sigstore

# Check AgentCard status
kubectl get agentcard weather-agent -o yaml
```

### 5. Query Rekor (Audit Trail)

```bash
# Get the Rekor log index from your signed card
REKOR_INDEX=12345678  # Replace with actual index

# Query the transparency log
rekor-cli get --log-index $REKOR_INDEX
```

## Expected Operator Logs

On successful verification:
```
INFO  Sigstore signature verified successfully  {"rekorIndex": 12345678, "oidcIdentity": "https://github.com/your-org/your-repo/.github/workflows/sign.yaml@refs/heads/main"}
```

## Troubleshooting

### "No signature verified via Sigstore"

- Check that the AgentCard has `signatures[].header.x5c` (not in protected header)
- Verify `rekor_log_index` is present
- Check certificate hasn't expired (Fulcio certs are short-lived, but Rekor proves validity)

### "Fulcio certificate chain validation failed"

- Ensure the certificate was issued by the public Sigstore instance
- For private Sigstore, configure `--sigstore-trusted-root`

### "Rekor log entry verification failed"

- Verify network connectivity to `rekor.sigstore.dev`
- Check the log index is correct
