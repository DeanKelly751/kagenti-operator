#!/usr/bin/env bash
##
# Proactive restart demo: SVID expiry detection and automatic re-signing.
# Prerequisite: agentcard-spire-signing demo must be deployed.
#
# The operator args below must match your deployment. Adjust if your
# operator uses different flags.
#

set -eu

NAMESPACE="${NAMESPACE:-agents}"
AGENTCARD="${AGENTCARD:-weather-agent-card}"
DEPLOYMENT="${DEPLOYMENT:-weather-agent}"
OPERATOR_NS="${OPERATOR_NS:-agentcard-system}"
OPERATOR_DEPLOY="${OPERATOR_DEPLOY:-agentcard-operator}"
SPIRE_TRUST_DOMAIN="${SPIRE_TRUST_DOMAIN:-demo.example.com}"

OPERATOR_ARGS_BASE=(
  "--leader-elect=false"
  "--metrics-bind-address=0"
  "--health-probe-bind-address=:8081"
  "--require-a2a-signature=true"
  "--spire-trust-domain=${SPIRE_TRUST_DOMAIN}"
  "--spire-trust-bundle-configmap=spire-bundle"
  "--spire-trust-bundle-configmap-namespace=spire-system"
  "__GRACE__"
  "--webhook-cert-path=/tmp/k8s-webhook-server/serving-certs"
  "--enforce-network-policies=true"
)

patch_operator_grace() {
  local grace="$1"
  local args_json
  args_json=$(printf '%s\n' "${OPERATOR_ARGS_BASE[@]}" | sed "s/__GRACE__/--svid-expiry-grace-period=${grace}/" | python3 -c "import sys,json; print(json.dumps(sys.stdin.read().strip().split('\n')))")
  kubectl patch deployment "$OPERATOR_DEPLOY" -n "$OPERATOR_NS" --type=json \
    -p "[{\"op\": \"replace\", \"path\": \"/spec/template/spec/containers/0/args\", \"value\": ${args_json}}]"
}

# ── Part A: Baseline ─────────────────────────────────────────────────────────
echo "=== Part A: Baseline ==="
BASELINE_POD=$(kubectl get pods -n "$NAMESPACE" -l app.kubernetes.io/name="$DEPLOYMENT" \
  --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')
echo "  Pod:            $BASELINE_POD"

BASELINE_KEYID=$(kubectl get agentcard "$AGENTCARD" -n "$NAMESPACE" \
  -o jsonpath='{.status.signatureKeyId}')
echo "  Baseline KeyId: ${BASELINE_KEYID:-(none)}"

RESIGN=$(kubectl get deployment "$DEPLOYMENT" -n "$NAMESPACE" \
  -o jsonpath='{.spec.template.metadata.annotations.agentcard\.kagenti\.dev/resign-trigger}' 2>/dev/null || true)
echo "  resign-trigger: ${RESIGN:-(not set)}"
echo ""

# ── Part B: Trigger ──────────────────────────────────────────────────────────
echo "=== Part B: Triggering SVID expiry restart ==="
echo "  Patching operator with --svid-expiry-grace-period=999h..."
patch_operator_grace "999h"
echo "  Waiting for operator rollout..."
kubectl rollout status deployment/"$OPERATOR_DEPLOY" -n "$OPERATOR_NS" --timeout=120s
echo "  Waiting 30s for reconciliation..."
sleep 30
echo ""

# ── Part C: Verify ───────────────────────────────────────────────────────────
echo "=== Part C: Verify Restart ==="
echo "  Operator logs (restart-related):"
kubectl logs -n "$OPERATOR_NS" deployment/"$OPERATOR_DEPLOY" 2>&1 | \
  grep -i -E "proactive|resign|restart|expir" | tail -5 || echo "  (no matching log lines)"
echo ""

RESIGN_AFTER=$(kubectl get deployment "$DEPLOYMENT" -n "$NAMESPACE" \
  -o jsonpath='{.spec.template.metadata.annotations.agentcard\.kagenti\.dev/resign-trigger}' 2>/dev/null || true)
echo "  resign-trigger: ${RESIGN_AFTER:-(not set)}"

echo ""
echo "  ResignTriggered events:"
kubectl get events -n "$NAMESPACE" --field-selector reason=ResignTriggered --no-headers 2>/dev/null || echo "  (none)"

echo ""
echo "  Current pods:"
kubectl get pods -n "$NAMESPACE" -l app.kubernetes.io/name="$DEPLOYMENT" --no-headers
echo ""

# ── Part D: Restore ──────────────────────────────────────────────────────────
echo "=== Part D: Restore & Verify ==="
echo "  Restoring --svid-expiry-grace-period=30m..."
patch_operator_grace "30m"
kubectl rollout status deployment/"$OPERATOR_DEPLOY" -n "$OPERATOR_NS" --timeout=120s
echo "  Waiting 30s for stabilization..."
sleep 30

echo ""
echo "  AgentCard status after restart cycle:"
kubectl get agentcard "$AGENTCARD" -n "$NAMESPACE" -o jsonpath='{.status}' | python3 -c "
import sys, json
s = json.loads(sys.stdin.read())
print(f'  validSignature:  {s.get(\"validSignature\")}')
print(f'  signatureKeyId:  {s.get(\"signatureKeyId\")}')
print(f'  identityMatch:   {s.get(\"signatureIdentityMatch\")}')
print(f'  bound:           {s.get(\"bindingStatus\", {}).get(\"bound\")}')
"

NEW_KEYID=$(kubectl get agentcard "$AGENTCARD" -n "$NAMESPACE" \
  -o jsonpath='{.status.signatureKeyId}')
echo ""
if [ "$BASELINE_KEYID" != "$NEW_KEYID" ]; then
  echo "  Key rotated: ${BASELINE_KEYID} -> ${NEW_KEYID}"
else
  echo "  WARNING: Key ID unchanged (${BASELINE_KEYID}). The restart may not have completed yet."
fi
