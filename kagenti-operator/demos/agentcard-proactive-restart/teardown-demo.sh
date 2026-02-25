#!/usr/bin/env bash
#
# Teardown for the proactive restart demo.
# Restores the operator to the normal grace period.
#

set -eu

OPERATOR_NS="${OPERATOR_NS:-agentcard-system}"
OPERATOR_DEPLOY="${OPERATOR_DEPLOY:-agentcard-operator}"
SPIRE_TRUST_DOMAIN="${SPIRE_TRUST_DOMAIN:-demo.example.com}"

echo "=== AgentCard Proactive Restart Demo Teardown ==="
echo ""

echo "Restoring operator to --svid-expiry-grace-period=30m..."
kubectl patch deployment "$OPERATOR_DEPLOY" -n "$OPERATOR_NS" --type=json -p "[
  {\"op\": \"replace\", \"path\": \"/spec/template/spec/containers/0/args\",
   \"value\": [
     \"--leader-elect=false\",
     \"--metrics-bind-address=0\",
     \"--health-probe-bind-address=:8081\",
     \"--require-a2a-signature=true\",
     \"--spire-trust-domain=${SPIRE_TRUST_DOMAIN}\",
     \"--spire-trust-bundle-configmap=spire-bundle\",
     \"--spire-trust-bundle-configmap-namespace=spire-system\",
     \"--svid-expiry-grace-period=30m\",
     \"--webhook-cert-path=/tmp/k8s-webhook-server/serving-certs\",
     \"--enforce-network-policies=true\"
   ]}
]"
kubectl rollout status deployment/"$OPERATOR_DEPLOY" -n "$OPERATOR_NS" --timeout=120s

echo ""
echo "=== Teardown Complete ==="
