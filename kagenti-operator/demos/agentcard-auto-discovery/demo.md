# AgentCard Auto-Discovery Demo

This demo shows how the operator's sync controller automatically discovers labeled workloads and creates AgentCard CRs for them.

## Prerequisites

- The kagenti operator is running with sync enabled.
- The `agents` namespace exists (deployed by `agentcard-spire-signing`).

## What This Demonstrates

| Scenario | What happens |
|----------|-------------|
| Deploy labeled workload | Sync controller auto-creates an AgentCard CR |
| Inspect auto-created card | Shows the card was created with correct targetRef |
| Cleanup | Removes echo-agent and auto-created cards |

## Run the Demo

```bash
./demos/agentcard-auto-discovery/run-demo-commands.sh
```

Expected output:

```
=== 1. Before: AgentCards in namespace ===
  (only weather-agent-card if spire-signing demo is deployed)

=== 2. Deploying echo-agent (labeled, no AgentCard CR) ===
  deployment.apps/echo-agent created
  service/echo-agent created

=== 3. Auto-Created AgentCards ===
  NAME                              AGE
  weather-agent-card                ...
  echo-agent-deployment-card        ...

=== 4. Auto-Created Card Details ===
  Name:      echo-agent-deployment-card
  TargetRef: Deployment/echo-agent

=== 5. Cleanup ===
  echo-agent resources deleted
```

## How It Works

1. The sync controller watches for Deployments labeled `kagenti.io/type: agent`
2. When a new labeled Deployment appears without a matching AgentCard, the controller creates one
3. The auto-created card uses the naming convention `<deployment-name>-deployment-card`
4. If you later create a manual AgentCard targeting the same Deployment, it takes precedence

## Cleanup

```bash
./demos/agentcard-auto-discovery/teardown-demo.sh
```
