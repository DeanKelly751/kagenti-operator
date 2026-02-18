# Getting Started with Kagenti Operator

> **Note**: This guide assumes you have already installed the Kagenti platform using the [Kagenti installer](https://github.com/kagenti/kagenti/blob/main/deployments/ansible/README.md).

## Prerequisites

The examples in this guide assume you are running Ollama locally with a specific model loaded. Before proceeding, ensure you have:

- **Ollama installed and running** on your local machine
- **Model loaded**: `llama3.2:3b-instruct-fp16`
- **Ollama accessible** at `http://host.docker.internal:11434/v1` from within the Kubernetes cluster

The agent deployments in this guide are configured with the following environment variables to connect to your local Ollama instance:
```yaml
- name: LLM_API_BASE
  value: http://host.docker.internal:11434/v1
- name: LLM_API_KEY
  value: dummy
- name: LLM_MODEL
  value: llama3.2:3b-instruct-fp16
```

---

## Intent

This guide provides step-by-step instructions for deploying and testing AI agents with the Kagenti platform. By following this guide, you will learn how to deploy agents and integrate MCP (Model Context Protocol) servers to extend agent capabilities.

## Scenario

In this guide, you will:

1. Deploy a weather agent that can answer weather-related queries
2. Deploy an MCP server that provides tools and resources to the agent
3. Test the end-to-end flow by sending a weather query ("What is the weather in New York?") to the agent, which will communicate with the MCP server and return a response

This scenario demonstrates the complete lifecycle of an AI agent deployment on the Kagenti platform, from initial deployment to integration with external tools via MCP servers.

---
## Overview

### Kagenti Operator
The Kagenti Operator discovers, indexes, and secures AI agents deployed in Kubernetes. Agents are deployed as standard Kubernetes **Deployments** or **StatefulSets** with the `kagenti.io/type: agent` label. The operator automatically creates **AgentCard** resources for discovered workloads to enable Kubernetes-native agent discovery.

> **Note:** The `Agent` Custom Resource is deprecated and will be removed in a future release. Use standard Kubernetes Deployments or StatefulSets with the `kagenti.io/type: agent` label instead.

### Stacklok ToolHive Operator

The Stacklok ToolHive Operator is deployed as part of the Kagenti platform installation and manages:

- **MCPServer**: Deploys MCP servers that provide tools and resources to agents

---

## Deploy an Agent

Deploy an agent as a standard Kubernetes Deployment with the required `kagenti.io/type: agent` label. The operator will automatically discover the workload and create an AgentCard for it.

### Quick Example Deployment

```yaml
kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: weather-agent
  namespace: team1
  labels:
    app.kubernetes.io/name: weather-agent
    kagenti.io/type: agent
    kagenti.io/protocol: a2a
    kagenti.io/framework: LangGraph
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
        imagePullPolicy: Always
        env:
        - name: PORT
          value: "8000"
        - name: UV_CACHE_DIR
          value: /app/.cache/uv
        - name: MCP_URL
          value: http://mcp-weather-tool-proxy.team1.svc.cluster.local:8000/mcp
        - name: LLM_API_BASE
          value: http://host.docker.internal:11434/v1
        - name: LLM_API_KEY
          value: dummy
        - name: LLM_MODEL
          value: llama3.2:3b-instruct-fp16
---
apiVersion: v1
kind: Service
metadata:
  name: weather-agent
  namespace: team1
spec:
  selector:
    app.kubernetes.io/name: weather-agent
  ports:
  - name: http
    port: 8000
    targetPort: 8000
EOF

```

**Check Status**:
```bash

# Check discovered agent cards
kubectl get agentcards -n team1

# Check deployment status
kubectl get deployment weather-agent -n team1

# View logs
kubectl logs -l app.kubernetes.io/name=weather-agent -n team1
```

---

## Deploy an MCP Server

> **Note**: The MCPServer Custom Resource is managed by the Stacklok ToolHive Operator, which is deployed as part of the Kagenti platform installation. This guide shows how to deploy an MCPServer to enable end-to-end testing.

MCP (Model Context Protocol) servers provide tools and resources that your agents can use. Deploy an MCPServer after your agent is running.

### Basic MCP Server Deployment
```yaml
kubectl apply -f - <<EOF
apiVersion: toolhive.stacklok.dev/v1alpha1
kind: MCPServer
metadata:
  name: weather-tool
  namespace: team1
  labels:
    kagenti.io/framework: Python
    kagenti.io/protocol: streamable_http
    kagenti.io/type: tool
    toolhive-basename: weather-tool
spec:
  image: "ghcr.io/kagenti/agent-examples/weather_tool:v0.0.1-alpha.3"
  transport: streamable-http
  port: 8000
  targetPort: 8000
  proxyPort: 8000
  podTemplateSpec:
    spec:
      serviceAccountName: weather-tool
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      volumes:
        - name: cache
          emptyDir: {}
        - name: tmp-dir
          emptyDir: {}
      containers:
        - name: mcp
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
            runAsUser: 1000
          env:
            - name: PORT
              value: "8000"
            - name: UV_CACHE_DIR
              value: /app/.cache/uv
          volumeMounts:
            - name: cache
              mountPath: /app/.cache
              readOnly: false
            - name: tmp-dir
              mountPath: /tmp
              readOnly: false
EOF
```
---
**Check Status**:
```bash

# List MCP servers
kubectl get mcpservers.toolhive.stacklok.dev -n team1

# Check detailed status
kubectl describe mcpservers.toolhive.stacklok.dev weather-tool -n team1

# View logs
kubectl logs -l toolhive-basename=weather-tool -n team1
```


---
## End-to-End Testing: Send a Prompt to Agent

Once your Agent and MCPServer are deployed and running, you can test the end-to-end flow by sending a prompt to the agent using JSON-RPC.

> **Note**: The examples below use a temporary curl pod running inside the cluster. This approach allows you to directly access the agent service using its internal Kubernetes service DNS name (e.g., `http://mcp-weather-tool-proxy.team1.svc.cluster.local:8000`) without the need to set up port-forwarding from your local machine.

The reason this DNS name works is that the ToolHive Operator automatically creates a Kubernetes Service for each MCPServer using a specific naming convention:

mcp-[server-name]-proxy

For example, if your MCPServer resource is named weather-tool, the operator will generate a service named:

mcp-weather-tool-proxy

Kubernetes then exposes this service internally via its built-in DNS system, producing a fully qualified service hostname in the form:

mcp-[server-name]-proxy.[namespace].svc.cluster.local
### Test Weather Query

This example sends a weather query for New York to the weather-agent, which will communicate with the MCPServer to retrieve the weather information.
```bash
kubectl run curl-pod -i --tty --rm \
  --image=curlimages/curl:8.1.2 -n team1 -- \
  curl -sS -X POST http://weather-agent.team1.svc.cluster.local:8000/ \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":"76CD6BA3-16AA-4CED-8E0E-19156B8C5886","method":"message/send","params":{"message":{"role":"user","parts":[{"kind":"text","text":"What is the weather in NY?"}],"messageId":"DF05857B-98B7-4414-BD63-19E16E684E39"}}}'
```

> **Tip**: If you don't see a command prompt after running the command, try pressing enter. The pod will automatically be deleted after the curl command completes.

**Expected Response**

The agent should return a JSON-RPC response similar to:
```json
{
  "id": "76CD6BA3-16AA-4CED-8E0E-19156B8C5886",
  "jsonrpc": "2.0",
  "result": {
    "artifacts": [
      {
        "artifactId": "5e6ab98e-95a8-47d4-bfaf-a35ce9bd9235",
        "parts": [
          {
            "kind": "text",
            "text": "The current weather in NY is mostly cloudy with a temperature of 46.9°F (8.3°C). There is a moderate breeze coming from the northwest at 9.7 mph (15.6 km/h). It's currently nighttime."
          }
        ]
      }
    ],
    "contextId": "4991dce0-a893-4a65-8599-0621b46984dd",
    "history": [
      {
        "contextId": "4991dce0-a893-4a65-8599-0621b46984dd",
        "kind": "message",
        "messageId": "DF05857B-98B7-4414-BD63-19E16E684E39",
        "parts": [
          {
            "kind": "text",
            "text": "What is the weather in NY?"
          }
        ],
        "role": "user",
        "taskId": "b08ce1b8-59b6-4e96-b375-b3a0a4889b65"
      }
    ],
    "id": "b08ce1b8-59b6-4e96-b375-b3a0a4889b65",
    "kind": "task",
    "status": {
      "state": "completed",
      "timestamp": "2025-12-12T15:57:31.382161+00:00"
    }
  }
}
```

The response shows:
- **artifacts**: Contains the weather information returned by the agent
- **history**: Shows the conversation history, including the agent's interaction with the MCP server tools
- **status**: Indicates the task completed successfully
---

**Monitor the Interaction**

You can watch the logs to see the agent communicating with the MCP server:
```bash
# Watch agent logs
kubectl logs -f -l app.kubernetes.io/name=weather-agent -n team1

# Watch MCP server logs (in another terminal)
kubectl logs -f -l toolhive-basename=weather-tool -n team1
```

---

## Checking Status

### Deployment Status
```bash
# Check deployment
kubectl get deployment weather-agent -n team1

# Detailed status
kubectl describe deployment weather-agent -n team1

# Check if pods are ready
kubectl get pods -n team1 -l app.kubernetes.io/name=weather-agent
```

### AgentCard Status
```bash
# List discovered agent cards
kubectl get agentcards -n team1

# Get detailed agent card info
kubectl describe agentcard -n team1

# Check signature verification status
kubectl get agentcard -n team1 -o jsonpath='{.items[0].status.validSignature}'
```

### MCPServer Status
```bash
# List MCP servers
kubectl get mcpservers.toolhive.stacklok.dev -n team1

# Detailed status
kubectl describe mcpservers.toolhive.stacklok.dev weather-tool -n team1

# Check if pods are running
kubectl get pods -n team1 -l toolhive-basename=weather-tool

# View logs
kubectl logs -l toolhive-basename=weather-tool -n team1 -f
```

---

## Troubleshooting

### Agent Not Starting
```bash
# Check deployment status
kubectl describe deployment weather-agent -n team1

# Check events
kubectl get events -n team1 --field-selector involvedObject.name=weather-agent

# Check pod status
kubectl get pods -n team1 -l app.kubernetes.io/name=weather-agent
```

### MCP Server Not Starting
```bash
# Check MCP server status
kubectl get mcpservers.toolhive.stacklok.dev weather-tool -n team1 -o yaml

# Check pod status
kubectl get pods -n team1 -l toolhive-basename=weather-tool

# Check events
kubectl get events -n team1 --field-selector involvedObject.name=weather-tool

# Verify service account exists
kubectl get serviceaccount weather-tool-sa -n team1

# Check for image pull issues
kubectl describe pod -n team1 -l toolhive-basename=weather-tool
```

### Agent Not Responding to Requests
```bash
# Verify agent service is accessible
kubectl get svc weather-agent -n team1

# Test connectivity from within the cluster using a temporary curl pod
kubectl run test-curl --image=curlimages/curl:8.1.2 --rm -i --restart=Never -n team1 -- \
  curl -v http://weather-agent.team1.svc.cluster.local:8000/health

# Check if agent can reach MCP server
# Note: The agent container may not have curl installed, so we'll use a debug pod in the same namespace
kubectl run curl-debug --image=curlimages/curl:8.1.2 --rm -i --tty -n team1 -- \
  curl -v http://mcp-weather-tool-proxy.team1.svc.cluster.local:8000/health

```

### Ollama Connection Issues
```bash
# Verify Ollama is running and accessible from your local machine
curl http://localhost:11434/v1/models

# Check agent logs for LLM-related errors
kubectl logs -l app.kubernetes.io/name=weather-agent -n team1 | grep -i "llm\|model\|ollama"

# Check for connection errors in agent logs
kubectl logs -l app.kubernetes.io/name=weather-agent -n team1 --tail=100

# Test if the agent pod can reach Ollama
kubectl run curl-test --image=curlimages/curl:8.1.2 --rm -i --tty -n team1 -- \
  curl -v http://host.docker.internal:11434/v1/models
```

---

## Next Steps

- [Dynamic Agent Discovery](docs/dynamic-agent-discovery.md) — How AgentCard enables agent discovery
- [Signature Verification](docs/a2a-signature-verification.md) — Set up JWS signature verification
- [Identity Binding](docs/identity-binding-quickstart.md) — Configure SPIFFE identity binding
- [Migration Guide](../docs/migration/migrate-agent-crd-to-workloads.md) — Migrating from Agent CRD to workloads
- [API Reference](docs/api-reference.md) — Full CRD specifications

---
