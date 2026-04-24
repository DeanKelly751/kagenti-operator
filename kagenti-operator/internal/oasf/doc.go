// Package oasf integrates AGNTCY OASF (Open Agentic Schema Framework) schema
// validation for cached AgentCard content via the oasf-sdk HTTP validator. The
// operator has no in-process "MCP gateway" component; MCP is a protocol on
// workloads (e.g. protocol.kagenti.io/mcp). This package validates the A2A
// agent card bytes after sync, which is the natural place for OASF in a
// level-triggered operator.
package oasf
