package agntcy

// Opt-in: only AgentCards with this label (value "true" or "enabled")
// participate in the AGNTCY PoC flow.
const LabelPoc = "kagenti.io/agntcy-poc"

// Status condition types written by the AgntcyPocReconciler (must not
// overlap with the core AgentCard controller: Synced, ValidSignature, Bound, OASFValid, ...).
const (
	CondDirPublished = "AgntcyPocDir"
	CondIdentityPoc  = "AgntcyPocIdentity"
	CondSlimPoc      = "AgntcyPocSlim"
)

const (
	ReasonPocNotRequested = "PocNotRequested"
	ReasonDirPublished    = "DirPublished"
	ReasonDirFailed       = "DirPushFailed"
	ReasonIdentityOK      = "IdentityReachable"
	ReasonIdentityFail    = "IdentityUnreachable"
	ReasonSlimPoc         = "SlimPocPlaceholder"
)
