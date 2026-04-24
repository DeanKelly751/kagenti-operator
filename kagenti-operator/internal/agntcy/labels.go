package agntcy

// PocResourceOptIn is true when the object label kagenti.io/agntcy-poc is set to
// an enabled value (empty, "true", "1", "enabled").
func PocResourceOptIn(labels map[string]string) bool {
	if labels == nil {
		return false
	}
	v, ok := labels[LabelPoc]
	if !ok {
		return false
	}
	if v == "" {
		return true
	}
	return v == "true" || v == "1" || v == "enabled"
}
