package engine

// runtimeFailpoint is a no-op in production binaries. The privileged lab
// replaces it from an integration-only build-tagged file so lifecycle failure
// paths can be exercised without shipping an environment-controlled fault
// mechanism.
var runtimeFailpoint = func(string) error { return nil }
