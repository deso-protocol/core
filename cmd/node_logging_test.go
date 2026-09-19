package cmd

import (
	"flag"
	"testing"
)

func glogFlagValue(t *testing.T, name string) string {
	t.Helper()
	entry := flag.Lookup(name)
	if entry == nil {
		t.Fatalf("glog flag %q is not registered", name)
	}
	return entry.Value.String()
}

func TestConfigureGlogFlagsStderrOnly(t *testing.T) {
	originalLogToStderr := glogFlagValue(t, "logtostderr")
	originalAlsoLogToStderr := glogFlagValue(t, "alsologtostderr")
	t.Cleanup(func() {
		_ = flag.Set("logtostderr", originalLogToStderr)
		_ = flag.Set("alsologtostderr", originalAlsoLogToStderr)
	})

	configureGlogFlags(&Config{LogToStdErrOnly: true})

	if got := glogFlagValue(t, "logtostderr"); got != "true" {
		t.Fatalf("logtostderr = %s, want true", got)
	}
	if got := glogFlagValue(t, "alsologtostderr"); got != "false" {
		t.Fatalf("alsologtostderr = %s, want false", got)
	}
}

func TestConfigureGlogFlagsLegacyFileAndStderrMode(t *testing.T) {
	originalLogToStderr := glogFlagValue(t, "logtostderr")
	originalAlsoLogToStderr := glogFlagValue(t, "alsologtostderr")
	t.Cleanup(func() {
		_ = flag.Set("logtostderr", originalLogToStderr)
		_ = flag.Set("alsologtostderr", originalAlsoLogToStderr)
	})

	configureGlogFlags(&Config{NoLogToStdErr: false})

	if got := glogFlagValue(t, "logtostderr"); got != "false" {
		t.Fatalf("logtostderr = %s, want false", got)
	}
	if got := glogFlagValue(t, "alsologtostderr"); got != "true" {
		t.Fatalf("alsologtostderr = %s, want true", got)
	}
}
