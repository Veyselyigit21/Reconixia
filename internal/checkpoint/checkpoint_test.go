package checkpoint

import (
	"path/filepath"
	"testing"
)

func TestCheckpointLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "checkpoint.json")

	st, err := Load(path, "example.com")
	if err != nil {
		t.Fatalf("Load missing checkpoint: %v", err)
	}
	if st.Target != "example.com" {
		t.Fatalf("Target = %q, want example.com", st.Target)
	}
	if IsDone(st, "subdomains") {
		t.Fatal("new checkpoint unexpectedly has completed step")
	}

	st, err = MarkDone(path, st, "subdomains")
	if err != nil {
		t.Fatalf("MarkDone: %v", err)
	}
	if !IsDone(st, "subdomains") {
		t.Fatal("subdomains step was not marked done")
	}

	loaded, err := Load(path, "example.com")
	if err != nil {
		t.Fatalf("Load saved checkpoint: %v", err)
	}
	if !IsDone(loaded, "subdomains") {
		t.Fatal("saved checkpoint did not persist completed step")
	}

	if err := MarkInterrupted(path, loaded, "manual interrupt"); err != nil {
		t.Fatalf("MarkInterrupted: %v", err)
	}
	interrupted, err := Load(path, "example.com")
	if err != nil {
		t.Fatalf("Load interrupted checkpoint: %v", err)
	}
	if !interrupted.Interrupted {
		t.Fatal("checkpoint was not marked interrupted")
	}
	if len(interrupted.Warnings) != 1 {
		t.Fatalf("warnings length = %d, want 1", len(interrupted.Warnings))
	}
}

func TestCompletedListSorted(t *testing.T) {
	st := New("example.com")
	st.CompletedSteps["z"] = true
	st.CompletedSteps["a"] = true
	got := CompletedList(st)
	want := []string{"a", "z"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("CompletedList[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
