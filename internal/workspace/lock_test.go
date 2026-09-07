package workspace

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAcquireLockPreventsConcurrentUse(t *testing.T) {
	dir := t.TempDir()
	first, err := AcquireLock(dir, "example.com", time.Hour)
	if err != nil {
		t.Fatalf("AcquireLock first: %v", err)
	}
	defer first.Release()

	if _, err := AcquireLock(dir, "example.com", time.Hour); err == nil {
		t.Fatal("expected second lock acquisition to fail")
	}
}

func TestAcquireLockRemovesStaleLock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".lock")
	if err := os.WriteFile(path, []byte("stale"), 0600); err != nil {
		t.Fatalf("write stale lock: %v", err)
	}
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatalf("set stale lock time: %v", err)
	}

	lock, err := AcquireLock(dir, "example.com", time.Hour)
	if err != nil {
		t.Fatalf("AcquireLock with stale lock: %v", err)
	}
	defer lock.Release()
}
