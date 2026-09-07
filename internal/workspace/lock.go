package workspace

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type Lock struct {
	Path string
}

type lockInfo struct {
	PID       int    `json:"pid"`
	Target    string `json:"target"`
	StartedAt string `json:"started_at"`
}

func AcquireLock(dir, target string, staleAfter time.Duration) (*Lock, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, ".lock")
	if staleAfter <= 0 {
		staleAfter = 24 * time.Hour
	}
	if st, err := os.Stat(path); err == nil && time.Since(st.ModTime()) > staleAfter {
		_ = os.Remove(path)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		if os.IsExist(err) {
			return nil, fmt.Errorf("workspace locked: another Reconixia scan may be running for %s (%s)", target, path)
		}
		return nil, err
	}
	defer f.Close()

	info := lockInfo{
		PID:       os.Getpid(),
		Target:    target,
		StartedAt: time.Now().Format(time.RFC3339),
	}
	raw, _ := json.MarshalIndent(info, "", "  ")
	if _, err := f.Write(append(raw, '\n')); err != nil {
		_ = os.Remove(path)
		return nil, err
	}
	return &Lock{Path: path}, nil
}

func (l *Lock) Release() error {
	if l == nil || l.Path == "" {
		return nil
	}
	return os.Remove(l.Path)
}
