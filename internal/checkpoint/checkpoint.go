package checkpoint

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// State stores resumable scan progress for a single Reconixia workspace.
type State struct {
	Target         string          `json:"target"`
	StartedAt      string          `json:"started_at"`
	UpdatedAt      string          `json:"updated_at"`
	CompletedSteps map[string]bool `json:"completed_steps"`
	LastStep       string          `json:"last_step,omitempty"`
	Interrupted    bool            `json:"interrupted"`
	Warnings       []string        `json:"warnings,omitempty"`
}

func New(target string) State {
	now := time.Now().Format(time.RFC3339)
	return State{
		Target:         target,
		StartedAt:      now,
		UpdatedAt:      now,
		CompletedSteps: map[string]bool{},
	}
}

func Load(path string, target string) (State, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return New(target), nil
		}
		return State{}, err
	}
	var st State
	if err := json.Unmarshal(raw, &st); err != nil {
		return State{}, err
	}
	if st.CompletedSteps == nil {
		st.CompletedSteps = map[string]bool{}
	}
	if st.Target == "" {
		st.Target = target
	}
	return st, nil
}

func Save(path string, st State) error {
	st.UpdatedAt = time.Now().Format(time.RFC3339)
	if st.CompletedSteps == nil {
		st.CompletedSteps = map[string]bool{}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0644)
}

func MarkDone(path string, st State, step string) (State, error) {
	if st.CompletedSteps == nil {
		st.CompletedSteps = map[string]bool{}
	}
	st.CompletedSteps[step] = true
	st.LastStep = step
	st.Interrupted = false
	return st, Save(path, st)
}

func MarkInterrupted(path string, st State, note string) error {
	st.Interrupted = true
	if note != "" {
		st.Warnings = append(st.Warnings, note)
	}
	return Save(path, st)
}

func IsDone(st State, step string) bool {
	return st.CompletedSteps != nil && st.CompletedSteps[step]
}

func CompletedList(st State) []string {
	out := make([]string, 0, len(st.CompletedSteps))
	for k, ok := range st.CompletedSteps {
		if ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
