package tools

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

type Result struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
	Output    string `json:"output,omitempty"`
	Error     string `json:"error,omitempty"`
}

func Available(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func Run(ctx context.Context, timeout time.Duration, name string, args ...string) Result {
	res := Result{Name: name, Available: Available(name)}
	if !res.Available {
		res.Error = fmt.Sprintf("%s not found", name)
		return res
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	res.Output = string(out)
	if ctx.Err() == context.DeadlineExceeded {
		res.Error = "timeout"
		return res
	}
	if err != nil {
		res.Error = err.Error()
	}
	return res
}
