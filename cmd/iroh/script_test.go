package main

import (
	"context"
	"strings"
	"testing"

	"rsc.io/script"
	"rsc.io/script/scripttest"
)

// TestScripts runs the txtar-based CLI scripts in testdata/script. Each script
// exercises the iroh command through the in-process run() entrypoint, so the
// tests need no compiled binary.
func TestScripts(t *testing.T) {
	engine := &script.Engine{
		Cmds:  scriptCmds(),
		Conds: scripttest.DefaultConds(),
		Quiet: !testing.Verbose(),
	}
	scripttest.Test(t, context.Background(), engine, nil, "testdata/script/*.txtar")
}

// scriptCmds returns the default script commands plus an "iroh" command that
// invokes run() in-process.
func scriptCmds() map[string]script.Cmd {
	cmds := scripttest.DefaultCmds()
	cmds["iroh"] = script.Command(
		script.CmdUsage{
			Summary: "run the iroh CLI in-process",
			Args:    "args...",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			var stdout, stderr strings.Builder
			err := run(args, strings.NewReader(""), &stdout, &stderr)
			wait := func(*script.State) (string, string, error) {
				return stdout.String(), stderr.String(), err
			}
			return wait, nil
		},
	)
	return cmds
}
