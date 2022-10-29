package shell

import (
	"os/exec"
	"github.com/go-cmd/cmd"
)

type ShellOutput struct {
	CmdError error
	Stdout string
	Stderr string
}


func Execute(execCmd string, stdoutTrue bool, stderrTrue bool) *ShellOutput {
	sOut := new(ShellOutput)
	sOut.CmdError,sOut.Stdout,sOut.Stderr = ShellExecWithChannels(execCmd,stdoutTrue,stderrTrue)
	return sOut
}

func ShellExecWithChannels(execCmd string, stdoutSync bool, stderrSync bool) (error, string, string) {
	var preferredShell string
	_, shellSearch := exec.LookPath("bash")
	if shellSearch != nil {
		preferredShell = "sh"
	} else {
		preferredShell = "bash"
	}

	var stdout string
	var stderr string

	shellCmd := cmd.NewCmd(preferredShell, "-c", execCmd)
	statusChan := shellCmd.Start()


	select {
	case finalStatus := <-statusChan:
		// done
		if finalStatus.Complete {
			status := shellCmd.Status()
			stdoutLen := len(status.Stdout)
			for l := 0; l < stdoutLen; l++ { stdout += status.Stdout[l] }
			stderrLen := len(status.Stderr)
			for l := 0; l < stderrLen; l++ { stderr += status.Stderr[l] }
		}
	default:
		// no, still running
	}

	// Block waiting for command to exit, be stopped, or be killed
	finalStatus := <-statusChan
	if finalStatus.Exit == 0 {
		return nil , stdout, stderr
	} else {
		return finalStatus.Error , stdout, stderr
	}

}


