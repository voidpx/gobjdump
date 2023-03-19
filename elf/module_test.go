package elf

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestModule(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	rd := filepath.Dir(wd)
	cmd := exec.Command("go", "build")
	cmd.Dir = rd
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		panic(err)
	}

	f := Open(rd + "/gobjdump")
	sb := strings.Builder{}
	f.PrintModule(&sb)
	t.Log("module layout:" + sb.String())
}
