package main

import (
	"reflect"
	"testing"
)

func TestStripTargetFlags(t *testing.T) {
	args := []string{
		"-l", "targets.txt",
		"-u=http://old.lab",
		"-o", "old-report",
		"--log=old.log",
		"-m", "all",
		"-H", "X-Test: yes",
		"--", "ignored",
	}
	got := stripTargetFlags(args, "l", "u", "o", "log")
	want := []string{"-m", "all", "-H", "X-Test: yes"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestTargetArgs(t *testing.T) {
	args := []string{"-l", "targets.txt", "-u", "http://old.lab", "-m", "all"}
	got := targetArgs(args, "http://new.lab:8080", "reports/new", "reports/new.log")
	want := []string{
		"-m", "all",
		"-u", "http://new.lab:8080",
		"-o", "reports/new",
		"-log", "reports/new.log",
		"-l=",
		"-list=",
		"-no-update-check",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestTargetArgsWithoutLog(t *testing.T) {
	got := targetArgs([]string{"-m", "headers"}, "target.lab", "scan-target", "")
	want := []string{
		"-m", "headers",
		"-u", "target.lab",
		"-o", "scan-target",
		"-l=",
		"-list=",
		"-no-update-check",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
