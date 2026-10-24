//go:build ignore

// Sample NightfallLX plugin.
//
// Build on Linux/macOS:
//
//	mkdir -p ~/.nightfalllx/plugins
//	go build -buildmode=plugin -o ~/.nightfalllx/plugins/sample.so ./pkg/plugins/examples/sample_plugin.go
//
// Then run:
//
//	nightfalllx -u http://target.lab/ --plugins
//
// The exported symbol must be named Plugin and implement:
//
//	Name() string
//	Execute(target string, client *http.Client) (string, error)
package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

type samplePlugin struct{}

func (samplePlugin) Name() string {
	return "sample-wordpress-check"
}

func (samplePlugin) Execute(target string, client *http.Client) (string, error) {
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Get(target)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return "", err
	}
	lower := strings.ToLower(string(body))
	if strings.Contains(lower, "wp-content") || strings.Contains(lower, "wordpress") {
		return fmt.Sprintf("WordPress indicators found on %s (HTTP %d)", target, resp.StatusCode), nil
	}
	return fmt.Sprintf("No WordPress indicators found on %s (HTTP %d)", target, resp.StatusCode), nil
}

// Plugin is the symbol loaded by pkg/plugins.
var Plugin samplePlugin
