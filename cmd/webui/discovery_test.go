package main

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestURLDiscovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	hosts := []string{"example.com"}
	// Note: this relies on finding katana.exe which might need CWD adjustment
	// The test runner CWD is usually the package dir. If running from cmd/webui,
	// findKatanaBinary looks in CWD (cmd/webui) or parent.
	// We might need to copy katana.exe or rely on finding it in e:\subfinder.

	results, err := runURLDiscoveryAggressive(ctx, hosts, func(p int, m string) {
		fmt.Printf("[%d%%] %s\n", p, m)
	})
	if err != nil {
		t.Fatalf("Discovery failed: %v", err)
	}

	out, _ := json.MarshalIndent(results, "", "  ")
	fmt.Println(string(out))

	if len(results) == 0 {
		t.Log("No URLs found (internet might be down or example.com has no extra links), but function ran.")
	} else {
		t.Logf("Found %d URLs", len(results))
	}
}
