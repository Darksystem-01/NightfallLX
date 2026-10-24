package wordlists

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveCommon(t *testing.T) {
	words, src, err := Resolve(CategoryCommon, "")
	if err != nil {
		t.Fatalf("Resolve Common failed: %v", err)
	}
	if len(words) == 0 {
		t.Fatalf("expected non-empty common wordlist")
	}
	t.Logf("Resolved Common: %d words from %s", len(words), src)
}

func TestResolveLFI(t *testing.T) {
	words, src, err := Resolve(CategoryLFI, "")
	if err != nil {
		t.Fatalf("Resolve LFI failed: %v", err)
	}
	if len(words) == 0 {
		t.Fatalf("expected non-empty LFI wordlist")
	}
	t.Logf("Resolved LFI: %d words from %s", len(words), src)
}

func TestResolveParams(t *testing.T) {
	words, src, err := Resolve(CategoryParams, "")
	if err != nil {
		t.Fatalf("Resolve Params failed: %v", err)
	}
	if len(words) == 0 {
		t.Fatalf("expected non-empty Params wordlist")
	}
	t.Logf("Resolved Params: %d words from %s", len(words), src)
}

func TestGenerate4DigitIDOR(t *testing.T) {
	words, src, err := Resolve(CategoryNumeric, "4digit")
	if err != nil {
		t.Fatalf("Resolve 4digit failed: %v", err)
	}
	if len(words) < 10000 {
		t.Fatalf("expected at least 10000 numbers, got %d", len(words))
	}

	found0 := false
	found0000 := false
	found10000 := false
	for _, w := range words {
		if w == "0" {
			found0 = true
		}
		if w == "0000" {
			found0000 = true
		}
		if w == "10000" {
			found10000 = true
		}
	}

	if !found0 || !found0000 || !found10000 {
		t.Errorf("expected 0, 0000, 10000 in generated IDOR list: 0=%v, 0000=%v, 10000=%v", found0, found0000, found10000)
	}
	t.Logf("Generated 4digit: %d entries from %s", len(words), src)
}

func TestResolveColorsAndCities(t *testing.T) {
	colors, srcC, errC := Resolve(CategoryColors, "colors")
	if errC != nil || len(colors) == 0 {
		t.Fatalf("Resolve colors failed: %v, len=%d", errC, len(colors))
	}
	t.Logf("Colors: %d from %s", len(colors), srcC)

	cities, srcCi, errCi := Resolve(CategoryCities, "cities")
	if errCi != nil || len(cities) == 0 {
		t.Fatalf("Resolve cities failed: %v, len=%d", errCi, len(cities))
	}
	t.Logf("Cities: %d from %s", len(cities), srcCi)
}

func TestCustomUserFile(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "custom.txt")
	err := os.WriteFile(tmp, []byte("custom1\ncustom2\n# comment\ncustom3\n"), 0644)
	if err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	words, src, err := Resolve(CategoryCommon, tmp)
	if err != nil {
		t.Fatalf("Resolve custom failed: %v", err)
	}
	if len(words) != 3 || words[0] != "custom1" || words[2] != "custom3" {
		t.Fatalf("unexpected custom words: %v", words)
	}
	if src != tmp {
		t.Errorf("expected src=%q, got %q", tmp, src)
	}
}
