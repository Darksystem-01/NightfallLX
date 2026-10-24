package wordlists

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Standard system paths for SecLists, RockYou, and CWES
const (
	SecListsBasePath = "/usr/share/wordlists/SecLists"
	SecListsAltPath  = "/usr/share/seclists"
	RockYouPath      = "/usr/share/wordlists/rockyou.txt"
	CWESBasePath     = "/home/cyborg/CWES"

	SecListsCommonPath = "Discovery/Web-Content/common.txt"
	SecListsLFIPath    = "Fuzzing/LFI/LFI-Jhaddix.txt"
	SecListsParamsPath = "Discovery/Web-Content/burp-parameter-names.txt"
)

// Category represents a specialized wordlist purpose.
type Category string

const (
	CategoryCommon   Category = "common"
	CategoryLFI      Category = "lfi"
	CategoryParams   Category = "params"
	CategoryBrute    Category = "brute"
	CategoryNumeric  Category = "4digit"
	CategoryColors   Category = "colors"
	CategoryCities   Category = "cities"
	CategoryPins     Category = "pins"
	CategoryUserlist Category = "users"
)

var (
	cacheLock sync.RWMutex
	cache     = make(map[string][]string)
)

// Resolve returns candidates for a given category.
// If userPath is provided (non-empty), it resolves userPath (or keyword alias).
// If userPath is empty, it resolves the best default system path for that category.
func Resolve(category Category, userPath string) (words []string, sourceName string, err error) {
	trimmed := strings.TrimSpace(userPath)

	// 1. Check keyword aliases in userPath
	lower := strings.ToLower(trimmed)
	switch lower {
	case "4digit", "4digits", "idor", "numbers", "seq":
		return Generate4DigitIDOR(), "generated (seq 0 10000 / 4-digit)", nil
	case "colors", "color", "colour", "colours":
		return LoadColors(), "default colors (/home/cyborg/CWES/colors.txt)", nil
	case "cities", "city", "world-cities":
		return LoadCities(), "default cities (/home/cyborg/CWES/world-cities.csv)", nil
	case "pins", "pin", "2fa":
		return LoadPins(), "default 2FA PINs (/home/cyborg/CWES/pins.txt)", nil
	case "users", "user", "usernames":
		return LoadUsernames(), "default usernames (/home/cyborg/CWES/top-usernames-shortlist.txt)", nil
	case "rockyou", "passwords", "password":
		return LoadRockYou(100000), "default passwords (/usr/share/wordlists/rockyou.txt)", nil
	case "lfi", "traversal":
		return LoadLFI(), "default LFI (/usr/share/wordlists/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt)", nil
	case "params", "param", "parameters":
		return LoadParams(), "default parameters (/usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt)", nil
	case "common", "dir", "dirs":
		return LoadCommon(), "default SecLists common.txt", nil
	}

	// 2. User explicitly specified a custom file path
	if trimmed != "" {
		words, err := LoadFile(trimmed)
		if err != nil {
			return nil, trimmed, err
		}
		return words, trimmed, nil
	}

	// 3. Auto-resolve default wordlist when user did not specify -w
	switch category {
	case CategoryCommon:
		return LoadCommon(), "default SecLists common.txt", nil
	case CategoryLFI:
		return LoadLFI(), "default LFI (SecLists/Fuzzing/LFI/LFI-Jhaddix.txt)", nil
	case CategoryParams:
		return LoadParams(), "default parameters (SecLists burp-parameter-names.txt)", nil
	case CategoryBrute:
		return LoadRockYou(50000), "default brute passwords", nil
	case CategoryNumeric:
		return Generate4DigitIDOR(), "generated (seq 0 10000 / 4-digit)", nil
	case CategoryColors:
		return LoadColors(), "default colors (CWES/colors.txt)", nil
	case CategoryCities:
		return LoadCities(), "default cities (CWES/world-cities.csv)", nil
	case CategoryPins:
		return LoadPins(), "default PINs (CWES/pins.txt)", nil
	case CategoryUserlist:
		return LoadUsernames(), "default usernames", nil
	default:
		return LoadCommon(), "default SecLists common.txt", nil
	}
}

// LoadCommon loads SecLists common.txt or CWES custom wordlist, or falls back to built-in.
func LoadCommon() []string {
	candidates := []string{
		filepath.Join(SecListsBasePath, SecListsCommonPath),
		filepath.Join(SecListsAltPath, SecListsCommonPath),
		filepath.Join(CWESBasePath, "custom_wordlist.txt"),
	}
	for _, path := range candidates {
		if fileExists(path) {
			if words, err := LoadFile(path); err == nil && len(words) > 0 {
				return words
			}
		}
	}
	return defaultBuiltinCommon
}

// LoadLFI loads SecLists LFI-Jhaddix.txt or falls back to built-in traversal paths.
func LoadLFI() []string {
	candidates := []string{
		filepath.Join(SecListsBasePath, SecListsLFIPath),
		filepath.Join(SecListsAltPath, SecListsLFIPath),
	}
	for _, path := range candidates {
		if fileExists(path) {
			if words, err := LoadFile(path); err == nil && len(words) > 0 {
				return words
			}
		}
	}
	return defaultBuiltinLFI
}

// LoadParams loads SecLists burp-parameter-names.txt or falls back to built-in list.
func LoadParams() []string {
	candidates := []string{
		filepath.Join(SecListsBasePath, SecListsParamsPath),
		filepath.Join(SecListsAltPath, SecListsParamsPath),
	}
	for _, path := range candidates {
		if fileExists(path) {
			if words, err := LoadFile(path); err == nil && len(words) > 0 {
				return words
			}
		}
	}
	return defaultBuiltinParams
}

// LoadRockYou loads passwords from rockyou.txt (capped at maxLines for performance) or CWES passwords.
func LoadRockYou(maxLines int) []string {
	if maxLines <= 0 {
		maxLines = 50000
	}
	candidates := []string{
		RockYouPath,
		filepath.Join(CWESBasePath, "passwords.txt"),
		filepath.Join(CWESBasePath, "2023-200_most_used_passwords.txt"),
		filepath.Join(CWESBasePath, "500-worst-passwords.txt"),
	}
	for _, path := range candidates {
		if fileExists(path) {
			if words, err := LoadFileLimited(path, maxLines); err == nil && len(words) > 0 {
				return words
			}
		}
	}
	return defaultBuiltinPasswords
}

// Generate4DigitIDOR generates sequential 0 to 10000 (both plain and zero-padded 4-digit)
// plus loads any available numbers from CWES/numbers.txt or CWES/pins.txt.
func Generate4DigitIDOR() []string {
	cacheLock.RLock()
	if cached, ok := cache["4digit_idor"]; ok {
		cacheLock.RUnlock()
		return cached
	}
	cacheLock.RUnlock()

	seen := make(map[string]bool)
	var list []string

	// Check CWES pins.txt or numbers.txt first if present
	for _, path := range []string{filepath.Join(CWESBasePath, "pins.txt"), filepath.Join(CWESBasePath, "numbers.txt")} {
		if fileExists(path) {
			if words, err := LoadFile(path); err == nil {
				for _, w := range words {
					if !seen[w] {
						seen[w] = true
						list = append(list, w)
					}
				}
			}
		}
	}

	// Generate seq 0 10000:
	// Include 0..10000 and 4-digit formatted 0000..9999
	for i := 0; i <= 10000; i++ {
		plain := fmt.Sprintf("%d", i)
		if !seen[plain] {
			seen[plain] = true
			list = append(list, plain)
		}
		if i <= 9999 {
			padded := fmt.Sprintf("%04d", i)
			if !seen[padded] {
				seen[padded] = true
				list = append(list, padded)
			}
		}
	}

	cacheLock.Lock()
	cache["4digit_idor"] = list
	cacheLock.Unlock()

	return list
}

// LoadColors loads colors from CWES/colors.txt or built-in colors.
func LoadColors() []string {
	path := filepath.Join(CWESBasePath, "colors.txt")
	if fileExists(path) {
		if words, err := LoadFile(path); err == nil && len(words) > 0 {
			return words
		}
	}
	return defaultBuiltinColors
}

// LoadCities loads city names from CWES/world-cities.csv (column 0) or built-in cities.
func LoadCities() []string {
	path := filepath.Join(CWESBasePath, "world-cities.csv")
	if fileExists(path) {
		f, err := os.Open(path)
		if err == nil {
			defer f.Close()
			r := csv.NewReader(f)
			var cities []string
			seen := make(map[string]bool)
			for {
				record, err := r.Read()
				if err == io.EOF {
					break
				}
				if err != nil || len(record) == 0 {
					continue
				}
				cityName := strings.TrimSpace(record[0])
				if cityName == "" || strings.EqualFold(cityName, "name") {
					continue
				}
				if !seen[cityName] {
					seen[cityName] = true
					cities = append(cities, cityName)
				}
			}
			if len(cities) > 0 {
				return cities
			}
		}
	}
	return defaultBuiltinCities
}

// LoadPins loads PINs from CWES/pins.txt or CWES/tokens.txt or generates 4-digit PINs.
func LoadPins() []string {
	for _, path := range []string{filepath.Join(CWESBasePath, "pins.txt"), filepath.Join(CWESBasePath, "tokens.txt")} {
		if fileExists(path) {
			if words, err := LoadFile(path); err == nil && len(words) > 0 {
				return words
			}
		}
	}
	return Generate4DigitIDOR()
}

// LoadUsernames loads usernames from CWES/top-usernames-shortlist.txt or CWES/users.txt.
func LoadUsernames() []string {
	for _, path := range []string{
		filepath.Join(CWESBasePath, "top-usernames-shortlist.txt"),
		filepath.Join(CWESBasePath, "users.txt"),
	} {
		if fileExists(path) {
			if words, err := LoadFile(path); err == nil && len(words) > 0 {
				return words
			}
		}
	}
	return defaultBuiltinUsers
}

// LoadFile reads lines from a file ignoring blanks and comments.
func LoadFile(path string) ([]string, error) {
	return LoadFileLimited(path, 0)
}

// LoadFileLimited reads up to maxLines from a file (0 = unlimited).
func LoadFileLimited(path string, maxLines int) ([]string, error) {
	cacheLock.RLock()
	cacheKey := fmt.Sprintf("%s:%d", path, maxLines)
	if cached, ok := cache[cacheKey]; ok {
		cacheLock.RUnlock()
		return cached, nil
	}
	cacheLock.RUnlock()

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var words []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 2*1024*1024)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			words = append(words, line)
			if maxLines > 0 && len(words) >= maxLines {
				break
			}
		}
	}

	if err := sc.Err(); err != nil && len(words) == 0 {
		return nil, err
	}

	cacheLock.Lock()
	cache[cacheKey] = words
	cacheLock.Unlock()

	return words, nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// Fallback built-in lists when external wordlist files are absent
var defaultBuiltinCommon = []string{
	"admin", "login", "api", "dashboard", "panel", "robots.txt", ".git", ".env",
	"config", "backup", "db", "upload", "uploads", "shell", "test", "dev",
	"portal", "console", "server-status", "phpmyadmin", "actuator", "swagger",
	"graphql", "v1", "v2", "debug", "secret", "private", "users", "user",
	"manage", "manager", "app", "cgi-bin", "internal", "auth", "token",
	"register", "signup", "view", "edit", "create", "delete", "file", "download",
	"logs", "error.log", "access.log", "info.php", "phpinfo.php", "index.php",
	"home", "search", "query", "status", "health", "metrics", "root",
}

var defaultBuiltinLFI = []string{
	"../../../../etc/passwd",
	"../../../../../../../../etc/passwd",
	"/etc/passwd",
	"../../../../windows/win.ini",
	"../../../../windows/system32/drivers/etc/hosts",
	"php://filter/convert.base64-encode/resource=index.php",
	"php://filter/convert.base64-encode/resource=config.php",
}

var defaultBuiltinParams = []string{
	"id", "user", "username", "email", "pass", "password", "token", "key", "admin", "debug",
	"file", "path", "url", "redirect", "dest", "view", "show", "cat", "page", "role", "cmd",
	"exec", "action", "query", "search", "lang", "type", "filter", "sort", "data", "callback",
}

var defaultBuiltinPasswords = []string{
	"password", "123456", "12345678", "1234", "qwerty", "12345", "dragon",
	"admin", "welcome", "login", "secret", "root", "toor", "pass123",
}

var defaultBuiltinColors = []string{
	"red", "blue", "green", "yellow", "black", "white", "orange", "purple",
	"pink", "brown", "gray", "gold", "silver", "cyan", "magenta", "violet",
}

var defaultBuiltinCities = []string{
	"London", "Paris", "Berlin", "New York", "Tokyo", "Tashkent", "Moscow",
	"Dubai", "Singapore", "Sydney", "Toronto", "Madrid", "Rome", "Istanbul",
}

var defaultBuiltinUsers = []string{
	"admin", "root", "user", "guest", "test", "administrator", "manager", "operator",
}
