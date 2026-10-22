package main

import (
	"net/http/httptest"
	"nightfalllx/pkg/client"
	"nightfalllx/pkg/discovery"
	"nightfalllx/pkg/modules"
	"nightfalllx/pkg/oast"
	"nightfalllx/testdata"
	"regexp"
	"sort"
	"testing"
	"time"
)

func TestIntegrationLabSuite(t *testing.T) {
	mux := testdata.SetupLabMux()
	ts := httptest.NewServer(mux)
	defer ts.Close()

	c := client.NewClient("", 8*time.Second, true, "", nil)

	// 1. JSON SQLi Test
	t.Run("JSON_SQLi", func(t *testing.T) {
		target := &modules.Target{
			URL:     ts.URL + "/vuln/json_sqli",
			Method:  "POST",
			IsJSON:  true,
			RawJSON: `{"user":{"id":1}}`,
		}
		_ = target.ParseJSONBody(target.RawJSON)

		mod := modules.NewSQLiModule()
		findings, err := mod.Run(target, c)
		if err != nil {
			t.Fatalf("SQLi module failed: %v", err)
		}
		if len(findings) == 0 {
			t.Fatalf("expected SQLi finding in JSON body, got none")
		}
		if findings[0].ConfidenceLevel != modules.ConfidenceConfirmed {
			t.Fatalf("expected confirmed finding, got %s", findings[0].ConfidenceLevel)
		}
	})

	// 2. Time-Based SQLi Test
	t.Run("TimeBased_SQLi", func(t *testing.T) {
		target := &modules.Target{
			URL:    ts.URL + "/vuln/time_sqli",
			Method: "GET",
			Params: map[string]string{"id": "1"},
		}

		mod := modules.NewSQLiModule()
		mod.DefaultDelay = 1 // 1s then 4s for quick test execution
		findings, err := mod.Run(target, c)
		if err != nil {
			t.Fatalf("time-based SQLi failed: %v", err)
		}
		if len(findings) == 0 {
			t.Fatalf("expected time-based SQLi finding, got none")
		}
	})

	// 3. OAST SSRF Test (in-process callback)
	t.Run("OAST_SSRF", func(t *testing.T) {
		oastSrv := oast.NewServer("127.0.0.1:0", "", 3*time.Second)
		if err := oastSrv.Start(); err != nil {
			t.Fatalf("failed to start OAST: %v", err)
		}
		defer oastSrv.Close()

		target := &modules.Target{
			URL:    ts.URL + "/vuln/oast_ssrf",
			Method: "GET",
			Params: map[string]string{"url": "http://127.0.0.1/"},
			OAST:   oastSrv,
		}

		mod := modules.NewSSRFModule()
		findings, err := mod.Run(target, c)
		if err != nil {
			t.Fatalf("SSRF module error: %v", err)
		}
		if len(findings) == 0 {
			t.Fatalf("expected OAST SSRF finding, got none")
		}
		if findings[0].ConfidenceLevel != modules.ConfidenceConfirmed {
			t.Fatalf("expected confirmed OAST finding, got %s", findings[0].ConfidenceLevel)
		}
	})

	// 4. GraphQL Introspection Test
	t.Run("GraphQL_Introspection", func(t *testing.T) {
		target := &modules.Target{
			URL:    ts.URL + "/graphql",
			Method: "POST",
		}

		mod := modules.NewGraphQLModule()
		findings, err := mod.Run(target, c)
		if err != nil {
			t.Fatalf("GraphQL module error: %v", err)
		}
		if len(findings) == 0 {
			t.Fatalf("expected GraphQL introspection finding, got none")
		}
	})

	// 5. JWT alg:none Test
	t.Run("JWT_AlgNone", func(t *testing.T) {
		dummyToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlc3QifQ.invalidsig"
		target := &modules.Target{
			URL:     ts.URL + "/vuln/jwt",
			Method:  "GET",
			Headers: map[string]string{"Authorization": "Bearer " + dummyToken},
		}

		mod := modules.NewJWTModule()
		findings, err := mod.Run(target, c)
		if err != nil {
			t.Fatalf("JWT module error: %v", err)
		}
		if len(findings) == 0 {
			t.Fatalf("expected JWT alg:none finding, got none")
		}
	})

	// 6. Parameter Discovery with 3 hidden params
	t.Run("Parameter_Discovery_Three", func(t *testing.T) {
		target := &modules.Target{
			URL:    ts.URL + "/vuln/params",
			Method: "GET",
		}

		words := []string{
			"page", "limit", "offset", "sort", "order", "q", "search", "lang",
			"admin_key", "filter", "view", "debug_mode", "category", "tag", "secret_flag", "format",
		}

		pd := discovery.NewParameterDiscovery(5)
		found, err := pd.Discover(target, c, words)
		if err != nil {
			t.Fatalf("discovery error: %v", err)
		}

		sort.Strings(found)
		expected := []string{"admin_key", "debug_mode", "secret_flag"}
		if len(found) != 3 {
			t.Fatalf("expected 3 discovered params, got %d: %v", len(found), found)
		}
		for i := 0; i < 3; i++ {
			if found[i] != expected[i] {
				t.Errorf("at index %d: expected %s, got %s", i, expected[i], found[i])
			}
		}
	})

	// 7. Login with Cookie Session
	t.Run("Login_Cookie_Session", func(t *testing.T) {
		authClient := client.NewClient("", 3*time.Second, true, "", nil)
		authClient.LoginURL = ts.URL + "/login"
		authClient.LoginData = "user={{user}}&pass={{pass}}"
		authClient.LoginUser = "admin"
		authClient.LoginPass = "cyberpass"
		authClient.LoginSuccessStatus = 200
		authClient.LoginSuccessRegex = regexp.MustCompile(`"status":"success"`)

		if err := authClient.PerformLogin(); err != nil {
			t.Fatalf("login failed: %v", err)
		}

		resp, err := authClient.Request("GET", ts.URL+"/protected/profile", "", nil)
		if err != nil {
			t.Fatalf("protected access failed: %v", err)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("expected status 200 after login, got %d", resp.StatusCode)
		}
	})

	// 8. Clean Static Page: Zero False Positives
	t.Run("Clean_Static_Zero_False_Positives", func(t *testing.T) {
		target := &modules.Target{
			URL:    ts.URL + "/clean/page",
			Method: "GET",
			Params: map[string]string{"id": "1", "name": "test"},
		}

		allMods := []modules.Module{
			modules.NewSQLiModule(),
			modules.NewLFIModule(),
			modules.NewSSTIModule(),
			modules.NewCMDiModule(),
			modules.NewXSSModule(),
			modules.NewNoSQLiModule(),
			modules.NewXXEModule(),
			modules.NewCRLFModule(),
			modules.NewHostHeaderModule(),
			modules.NewCSRFModule(),
		}

		for _, m := range allMods {
			findings, err := m.Run(target, c)
			if err != nil {
				t.Fatalf("error running %s on clean page: %v", m.Name(), err)
			}
			if len(findings) > 0 {
				t.Fatalf("module %s falsely flagged clean page with %d findings!", m.Name(), len(findings))
			}
		}
	})
}
