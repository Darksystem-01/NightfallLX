package modules

import "nightfalllx/pkg/xss"

func Registry(xssCfg *xss.EngineConfig) map[string]Module {
	xssModule := NewXSSModule()
	if xssCfg != nil {
		xssModule = NewXSSModuleWithConfig(xssCfg)
	}

	return map[string]Module{
		"sqli":           NewSQLiModule(),
		"ssti":           NewSSTIModule(),
		"lfi":            NewLFIModule(),
		"cmdi":           NewCMDiModule(),
		"xss":            xssModule,
		"cors":           NewCORSModule(),
		"redirect":       NewRedirectModule(),
		"ssrf":           NewSSRFModule(),
		"jwt":            NewJWTModule(),
		"waf":            NewWAFModule(),
		"idor":           NewIDORModule(),
		"csrf":           NewCSRFModule(),
		"xxe":            NewXXEModule(),
		"nosqli":         NewNoSQLiModule(),
		"upload":         NewUploadModule(),
		"headers":        NewHeadersModule(),
		"exposure":       NewExposureModule(),
		"hostheader":     NewHostHeaderModule(),
		"crlf":           NewCRLFModule(),
		"graphql":        NewGraphQLModule(),
		"protopollution": NewProtoPollutionModule(),
		"massassign":     NewMassAssignModule(),
		"deserialize":    NewDeserializeModule(),
		"exploit-mapper": NewExploitMapperModule(),
	}
}

func DefaultOrder() []string {
	return []string{
		"waf", "headers", "exposure", "sqli", "ssti", "lfi", "cmdi",
		"xss", "cors", "redirect", "ssrf", "jwt", "idor", "csrf",
		"xxe", "nosqli", "hostheader", "crlf", "graphql",
		"protopollution", "massassign", "deserialize", "exploit-mapper",
	}
}

func AllOrder() []string {
	order := DefaultOrder()
	return append(order, "upload")
}
