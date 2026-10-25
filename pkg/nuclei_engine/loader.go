package nuclei_engine

import (
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadTemplateFromFile parses a single Nuclei YAML template.
func LoadTemplateFromFile(filePath string) (*NucleiTemplate, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var tmpl NucleiTemplate
	if err := yaml.Unmarshal(data, &tmpl); err != nil {
		return nil, err
	}

	return &tmpl, nil
}

// LoadTemplatesFromDir recursively parses all YAML templates in directory.
func LoadTemplatesFromDir(dir string, tagFilter string) ([]*NucleiTemplate, error) {
	var templates []*NucleiTemplate
	tags := strings.Split(strings.ToLower(tagFilter), ",")

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".yaml" || ext == ".yml" {
			tmpl, err := LoadTemplateFromFile(path)
			if err == nil && tmpl != nil && tmpl.ID != "" {
				if tagFilter != "" {
					matched := false
					tmplTags := strings.ToLower(tmpl.Info.Tags)
					for _, t := range tags {
						t = strings.TrimSpace(t)
						if t != "" && strings.Contains(tmplTags, t) {
							matched = true
							break
						}
					}
					if !matched {
						return nil
					}
				}
				templates = append(templates, tmpl)
			}
		}
		return nil
	})

	return templates, err
}
