package policy

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

type policyInput struct {
	Data     map[string]interface{}
	FilePath string
}

func collectPolicyInputs(root string) ([]policyInput, error) {
	var inputs []policyInput

	k8sInputs, err := collectKubernetesInputs(root)
	if err != nil {
		return nil, err
	}
	inputs = append(inputs, k8sInputs...)

	tfInput, err := collectTerraformInput(root)
	if err != nil {
		return nil, err
	}
	if tfInput != nil {
		inputs = append(inputs, *tfInput)
	}

	return inputs, nil
}

func collectKubernetesInputs(root string) ([]policyInput, error) {
	var inputs []policyInput

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		if !strings.Contains(string(content), "apiVersion:") {
			return nil
		}

		var doc map[string]interface{}
		if err := yaml.Unmarshal(content, &doc); err != nil {
			return nil
		}

		rel, _ := filepath.Rel(root, path)
		doc["_file"] = rel
		inputs = append(inputs, policyInput{Data: doc, FilePath: rel})

		return nil
	})

	return inputs, err
}

var tfResourcePattern = regexp.MustCompile(`resource\s+"([^"]+)"\s+"([^"]+)"\s*\{`)

func collectTerraformInput(root string) (*policyInput, error) {
	var changes []map[string]interface{}

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		if filepath.Ext(path) != ".tf" {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		rel, _ := filepath.Rel(root, path)
		fileChanges := parseTerraformResources(string(content), rel)
		changes = append(changes, fileChanges...)
		return nil
	})
	if err != nil {
		return nil, err
	}

	if len(changes) == 0 {
		return nil, nil
	}

	return &policyInput{
		Data: map[string]interface{}{
			"resource_changes": changes,
		},
		FilePath: root,
	}, nil
}

func parseTerraformResources(content, file string) []map[string]interface{} {
	var changes []map[string]interface{}

	matches := tfResourcePattern.FindAllStringSubmatchIndex(content, -1)
	for i, loc := range matches {
		resourceType := content[loc[2]:loc[3]]
		resourceName := content[loc[4]:loc[5]]

		bodyStart := loc[1]
		bodyEnd := len(content)
		if i+1 < len(matches) {
			bodyEnd = matches[i+1][0]
		}

		body := content[bodyStart:bodyEnd]
		after := parseTerraformAttributes(body)

		changes = append(changes, map[string]interface{}{
			"type": resourceType,
			"name": resourceName,
			"file": file,
			"change": map[string]interface{}{
				"after": after,
			},
		})
	}

	return changes
}

var tfAttrPattern = regexp.MustCompile(`(?m)^\s*([a-zA-Z0-9_]+)\s*=\s*(.+)$`)

func parseTerraformAttributes(body string) map[string]interface{} {
	attrs := make(map[string]interface{})

	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || trimmed == "{" || trimmed == "}" {
			continue
		}

		match := tfAttrPattern.FindStringSubmatch(trimmed)
		if len(match) < 3 {
			continue
		}

		key := match[1]
		value := strings.TrimSpace(match[2])
		value = strings.Trim(value, `"`)

		switch value {
		case "true":
			attrs[key] = true
		case "false":
			attrs[key] = false
		default:
			attrs[key] = value
		}
	}

	return attrs
}
