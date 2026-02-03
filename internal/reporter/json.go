package reporter

import (
	"encoding/json"

	"github.com/cozygarage/sentinelflow/pkg/api"
)

// JSONFormatter formats reports as JSON
type JSONFormatter struct{}

func (f *JSONFormatter) Format(result *api.ScanResult) (string, error) {
	output, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", err
	}

	return string(output), nil
}
