package security

import "regexp"

var failedLoginPatterns = []*regexp.Regexp{
	regexp.MustCompile(`Failed password for (?P<username>\w+) from (?P<source_ip>\d+\.\d+\.\d+\.\d+)`),
	regexp.MustCompile(`Invalid password for user (?P<username>\w+) from (?P<source_ip>\d+\.\d+\.\d+\.\d+)`),
	regexp.MustCompile(`Authentication failed for (?P<username>\w+) from (?P<source_ip>\d+\.\d+\.\d+\.\d+)`),
	regexp.MustCompile(`Login failed user=(?P<username>\w+) src=(?P<source_ip>\d+\.\d+\.\d+\.\d+)`),
}

func ParseLinuxAuthLog(message string) map[string]any {
	for _, pattern := range failedLoginPatterns {
		match := pattern.FindStringSubmatch(message)
		if match == nil {
			continue
		}

		values := map[string]string{}
		for index, name := range pattern.SubexpNames() {
			if index > 0 && name != "" {
				values[name] = match[index]
			}
		}

		return map[string]any{
			"category":  "authentication",
			"action":    "login_failed",
			"username":  values["username"],
			"source_ip": values["source_ip"],
			"severity":  "medium",
		}
	}

	return map[string]any{
		"category":  "unknown",
		"action":    "unknown",
		"username":  nil,
		"source_ip": nil,
		"severity":  "low",
	}
}
