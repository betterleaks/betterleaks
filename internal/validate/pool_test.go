package validate

import "testing"

func TestValidationCacheKeyIncludesAttributes(t *testing.T) {
	captures := map[string]string{"account": "prod"}

	first := validationCacheKey(
		"rule",
		"secret",
		captures,
		map[string]string{"path": "service/config.yml"},
	)
	second := validationCacheKey(
		"rule",
		"secret",
		captures,
		map[string]string{"path": "service/other.yml"},
	)

	if first == second {
		t.Fatal("validation cache key did not change when attributes changed")
	}
}
