package config

import (
	"fmt"
	"os"

	"github.com/go-viper/mapstructure/v2"
	"github.com/knadh/koanf/parsers/toml"
	"github.com/knadh/koanf/providers/rawbytes"
	"github.com/knadh/koanf/v2"
)

// LoadTOML parses TOML content into a ViperConfig.
func LoadTOML(content string) (ViperConfig, error) {
	k := koanf.New(".")
	if err := k.Load(rawbytes.Provider([]byte(content)), toml.Parser()); err != nil {
		return ViperConfig{}, fmt.Errorf("failed to parse TOML: %w", err)
	}
	var vc ViperConfig
	if err := unmarshalKoanf(k, &vc); err != nil {
		return ViperConfig{}, fmt.Errorf("failed to unmarshal config: %w", err)
	}
	return vc, nil
}

// LoadTOMLFile parses a TOML file into a ViperConfig.
func LoadTOMLFile(path string) (ViperConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return ViperConfig{}, fmt.Errorf("failed to read config file %s: %w", path, err)
	}
	k := koanf.New(".")
	if err := k.Load(rawbytes.Provider(data), toml.Parser()); err != nil {
		return ViperConfig{}, fmt.Errorf("failed to parse config file %s: %w", path, err)
	}
	var vc ViperConfig
	if err := unmarshalKoanf(k, &vc); err != nil {
		return ViperConfig{}, fmt.Errorf("failed to unmarshal config file %s: %w", path, err)
	}
	vc.configPath = path
	return vc, nil
}

func unmarshalKoanf(k *koanf.Koanf, v any) error {
	return k.UnmarshalWithConf("", v, koanf.UnmarshalConf{
		Tag: "mapstructure",
		DecoderConfig: &mapstructure.DecoderConfig{
			DecodeHook: mapstructure.ComposeDecodeHookFunc(
				mapstructure.StringToTimeDurationHookFunc(),
			),
			Metadata:         nil,
			WeaklyTypedInput: true,
			Squash:           true,
			Result:           v,
			TagName:          "mapstructure",
		},
	})
}
