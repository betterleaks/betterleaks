// Package rules defines Betterleaks' default rules, one file per provider.
// Rules that are not specific to a provider live in rules/generic. Each file
// registers its rules with rulebuilder.Add, and go generate renders them into
// config/betterleaks.toml.
//
// Import it for its registrations, including those of rules/generic.
package rules

import _ "github.com/betterleaks/betterleaks/v2/rules/generic" // register generic rules

//go:generate go run ./gen ../config/betterleaks.toml
