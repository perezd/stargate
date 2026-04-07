// Package parser wraps mvdan.cc/sh/v3/syntax to parse shell commands and
// extract command invocations from the resulting AST.
package parser

import (
	"fmt"
	"strings"

	"github.com/perezd/stargate/internal/rules"
	"mvdan.cc/sh/v3/syntax"
)

// dialectVariant maps dialect strings to syntax.LangVariant values.
var dialectVariant = map[string]syntax.LangVariant{
	"bash":  syntax.LangBash,
	"posix": syntax.LangPOSIX,
	"mksh":  syntax.LangMirBSDKorn,
}

// Parse parses a shell command string into an AST using the given dialect.
// Supported dialects: "bash", "posix", "mksh". Defaults to bash if unknown.
func Parse(command string, dialect string) (*syntax.File, error) {
	variant, ok := dialectVariant[dialect]
	if !ok {
		variant = syntax.LangBash
	}
	p := syntax.NewParser(syntax.Variant(variant))
	r := strings.NewReader(command)
	f, err := p.Parse(r, "")
	if err != nil {
		return nil, fmt.Errorf("parse error: %w", err)
	}
	return f, nil
}

// ParseAndWalk parses a shell command string and then walks the AST to extract
// all command invocations.
func ParseAndWalk(command string, dialect string) ([]rules.CommandInfo, error) {
	f, err := Parse(command, dialect)
	if err != nil {
		return nil, err
	}
	return Walk(f), nil
}
