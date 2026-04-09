// fence.go implements XML fence tag stripping for LLM prompt security.
//
// All untrusted content interpolated into the prompt is wrapped in XML fence
// tags (e.g., <untrusted_command>). Before interpolation, both opening and
// closing fence tags are stripped from the content to prevent:
//   - Breakout: attacker embeds </untrusted_command> to close the fence early
//   - Trust confusion: attacker injects <trusted_scopes> inside untrusted content
//
// Stripping is iterative (handles recursive nesting), case-insensitive,
// handles whitespace variants, matches tags with attributes, and normalizes
// Unicode confusables for <, /, >.
package llm

import (
	"regexp"
	"strings"
)

// fenceTagNames are the XML tag names used to fence content in the LLM prompt.
var fenceTagNames = []string{
	"untrusted_command",
	"untrusted_file_contents",
	"parsed_structure",
	"precedent_context",
	"trusted_scopes",
}

// maxTagStripIterations bounds the iterative stripping loop to prevent
// infinite loops on pathological input.
const maxTagStripIterations = 10

// unicodeConfusables maps Unicode characters that visually resemble <, /, >
// to their ASCII equivalents. Applied before tag matching.
var unicodeConfusables = strings.NewReplacer(
	// Fullwidth forms
	"\uFF1C", "<", // ＜
	"\uFF0F", "/", // ／
	"\uFF1E", ">", // ＞
	// Mathematical angle brackets
	"\u27E8", "<", // ⟨
	"\u27E9", ">", // ⟩
	// Small form variants
	"\uFE64", "<", // ﹤
	"\uFE65", ">", // ﹥
	// Other common confusables
	"\u2039", "<", // ‹
	"\u203A", ">", // ›
	"\u2215", "/", // ∕
)

// fenceTagRegexps are compiled regexes for each fence tag name.
// Pattern requires exact tag name match (not prefix) — <trusted_scopesXYZ>
// would NOT match. The (?:\s|/?>|$) boundary ensures the tag name ends at
// whitespace, closing slash, >, or end of string.
var fenceTagRegexps []*regexp.Regexp

func init() {
	fenceTagRegexps = make([]*regexp.Regexp, len(fenceTagNames))
	for i, name := range fenceTagNames {
		pattern := `(?i)<\s*/?\s*` + regexp.QuoteMeta(name) + `(?:\s[^>]*)?\s*/?>`
		fenceTagRegexps[i] = regexp.MustCompile(pattern)
	}
}

// StripFenceTags removes all opening and closing XML fence tags from content.
// Applied iteratively until no more matches are found (up to maxTagStripIterations).
func StripFenceTags(content string) string {
	// Normalize Unicode confusables first.
	content = unicodeConfusables.Replace(content)

	for range maxTagStripIterations {
		changed := false
		for _, re := range fenceTagRegexps {
			next := re.ReplaceAllString(content, "")
			if next != content {
				changed = true
				content = next
			}
		}
		if !changed {
			break
		}
	}
	return content
}
