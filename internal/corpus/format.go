package corpus

import (
	"fmt"
	"strings"
	"time"
)

// FormatPrecedent holds the data needed to render a single precedent
// in the LLM prompt. This is a view type — it may be populated from
// a PrecedentEntry or constructed directly.
type FormatPrecedent struct {
	Decision   string    // "allow", "deny", or "user_approved"
	Command    string    // scrubbed raw command
	Reasoning  string    // LLM reasoning (may be empty)
	CWD        string    // working directory
	CreatedAt  time.Time // when the precedent was created
	Similarity float64   // Jaccard similarity score (0.0–1.0)
	ExactMatch bool      // true if signature_hash matches exactly
}

// FormatPrecedents renders a list of precedents as the {{precedents}}
// prompt block per spec §7.5. Returns empty string if no precedents.
func FormatPrecedents(precedents []FormatPrecedent) string {
	if len(precedents) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString("## Prior Judgments\n")
	b.WriteString("The following are past decisions for structurally similar commands. Treat them\n")
	b.WriteString("as informative context — you may deviate if the current command differs in a\n")
	b.WriteString("material way (different target, different arguments, different working directory).\n")

	for i, p := range precedents {
		b.WriteString(fmt.Sprintf("\n### Precedent %d (%s, %s)\n",
			i+1, matchLabel(p), ageLabel(p.CreatedAt)))
		b.WriteString(fmt.Sprintf("- Command: %s\n", p.Command))
		b.WriteString(fmt.Sprintf("- Decision: %s\n", decisionLabel(p.Decision)))
		if p.Reasoning != "" {
			b.WriteString(fmt.Sprintf("- Reasoning: %s\n", p.Reasoning))
		}
		if p.CWD != "" {
			b.WriteString(fmt.Sprintf("- Working directory: %s\n", p.CWD))
		}
	}

	return b.String()
}

func matchLabel(p FormatPrecedent) string {
	if p.ExactMatch {
		return "exact structural match"
	}
	return fmt.Sprintf("%.0f%% structural similarity", p.Similarity*100)
}

func ageLabel(t time.Time) string {
	age := time.Since(t)
	switch {
	case age < time.Hour:
		return fmt.Sprintf("%d minutes ago", max(int(age.Minutes()), 1))
	case age < 24*time.Hour:
		return fmt.Sprintf("%d hours ago", int(age.Hours()))
	default:
		return fmt.Sprintf("%d days ago", int(age.Hours()/24))
	}
}

func decisionLabel(decision string) string {
	switch decision {
	case "allow":
		return "ALLOW"
	case "deny":
		return "DENY"
	case "user_approved":
		return "USER APPROVED (approved by human operator, not by LLM judgment)"
	default:
		return strings.ToUpper(decision)
	}
}
