package feedback

import (
	"testing"
)

func TestGenerateSecret_Length(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret() error = %v", err)
	}
	if len(secret) != 32 {
		t.Errorf("GenerateSecret() len = %d, want 32", len(secret))
	}
}

func TestGenerateToken_Consistent(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret() error = %v", err)
	}

	token1 := GenerateToken(secret, "trace-1", "tool-1", "yellow")
	token2 := GenerateToken(secret, "trace-1", "tool-1", "yellow")

	if token1 != token2 {
		t.Errorf("GenerateToken() not consistent: %q != %q", token1, token2)
	}
}

func TestGenerateToken_DifferentInputs(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret() error = %v", err)
	}

	token1 := GenerateToken(secret, "trace-1", "tool-1", "yellow")
	token2 := GenerateToken(secret, "trace-2", "tool-1", "yellow")

	if token1 == token2 {
		t.Errorf("GenerateToken() produced identical tokens for different traceIDs")
	}
}

func TestVerifyToken_Valid(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret() error = %v", err)
	}

	token := GenerateToken(secret, "trace-1", "tool-1", "green")
	if !VerifyToken(secret, token, "trace-1", "tool-1", "green") {
		t.Error("VerifyToken() returned false for valid token")
	}
}

func TestVerifyToken_WrongTraceID(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret() error = %v", err)
	}

	token := GenerateToken(secret, "trace-1", "tool-1", "green")
	if VerifyToken(secret, token, "trace-WRONG", "tool-1", "green") {
		t.Error("VerifyToken() returned true for wrong traceID")
	}
}

func TestVerifyToken_WrongToolUseID(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret() error = %v", err)
	}

	token := GenerateToken(secret, "trace-1", "tool-1", "green")
	if VerifyToken(secret, token, "trace-1", "tool-WRONG", "green") {
		t.Error("VerifyToken() returned true for wrong toolUseID")
	}
}

func TestVerifyToken_WrongDecision(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret() error = %v", err)
	}

	token := GenerateToken(secret, "trace-1", "tool-1", "green")
	if VerifyToken(secret, token, "trace-1", "tool-1", "red") {
		t.Error("VerifyToken() returned true for wrong decision")
	}
}

func TestVerifyToken_TamperedToken(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret() error = %v", err)
	}

	token := GenerateToken(secret, "trace-1", "tool-1", "yellow")
	// Flip the last character (hex digit) to tamper with the token.
	tampered := []byte(token)
	if tampered[len(tampered)-1] == 'a' {
		tampered[len(tampered)-1] = 'b'
	} else {
		tampered[len(tampered)-1] = 'a'
	}

	if VerifyToken(secret, string(tampered), "trace-1", "tool-1", "yellow") {
		t.Error("VerifyToken() returned true for tampered token")
	}
}

func TestVerifyToken_EmptyToken(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret() error = %v", err)
	}

	if VerifyToken(secret, "", "trace-1", "tool-1", "yellow") {
		t.Error("VerifyToken() returned true for empty token")
	}
}

func TestVerifyToken_GarbageToken(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret() error = %v", err)
	}

	if VerifyToken(secret, "not-valid-hex!!!", "trace-1", "tool-1", "yellow") {
		t.Error("VerifyToken() returned true for garbage token")
	}
}

// TestGenerateToken_NullByteSeparation verifies that null-byte separators
// prevent domain collision between adjacent field concatenations.
// Without separators, trace="ab"+id="cd" and trace="abc"+id="d" would
// produce the same HMAC input ("abcd"). With separators they are distinct.
func TestGenerateToken_NullByteSeparation(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret() error = %v", err)
	}

	token1 := GenerateToken(secret, "ab", "cd", "green")
	token2 := GenerateToken(secret, "abc", "d", "green")

	if token1 == token2 {
		t.Errorf("NullByteSeparation: tokens collide for (ab,cd) vs (abc,d): %q", token1)
	}
}
