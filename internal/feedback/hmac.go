// Package feedback provides HMAC-based token generation and verification
// for the feedback endpoint. Tokens bind a feedback submission to a specific
// classification decision, preventing replay and forgery.
package feedback

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
)

// GenerateSecret returns a 256-bit (32-byte) cryptographically random secret.
// The secret is generated at server startup and held in memory only; it
// rotates on every restart, which is acceptable because pending feedback is
// best-effort.
func GenerateSecret() ([]byte, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	return secret, nil
}

// GenerateToken creates an HMAC-SHA256 feedback token bound to the given
// traceID, toolUseID, and decision. Null-byte separators between fields
// prevent domain collision (e.g., trace="ab"+id="cd" vs trace="abc"+id="d").
// decision is the rule-engine tier (red/yellow/green), not the action taken.
// The token is returned as a lowercase hex string for JSON transport.
func GenerateToken(secret []byte, traceID, toolUseID, decision string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(traceID))
	mac.Write([]byte{0})
	mac.Write([]byte(toolUseID))
	mac.Write([]byte{0})
	mac.Write([]byte(decision))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyToken checks a feedback token using constant-time comparison to
// prevent timing oracles. It returns true only if the token matches the
// expected HMAC for the given inputs.
func VerifyToken(secret []byte, token, traceID, toolUseID, decision string) bool {
	tokenBytes, err := hex.DecodeString(token)
	if err != nil {
		return false
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(traceID))
	mac.Write([]byte{0})
	mac.Write([]byte(toolUseID))
	mac.Write([]byte{0})
	mac.Write([]byte(decision))
	expected := mac.Sum(nil)

	return hmac.Equal(tokenBytes, expected)
}
