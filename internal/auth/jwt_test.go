package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGenerateTokens(t *testing.T) {
	access, refresh, err := GenerateJwt("testuser", "admin", "127.0.0.1", "TestAgent")
	assert.NoError(t, err)
	assert.NotEmpty(t, access)
	assert.NotEmpty(t, refresh)
}

func TestParseJWT(t *testing.T) {
	ctx := t.Context()
	access, _, err := GenerateJwt("testuser1", "admin", "127.0.0.1", "TestAgent")
	assert.NoError(t, err)

	claims, err := ValidateJwt(ctx, access, "127.0.0.1", "TestAgent")
	assert.NoError(t, err)
	assert.Equal(t, "testuser1", claims.Username)
	assert.Equal(t, "admin", claims.Role)
}

func TestParseJWT_InvalidToken(t *testing.T) {
	ctx := t.Context()
	_, err := ValidateJwt(ctx, "invalid.token.string", "127.0.0.1", "TestAgent")
	assert.Error(t, err)
}

func TestParseJWT_AntiHijacking(t *testing.T) {
	ctx := t.Context()

	access, _, err := GenerateJwt("testuser2", "admin", "127.0.0.1", "TestAgent")
	assert.NoError(t, err)

	_, err = ValidateJwt(ctx, access, "127.0.0.2", "TestAgent") // Different IP
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token IP mismatch")

	_, err = ValidateJwt(ctx, access, "127.0.0.1", "FakeAgent") // Different User-Agent
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token user-agent mismatch")
}

func TestBlacklistToken(t *testing.T) {
	ctx := t.Context()

	// Generate a test token
	access, _, err := GenerateJwt("testuser3", "admin", "127.0.0.1", "TestAgent")
	assert.NoError(t, err)

	// Parse to get the JTI (JWT ID)
	claims, err := ValidateJwt(ctx, access, "127.0.0.1", "TestAgent")
	assert.NoError(t, err)

	// Blacklist the token
	err = BlacklistToken(ctx, claims.ID, 10*time.Minute)
	assert.NoError(t, err)

	// Token should now be blacklisted
	blacklisted, err := IsBlacklisted(ctx, claims.ID)
	assert.NoError(t, err)
	assert.True(t, blacklisted)
}

func TestBlacklistedTokenCannotBeUsed(t *testing.T) {
	ctx := t.Context()

	// Generate a test token
	access, _, err := GenerateJwt("testuser4", "admin", "127.0.0.1", "TestAgent")
	assert.NoError(t, err)

	// Parse to get the JTI (JWT ID)
	claims, err := ValidateJwt(ctx, access, "127.0.0.1", "TestAgent")
	assert.NoError(t, err)

	// Blacklist the token
	err = BlacklistToken(ctx, claims.ID, 10*time.Minute)
	assert.NoError(t, err)

	// Attempt to use the blacklisted token
	_, err = ValidateJwt(ctx, access, "127.0.0.1", "TestAgent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token has been blacklisted")
}

func TestExpiredBlacklistIsRemoved(t *testing.T) {
	ctx := t.Context()

	// Generate a test token
	access, _, err := GenerateJwt("testuser5", "admin", "127.0.0.1", "TestAgent")
	assert.NoError(t, err)

	// Parse to get the JTI (JWT ID)
	claims, err := ValidateJwt(ctx, access, "127.0.0.1", "TestAgent")
	assert.NoError(t, err)

	// Blacklist the token for 1 second
	err = BlacklistToken(ctx, claims.ID, 1*time.Second)
	assert.NoError(t, err)

	// Wait for the blacklist to expire
	time.Sleep(2 * time.Second)

	// Token should not be in the blacklist anymore
	blacklisted, err := IsBlacklisted(ctx, claims.ID)
	assert.NoError(t, err)
	assert.False(t, blacklisted)
}
