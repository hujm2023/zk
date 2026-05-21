package zk

import (
	"errors"
	"strings"
	"testing"
)

func TestSASLDigestResponse(t *testing.T) {
	config, err := newSASLDigestConfig("super", "admin")
	if err != nil {
		t.Fatalf("newSASLDigestConfig returned error: %v", err)
	}

	challenge := []byte(`nonce="qWkHmx+rW9vYQNysvUOCA3gWLks3u9cL5rc9JJFi",realm="zk-sasl-md5",qop="auth"`)
	token, err := newSASLDigestResponseWithCNonce(config, challenge, "140741146289")
	if err != nil {
		t.Fatalf("newSASLDigestResponseWithCNonce returned error: %v", err)
	}

	got := string(token)
	expectedParts := []string{
		`username="super"`,
		`realm="zk-sasl-md5"`,
		`nonce="qWkHmx+rW9vYQNysvUOCA3gWLks3u9cL5rc9JJFi"`,
		`cnonce="140741146289"`,
		`nc=00000001`,
		`qop=auth`,
		`digest-uri="zookeeper/zk-sasl-md5"`,
		`response=08125d12f8b89ca7dd8b5028b5cd7c3b`,
	}
	for _, part := range expectedParts {
		if !strings.Contains(got, part) {
			t.Fatalf("response token %q does not contain %q", got, part)
		}
	}
}

func TestSASLDigestChallengeQuotedComma(t *testing.T) {
	challenge, err := parseSASLDigestChallenge([]byte(`realm="zk,sasl,md5",nonce="abc",qop="auth,auth-int"`))
	if err != nil {
		t.Fatalf("parseSASLDigestChallenge returned error: %v", err)
	}
	if challenge.realm != "zk,sasl,md5" {
		t.Fatalf("realm = %q, want quoted comma value", challenge.realm)
	}
	if challenge.nonce != "abc" {
		t.Fatalf("nonce = %q, want abc", challenge.nonce)
	}
}

func TestSASLDigestInvalidCredentials(t *testing.T) {
	cases := []struct {
		name     string
		username string
		password string
	}{
		{name: "missing username", password: "secret"},
		{name: "missing password", username: "user"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newSASLDigestConfig(tc.username, tc.password)
			if !errors.Is(err, errSASLDigestInvalidCredentials) {
				t.Fatalf("error = %v, want errSASLDigestInvalidCredentials", err)
			}
		})
	}
}

func TestSASLDigestInvalidChallenge(t *testing.T) {
	config, err := newSASLDigestConfig("user", "secret")
	if err != nil {
		t.Fatalf("newSASLDigestConfig returned error: %v", err)
	}

	cases := []struct {
		name      string
		challenge string
	}{
		{name: "empty", challenge: ""},
		{name: "missing nonce", challenge: `realm="zk-sasl-md5",qop="auth"`},
		{name: "missing realm", challenge: `nonce="abc",qop="auth"`},
		{name: "malformed directive", challenge: `nonce"abc",realm="zk-sasl-md5"`},
		{name: "unterminated quote", challenge: `nonce="abc,realm="zk-sasl-md5"`},
		{name: "unsupported qop", challenge: `nonce="abc",realm="zk-sasl-md5",qop="auth-conf"`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newSASLDigestResponseWithCNonce(config, []byte(tc.challenge), "fixed")
			if !errors.Is(err, errSASLDigestInvalidChallenge) {
				t.Fatalf("error = %v, want errSASLDigestInvalidChallenge", err)
			}
		})
	}
}
