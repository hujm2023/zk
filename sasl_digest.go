package zk

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const (
	saslDigestURI = "zookeeper/zk-sasl-md5"
	saslQOPAuth   = "auth"
)

var (
	errSASLDigestInvalidCredentials = errors.New("zk: sasl digest credentials must include username and password")
	errSASLDigestInvalidChallenge   = errors.New("zk: invalid sasl digest challenge")
)

type saslDigestConfig struct {
	username string
	password string
}

type saslDigestChallenge struct {
	nonce string
	realm string
	qop   string
}

func newSASLDigestConfig(username, password string) (*saslDigestConfig, error) {
	if username == "" || password == "" {
		return nil, errSASLDigestInvalidCredentials
	}
	return &saslDigestConfig{username: username, password: password}, nil
}

func newSASLDigestResponse(config *saslDigestConfig, challengeToken []byte) ([]byte, error) {
	return newSASLDigestResponseWithCNonce(config, challengeToken, "")
}

func newSASLDigestResponseWithCNonce(config *saslDigestConfig, challengeToken []byte, cnonce string) ([]byte, error) {
	if config == nil || config.username == "" || config.password == "" {
		return nil, errSASLDigestInvalidCredentials
	}

	challenge, err := parseSASLDigestChallenge(challengeToken)
	if err != nil {
		return nil, err
	}
	if cnonce == "" {
		cnonce, err = randomSASLDigestCNonce()
		if err != nil {
			return nil, err
		}
	}

	const nc = "00000001"
	response := saslDigestResponse(config.username, config.password, challenge.realm, challenge.nonce, cnonce, nc, saslQOPAuth)
	fields := []string{
		fmt.Sprintf("username=%q", config.username),
		fmt.Sprintf("realm=%q", challenge.realm),
		fmt.Sprintf("nonce=%q", challenge.nonce),
		fmt.Sprintf("cnonce=%q", cnonce),
		fmt.Sprintf("nc=%s", nc),
		fmt.Sprintf("qop=%s", saslQOPAuth),
		fmt.Sprintf("digest-uri=%q", saslDigestURI),
		fmt.Sprintf("response=%s", response),
	}
	return []byte(strings.Join(fields, ",")), nil
}

func parseSASLDigestChallenge(token []byte) (*saslDigestChallenge, error) {
	values, err := parseSASLDigestDirectives(string(token))
	if err != nil {
		return nil, err
	}

	challenge := &saslDigestChallenge{
		nonce: values["nonce"],
		realm: values["realm"],
		qop:   values["qop"],
	}
	if challenge.nonce == "" || challenge.realm == "" {
		return nil, fmt.Errorf("%w: missing nonce or realm", errSASLDigestInvalidChallenge)
	}
	if challenge.qop == "" {
		challenge.qop = saslQOPAuth
	}
	if !saslDigestQOPSupportsAuth(challenge.qop) {
		return nil, fmt.Errorf("%w: unsupported qop %q", errSASLDigestInvalidChallenge, challenge.qop)
	}
	return challenge, nil
}

func parseSASLDigestDirectives(s string) (map[string]string, error) {
	values := make(map[string]string)
	for _, part := range splitSASLDigestDirectives(s) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		eq := strings.Index(part, "=")
		if eq < 0 {
			return nil, fmt.Errorf("%w: malformed directive %q", errSASLDigestInvalidChallenge, part)
		}
		key, value := part[:eq], part[eq+1:]
		key = strings.ToLower(strings.TrimSpace(key))
		if key == "" {
			return nil, fmt.Errorf("%w: empty directive key", errSASLDigestInvalidChallenge)
		}
		value = strings.TrimSpace(value)
		unquoted, err := unquoteSASLDigestValue(value)
		if err != nil {
			return nil, err
		}
		values[key] = unquoted
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("%w: empty challenge", errSASLDigestInvalidChallenge)
	}
	return values, nil
}

func splitSASLDigestDirectives(s string) []string {
	var parts []string
	start := 0
	inQuote := false
	escaped := false
	for i, r := range s {
		switch {
		case escaped:
			escaped = false
		case r == '\\' && inQuote:
			escaped = true
		case r == '"':
			inQuote = !inQuote
		case r == ',' && !inQuote:
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

func unquoteSASLDigestValue(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	if value[0] != '"' {
		if strings.Contains(value, "\"") {
			return "", fmt.Errorf("%w: malformed quoted value", errSASLDigestInvalidChallenge)
		}
		return value, nil
	}
	if len(value) < 2 || value[len(value)-1] != '"' {
		return "", fmt.Errorf("%w: malformed quoted value", errSASLDigestInvalidChallenge)
	}
	var b strings.Builder
	escaped := false
	for _, r := range value[1 : len(value)-1] {
		if escaped {
			b.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if r == '"' {
			return "", fmt.Errorf("%w: malformed quoted value", errSASLDigestInvalidChallenge)
		}
		b.WriteRune(r)
	}
	if escaped {
		return "", fmt.Errorf("%w: dangling escape", errSASLDigestInvalidChallenge)
	}
	return b.String(), nil
}

func saslDigestQOPSupportsAuth(qop string) bool {
	for _, item := range strings.Split(qop, ",") {
		if strings.TrimSpace(item) == saslQOPAuth {
			return true
		}
	}
	return false
}

func randomSASLDigestCNonce() (string, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(nonce[:]), nil
}

func saslDigestResponse(username, password, realm, nonce, cnonce, nc, qop string) string {
	h := md5.New()
	h.Write([]byte(username))
	h.Write([]byte(":"))
	h.Write([]byte(realm))
	h.Write([]byte(":"))
	h.Write([]byte(password))
	a1Prefix := h.Sum(nil)

	h.Reset()
	h.Write(a1Prefix)
	h.Write([]byte(":"))
	h.Write([]byte(nonce))
	h.Write([]byte(":"))
	h.Write([]byte(cnonce))
	a1 := hex.EncodeToString(h.Sum(nil))

	a2 := saslDigestMD5Hex("AUTHENTICATE:" + saslDigestURI)
	return saslDigestMD5Hex(strings.Join([]string{a1, nonce, nc, cnonce, qop, a2}, ":"))
}

func saslDigestMD5Hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}
