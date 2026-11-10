// Bearer token checks: the Accounts public keys by key ID, and the RS256
// token profile the gateway applies (header members, issuer, audience,
// subject, expiry, not-before and roles), with no clock leeway.

package guard

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejson "github.com/go-jose/go-jose/v4/json"
)

// The Fetch token profile (contract section 2): every API accepts the tokens
// Accounts issues for the gateway, so one token works in every mode.
const (
	issuer   = "fetch-accounts"
	audience = "fetch-gateway"
)

const (
	maxTokenBytes  = 4096
	maxRoles       = 64
	maxSubject     = 128
	maxNumericDate = 253402300799 // 9999-12-31T23:59:59Z
)

// Key is a trusted Accounts signing key: its key ID and public key file.
type Key struct {
	Kid           string `json:"kid"`
	PublicKeyFile string `json:"public_key_file"`
}

// identity is a verified token's subject and asserted roles, sorted and
// without repeats.
type identity struct {
	subject string
	roles   []string
}

// parseKey reads an RSA public key of 2048 to 8192 bits from PEM.
func parseKey(data []byte) (*rsa.PublicKey, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" || strings.TrimSpace(string(rest)) != "" {
		return nil, errors.New("a PEM public key is required")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*rsa.PublicKey)
	if !ok || key.N.BitLen() < 2048 || key.N.BitLen() > 8192 {
		return nil, errors.New("an RSA public key of 2048 to 8192 bits is required")
	}
	return key, nil
}

// bearer returns the token of exactly one "Bearer <token>" field, or the
// refusal reason: a repeated field is ambiguous and refused.
func bearer(fields []string) (string, string) {
	if len(fields) == 0 {
		return "", "missing_credential"
	}
	scheme, token, found := strings.Cut(fields[0], " ")
	if len(fields) > 1 || !found || !strings.EqualFold(scheme, "Bearer") || !compact(token) {
		return "", "malformed_credential"
	}
	return token, ""
}

// compact accepts at most maxTokenBytes of three non-empty base64url segments.
func compact(token string) bool {
	segments := strings.Split(token, ".")
	if len(token) > maxTokenBytes || len(segments) != 3 {
		return false
	}
	for _, segment := range segments {
		if segment == "" || strings.Trim(segment, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") != "" {
			return false
		}
	}
	return true
}

// verify checks token at now with the key its header names. Nothing in the
// token is trusted before the signature verifies; the header is read first
// only to refuse it.
func verify(keys map[string]*rsa.PublicKey, token string, now time.Time) (identity, string) {
	header, _, _ := strings.Cut(token, ".")
	kid, reason := checkHeader(header)
	if reason != "" {
		return identity{}, reason
	}
	key := keys[kid]
	if key == nil {
		return identity{}, "unknown_kid"
	}
	signed, err := jose.ParseSignedCompact(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return identity{}, "malformed_credential"
	}
	payload, err := signed.Verify(key)
	if err != nil {
		return identity{}, "invalid_signature"
	}
	return checkClaims(payload, now)
}

// checkHeader allows only "alg" (RS256), "kid" (required) and "typ" (JWT);
// members that carry or locate a key, or add processing rules, refuse the
// token. go-jose's decoder refuses repeated member names.
func checkHeader(segment string) (string, string) {
	data, err := base64.RawURLEncoding.DecodeString(segment)
	var header map[string]any
	if err != nil || josejson.Unmarshal(data, &header) != nil || header == nil {
		return "", "malformed_credential"
	}
	kid, _ := header["kid"].(string)
	if alg, _ := header["alg"].(string); alg != string(jose.RS256) || kid == "" || len(kid) > 64 {
		return "", "unsupported_header"
	}
	for name, value := range header {
		typ, isString := value.(string)
		switch {
		case name == "alg" || name == "kid":
		case name == "typ" && isString && strings.EqualFold(typ, "JWT"):
		default:
			return "", "unsupported_header"
		}
	}
	return kid, ""
}

// checkClaims applies the claim profile to a verified payload: the token is
// valid before "exp" and from "nbf" onwards (RFC 7519), with no leeway.
func checkClaims(payload []byte, now time.Time) (identity, string) {
	var claims map[string]any
	if josejson.Unmarshal(payload, &claims) != nil || claims == nil {
		return identity{}, "invalid_claims"
	}
	subject, _ := claims["sub"].(string)
	expires, hasExpiry := numericDate(claims["exp"])
	notBefore, validStart := time.Time{}, true
	if value, present := claims["nbf"]; present {
		notBefore, validStart = numericDate(value)
	}
	claimed, hasIssuer := claims["iss"].(string)
	roles, validRoles := roleClaim(claims)
	switch {
	case !subjectID(subject) || !hasExpiry || !validStart || !hasIssuer || !validRoles:
		return identity{}, "invalid_claims"
	case claimed != issuer:
		return identity{}, "wrong_issuer"
	}
	if reason := checkAudience(claims["aud"]); reason != "" {
		return identity{}, reason
	}
	if !now.Before(expires) {
		return identity{}, "expired"
	}
	if now.Before(notBefore) {
		return identity{}, "not_yet_valid"
	}
	return identity{subject: subject, roles: roles}, ""
}

// roleClaim reads the optional "roles" array: at most maxRoles identifiers.
func roleClaim(claims map[string]any) ([]string, bool) {
	value, present := claims["roles"]
	if !present {
		return []string{}, true
	}
	items, ok := value.([]any)
	if !ok || len(items) > maxRoles {
		return nil, false
	}
	roles := []string{}
	for _, item := range items {
		role, ok := item.(string)
		if !ok || !roleID(role) {
			return nil, false
		}
		roles = append(roles, role)
	}
	slices.Sort(roles)
	return slices.Compact(roles), true
}

// checkAudience accepts a string, or an array of strings, naming audience.
func checkAudience(value any) string {
	switch claimed := value.(type) {
	case string:
		if claimed != audience {
			return "wrong_audience"
		}
		return ""
	case []any:
		named := false
		for _, item := range claimed {
			name, ok := item.(string)
			if !ok {
				return "invalid_claims"
			}
			named = named || name == audience
		}
		if !named {
			return "wrong_audience"
		}
		return ""
	}
	return "invalid_claims"
}

// numericDate converts a JSON number of seconds since the epoch, possibly
// fractional, to a time; any other JSON type is refused.
func numericDate(value any) (time.Time, bool) {
	seconds, ok := value.(float64)
	if !ok || seconds < 0 || seconds > maxNumericDate {
		return time.Time{}, false
	}
	whole := math.Floor(seconds)
	return time.Unix(int64(whole), int64(math.Round((seconds-whole)*1e9))), true
}

// subjectID accepts 1 to maxSubject printable ASCII characters, no spaces,
// so a subject is safe to log and to pass on in a header.
func subjectID(id string) bool {
	if id == "" || len(id) > maxSubject {
		return false
	}
	for i := 0; i < len(id); i++ {
		if id[i] < 0x21 || id[i] > 0x7e {
			return false
		}
	}
	return true
}

// roleID accepts 1 to 64 letters, digits, '.', '_' and '-', starting with a
// letter or digit.
func roleID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		alphanumeric := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		if !alphanumeric && (i == 0 || c != '.' && c != '_' && c != '-') {
			return false
		}
	}
	return true
}
