// Refusal answers in the services' error form, {"error", "message"}, with
// the gateway's codes and the same security headers as every service answer.
// Each body is encoded once at start, so a refusal costs one write.

package guard

import (
	"encoding/json"
	"net/http"
)

// messages explain each refusal code to the person using the shop.
var messages = map[string]string{
	"bad_request":            "The request is not valid for this operation.",
	"not_found":              "That resource was not found.",
	"method_not_allowed":     "This method is not allowed here.",
	"unauthenticated":        "A valid signed-in account is required.",
	"forbidden":              "Your account may not use this operation.",
	"account_blocked":        "This account is blocked.",
	"rate_limited":           "Too many requests. Wait a moment and try again.",
	"payload_too_large":      "The request body is too large.",
	"unsupported_media_type": "Send a JSON request body.",
	"gateway_unavailable":    "The service cannot take this request right now. Try again later.",
	"overloaded":             "The service is busy. Try again in a moment.",
}

// bodies holds each code's encoded answer, newline included.
var bodies = encodeBodies()

func encodeBodies() map[string][]byte {
	encoded := make(map[string][]byte, len(messages))
	for code, message := range messages {
		data, err := json.Marshal(map[string]string{"error": code, "message": message})
		if err != nil {
			panic(err) // two strings always encode
		}
		encoded[code] = append(data, '\n')
	}
	return encoded
}

// answer writes the refusal of code. A 503 tells the client when to try
// again (RFC 9110 section 10.2.3), unless the caller set a longer wait.
func answer(w http.ResponseWriter, status int, code string) {
	header := w.Header()
	header.Set("Content-Type", "application/json")
	header.Set("Cache-Control", "no-store")
	header.Set("X-Content-Type-Options", "nosniff")
	if status == http.StatusServiceUnavailable && header.Get("Retry-After") == "" {
		header.Set("Retry-After", "1")
	}
	w.WriteHeader(status)
	w.Write(bodies[code])
}
