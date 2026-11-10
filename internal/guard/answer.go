// Refusal answers in the services' error form, {"error", "message"}, with
// the gateway's codes and the same security headers as every service answer.

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
}

func answer(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": code, "message": messages[code]})
}
