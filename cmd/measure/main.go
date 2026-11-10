// Preliminary serial latency of one signed-in read, GET /orders/wallet, under
// up to three conditions measured in rotating order: standalone (the Orders
// service called directly with identity headers set by hand), built-in
// protection (a second stack whose Orders checks the token itself) and behind
// APIWard (the gateway's data address). Every answer must be the same
// successful wallet, else nothing is emitted.

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"time"

	"github.com/Alex-Zechariah-02/fetch/internal/ports"
	"github.com/Alex-Zechariah-02/fetch/internal/services"
)

// warmupRounds are measured but not kept, one per condition order.
const warmupRounds = 3

type latency struct {
	MeanMS float64 `json:"mean_ms"`
	P50MS  float64 `json:"p50_ms"`
	P95MS  float64 `json:"p95_ms"`
}
type measurement struct {
	At               time.Time `json:"at"`
	Label            string    `json:"label"`
	Account          string    `json:"account"`
	Samples          int       `json:"samples"`
	WarmupRounds     int       `json:"warmup_rounds"`
	Concurrency      int       `json:"concurrency"`
	Order            string    `json:"order"`
	Direct           latency   `json:"direct"`
	Builtin          *latency  `json:"builtin,omitempty"`
	Gateway          latency   `json:"gateway"`
	DirectSamplesMS  []float64 `json:"direct_samples_ms"`
	BuiltinSamplesMS []float64 `json:"builtin_samples_ms,omitempty"`
	GatewaySamplesMS []float64 `json:"gateway_samples_ms"`
	Clock            string    `json:"clock"`
	ClockFrequencyHz float64   `json:"clock_frequency_hz"`
}

// condition is one way of reaching Orders. Without a token the caller's
// identity is set by hand in the headers a gateway would set.
type condition struct {
	name, origin, token string
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "measure:", err)
		os.Exit(1)
	}
}

func run(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("measure", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	samples := flags.Int("samples", 30, "measured rounds (1 to 50)")
	account := flags.String("account", "cust-001", "seeded customer, once per quota window")
	builtin := flags.Int("builtin-offset", -1, "port offset of a running demo up -local stack to measure too (-1: none)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *samples < 1 || *samples > 50 || *builtin < -1 || *builtin > 50000 {
		return errors.New("use 1 to 50 samples, a built-in offset of -1 to 50000 and no positional arguments")
	}
	email := ""
	for _, user := range services.Users() {
		if user.ID == *account && slices.Contains(user.Roles, "CUSTOMER") {
			email = user.Email
		}
	}
	if email == "" {
		return errors.New("choose cust-001, cust-002 or cust-003")
	}
	data, err := ports.Offset("127.0.0.2:9480")
	if err != nil {
		return err
	}
	orders, err := ports.Offset("127.0.0.1:9502")
	if err != nil {
		return err
	}
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext, ResponseHeaderTimeout: 2 * time.Second, MaxIdleConns: 3, MaxIdleConnsPerHost: 1, IdleConnTimeout: 10 * time.Second}
	client := &http.Client{Timeout: 5 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	token, err := login(client, "http://"+data, email)
	if err != nil {
		return err
	}
	conditions := []condition{{"direct", "http://" + orders, ""}}
	if *builtin >= 0 {
		// The built-in stack is called directly, as its APIs are, with a
		// token from its own Accounts: its keys differ from the gateway's.
		local, err := login(client, "http://"+at(9505, *builtin), email)
		if err != nil {
			return err
		}
		conditions = append(conditions, condition{"builtin", "http://" + at(9502, *builtin), local})
	}
	conditions = append(conditions, condition{"gateway", "http://" + data, token})
	result, err := measure(client, conditions, *account, *samples)
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(result)
}

// at is the loopback address of base moved by offset.
func at(base, offset int) string {
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), uint16(base+offset)).String()
}

// login signs in at origin's Accounts and returns the token; credentials
// never reach the output.
func login(client *http.Client, origin, email string) (string, error) {
	credentials, _ := json.Marshal(map[string]string{"email": email, "password": "FetchDemo2026!"})
	request, err := http.NewRequest("POST", origin+"/accounts/login", bytes.NewReader(credentials))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("Accounts login at %s did not answer: %w", origin, err)
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 65537))
	response.Body.Close()
	var reply struct {
		Token string `json:"token"`
	}
	if readErr != nil || len(body) > 65536 || response.StatusCode != 200 || json.Unmarshal(body, &reply) != nil || reply.Token == "" {
		return "", errors.New("Accounts login failed; no measurement emitted")
	}
	return reply.Token, nil
}

// measure times one wallet read per condition per round, starting each round
// with the next condition in turn so no condition always goes first.
func measure(client *http.Client, conditions []condition, subject string, samples int) (measurement, error) {
	if samples < 1 || samples > 50 || len(conditions) < 2 {
		return measurement{}, errors.New("sample count is outside 1 to 50 or fewer than two conditions")
	}
	clock, err := newSampleClock()
	if err != nil {
		return measurement{}, err
	}
	times := make([][]float64, len(conditions))
	for round := 0; round < samples+warmupRounds; round++ {
		var balance *int64
		for k := range conditions {
			i := (round + k) % len(conditions)
			elapsed, value, err := wallet(client, conditions[i], subject, clock)
			if err != nil {
				return measurement{}, err
			}
			if balance != nil && *balance != value {
				return measurement{}, errors.New("wallet changed or answers differ; no measurement emitted")
			}
			balance = &value
			if round >= warmupRounds {
				times[i] = append(times[i], elapsed)
			}
		}
	}
	result := measurement{At: time.Now().UTC(), Label: "preliminary", Account: subject, Samples: samples, WarmupRounds: warmupRounds, Concurrency: 1, Clock: clock.name, ClockFrequencyHz: clock.frequency}
	for i, c := range conditions {
		result.Order += c.name + " "
		switch c.name {
		case "direct":
			result.Direct, result.DirectSamplesMS = summarize(times[i]), times[i]
		case "builtin":
			summary := summarize(times[i])
			result.Builtin, result.BuiltinSamplesMS = &summary, times[i]
		case "gateway":
			result.Gateway, result.GatewaySamplesMS = summarize(times[i]), times[i]
		}
	}
	result.Order = "rotating from: " + result.Order[:len(result.Order)-1]
	return result, nil
}

// wallet times one read: from just before the request to the end of the
// body. A protected condition must answer with a request ID.
func wallet(client *http.Client, c condition, subject string, clock sampleClock) (float64, int64, error) {
	request, err := http.NewRequest("GET", c.origin+"/orders/wallet", nil)
	if err != nil {
		return 0, 0, err
	}
	if c.token != "" {
		request.Header.Set("Authorization", "Bearer "+c.token)
	} else {
		request.Header.Set("X-Gateway-Subject", subject)
		request.Header.Set("X-Gateway-Roles", "CUSTOMER")
	}
	started, err := clock.read()
	if err != nil {
		return 0, 0, err
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, 0, fmt.Errorf("wallet request (%s) did not answer: %w", c.name, err)
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 4097))
	closeErr := response.Body.Close()
	ended, clockErr := clock.read()
	if clockErr != nil {
		return 0, 0, clockErr
	}
	if ended <= started {
		return 0, 0, errors.New("measurement clock did not advance; no measurement emitted")
	}
	elapsed := float64(ended-started) * 1000 / clock.frequency
	if readErr != nil || closeErr != nil || len(body) > 4096 || response.StatusCode != 200 || response.Header.Get("X-Service") != "orders" || c.token != "" && response.Header.Get("X-Request-Id") == "" {
		return 0, 0, fmt.Errorf("wallet request (%s) failed or had an invalid service response (status %d); no measurement emitted", c.name, response.StatusCode)
	}
	var reply struct {
		Balance *int64 `json:"balance_sen"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&reply) != nil || reply.Balance == nil {
		return 0, 0, errors.New("wallet answer has an invalid shape; no measurement emitted")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return 0, 0, errors.New("wallet answer has trailing data; no measurement emitted")
	}
	return elapsed, *reply.Balance, nil
}

func summarize(values []float64) latency {
	ordered := slices.Clone(values)
	slices.Sort(ordered)
	sum := 0.0
	for _, value := range values {
		sum += value
	}
	return latency{MeanMS: sum / float64(len(values)), P50MS: ordered[int(math.Ceil(float64(len(values))*.50))-1], P95MS: ordered[int(math.Ceil(float64(len(values))*.95))-1]}
}
