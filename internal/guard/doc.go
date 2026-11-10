// Package guard is Fetch's built-in protection: the five request controls an
// API process applies to itself, in front of its handler, when it runs
// without a gateway. In order: a verified RS256 token (issuer, audience,
// expiry), the API's own operation table of roles, a blocked-accounts list, a
// weighted sliding-window rate per operation, the request body's size, media
// type, strict JSON and schema, and a security log record synced to disk
// before the handler runs. Each API owns its table, keys, counters, list and
// log; nothing is shared between API processes.
package guard
