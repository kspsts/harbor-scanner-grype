package etc

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
)

// Registry configures how the scanner reaches the registry named in Harbor's scan request.
type Registry struct {
	// HostMap replaces a registry host from Harbor's scan request with a host[:port] the scanner can
	// actually reach (SCANNER_REGISTRY_HOST_MAP).
	HostMap HostMap `env:"SCANNER_REGISTRY_HOST_MAP"`

	// InsecureUseHTTP and InsecureSkipTLSVerify default to true, as in the deployed image. Both are
	// passed to grype as GRYPE_REGISTRY_INSECURE_USE_HTTP and GRYPE_REGISTRY_INSECURE_SKIP_TLS_VERIFY.
	// With certificate checks off, anyone on the network who can answer for a trusted host name
	// receives the registry credentials. To turn verification on, point SSL_CERT_FILE or
	// SSL_CERT_DIR at your CA and set SCANNER_REGISTRY_INSECURE_SKIP_TLS_VERIFY=false.
	InsecureUseHTTP       bool `env:"SCANNER_REGISTRY_INSECURE_USE_HTTP,notEmpty" envDefault:"true"`
	InsecureSkipTLSVerify bool `env:"SCANNER_REGISTRY_INSECURE_SKIP_TLS_VERIFY,notEmpty" envDefault:"true"`

	Username string `env:"SCANNER_REGISTRY_USERNAME"`
	Password string `env:"SCANNER_REGISTRY_PASSWORD"`

	// TrustedHosts lists the hosts the configured account may be sent to
	// (SCANNER_REGISTRY_TRUSTED_HOSTS). Matching is by host name only, never by port or scheme.
	TrustedHosts HostList `env:"SCANNER_REGISTRY_TRUSTED_HOSTS"`
}

// validate rejects a registry account with only a username or only a password: grype needs both or
// neither.
func (r Registry) validate() error {
	switch {
	case r.Username != "" && r.Password == "":
		return errors.New("SCANNER_REGISTRY_USERNAME is set without SCANNER_REGISTRY_PASSWORD")
	case r.Password != "" && r.Username == "":
		return errors.New("SCANNER_REGISTRY_PASSWORD is set without SCANNER_REGISTRY_USERNAME")
	}
	return nil
}

// AccountUnused reports whether SCANNER_REGISTRY_USERNAME is set but SCANNER_REGISTRY_TRUSTED_HOSTS
// is empty, so the configured account would never actually be sent anywhere.
func (r Registry) AccountUnused() bool { return r.Username != "" && len(r.TrustedHosts) == 0 }

// Trusted reports whether the configured account may be sent to host.
func (r Registry) Trusted(host string) bool {
	normalized, err := normalizeHost(host)
	if err != nil {
		return false
	}
	for _, trusted := range r.TrustedHosts {
		if trusted == normalized {
			return true
		}
	}
	return false
}

// String redacts Password so Registry never appears with its secret in a log line or error message.
func (r Registry) String() string {
	type redacted Registry
	cp := redacted(r)
	if cp.Password != "" {
		cp.Password = "***"
	}
	return fmt.Sprintf("%+v", cp)
}

// LogValue redacts Password the same way as String, for slog.
func (r Registry) LogValue() slog.Value {
	type redacted Registry
	cp := redacted(r)
	if cp.Password != "" {
		cp.Password = "***"
	}
	return slog.AnyValue(cp)
}

// HostMap maps a registry host from Harbor's scan request to the host[:port] the scanner connects
// to instead, from "host=target" pairs such as "localhost=nginx:8080,harbor.corp.local=harbor.corp.local:443".
// A key is a bare hostname or IP (see normalizeHost); a target is host or host:port, and a bracketed
// IPv6 target such as "[::1]:5000" is allowed.
type HostMap map[string]string

// UnmarshalText parses SCANNER_REGISTRY_HOST_MAP. Hosts are matched case-insensitively.
func (m *HostMap) UnmarshalText(text []byte) error {
	parsed := HostMap{}
	for _, pair := range strings.Split(string(text), ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		rawHost, target, ok := strings.Cut(pair, "=")
		rawHost, target = strings.TrimSpace(rawHost), strings.TrimSpace(target)
		if !ok || rawHost == "" || target == "" {
			return fmt.Errorf("SCANNER_REGISTRY_HOST_MAP: %q is not host=target", pair)
		}
		host, err := normalizeHost(rawHost)
		if err != nil {
			return fmt.Errorf("SCANNER_REGISTRY_HOST_MAP: %w", err)
		}
		if err := validateTarget(target); err != nil {
			return err
		}
		if _, dup := parsed[host]; dup {
			return fmt.Errorf("SCANNER_REGISTRY_HOST_MAP: duplicate host %q", host)
		}
		parsed[host] = target
	}
	*m = parsed
	return nil
}

// Lookup returns the target configured for host, after normalizing host the same way as a HostMap
// key.
func (m HostMap) Lookup(host string) (string, bool) {
	normalized, err := normalizeHost(host)
	if err != nil {
		return "", false
	}
	target, ok := m[normalized]
	return target, ok
}

// HostList is a comma-separated, case-insensitive list of registry host names, such as
// SCANNER_REGISTRY_TRUSTED_HOSTS. Each entry is normalized the same way as a HostMap key.
type HostList []string

// UnmarshalText parses SCANNER_REGISTRY_TRUSTED_HOSTS.
func (l *HostList) UnmarshalText(text []byte) error {
	var parsed HostList
	for _, raw := range strings.Split(string(text), ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		host, err := normalizeHost(raw)
		if err != nil {
			return fmt.Errorf("SCANNER_REGISTRY_TRUSTED_HOSTS: %w", err)
		}
		parsed = append(parsed, host)
	}
	*l = parsed
	return nil
}

// normalizeHost validates and normalizes a bare hostname or IP: it is lower-cased and one trailing
// dot is trimmed. A bracketed IPv6 literal such as "[::1]" is accepted and stored the way
// url.Hostname() returns it, without the brackets. Anything else containing "/", "@", whitespace or
// ":" is invalid: a port does not belong in a bare host, and an unbracketed IPv6 literal is
// ambiguous with host:port.
func normalizeHost(host string) (string, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return "", errors.New("host must not be empty")
	}
	if strings.HasPrefix(host, "[") {
		inner, rest, ok := strings.Cut(host[1:], "]")
		if !ok || rest != "" || net.ParseIP(inner) == nil {
			return "", fmt.Errorf("%q is not a valid IPv6 literal", host)
		}
		return strings.ToLower(inner), nil
	}
	if strings.ContainsAny(host, "/@: \t\r\n") {
		return "", fmt.Errorf("%q must be a bare hostname or IP", host)
	}
	return strings.TrimSuffix(strings.ToLower(host), "."), nil
}

// validateTarget checks a HostMap value: host or host:port, with a bracketed IPv6 target such as
// "[::1]:5000" allowed. It is stored and used as given, never otherwise normalized. Errors never
// echo a target that contains "@": it might carry credentials.
func validateTarget(target string) error {
	if strings.Contains(target, "@") {
		return errors.New("SCANNER_REGISTRY_HOST_MAP: target contains credentials")
	}
	if strings.Contains(target, "://") || strings.ContainsAny(target, "/= \t\r\n") {
		return fmt.Errorf("SCANNER_REGISTRY_HOST_MAP: target %q must be host or host:port", target)
	}

	host, port, err := net.SplitHostPort(target)
	if err != nil {
		// No ":port" suffix (or not a recognizable host:port pair): the whole target is the host.
		host, port = target, ""
	}
	if host == "" {
		return fmt.Errorf("SCANNER_REGISTRY_HOST_MAP: target %q: host must not be empty", target)
	}
	if port != "" {
		if n, convErr := strconv.Atoi(port); convErr != nil || n < 1 || n > 65535 {
			return fmt.Errorf("SCANNER_REGISTRY_HOST_MAP: target %q: port must be 1-65535", target)
		}
	}
	return nil
}
