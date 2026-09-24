package target

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"certificate-radar/internal/domain"
)

const defaultHTTPSPort = 443

func Parse(input string) (domain.Target, error) {
	input = strings.TrimSpace(input)

	if input == "" {
		return domain.Target{}, fmt.Errorf("target is empty")
	}

	if strings.Contains(input, "://") {
		return parseURL(input)
	}

	return parseHost(input)
}

func parseURL(input string) (domain.Target, error) {
	u, err := url.Parse(input)
	if err != nil {
		return domain.Target{}, fmt.Errorf("invalid URL: %w", err)
	}

	if u.Host == "" {
		return domain.Target{}, fmt.Errorf("URL has no host")
	}

	if u.Scheme != "https" {
		return domain.Target{}, fmt.Errorf(
			"unsupported scheme %q",
			u.Scheme,
		)
	}

	host := u.Hostname()

	if host == "" {
		return domain.Target{}, fmt.Errorf("URL has no hostname")
	}

	port := defaultHTTPSPort

	if u.Port() != "" {
		port, err = strconv.Atoi(u.Port())
		if err != nil {
			return domain.Target{}, fmt.Errorf(
				"invalid port %q",
				u.Port(),
			)
		}

		if port < 1 || port > 65535 {
			return domain.Target{}, fmt.Errorf(
				"port %d is out of range",
				port,
			)
		}
	}

	return domain.Target{
		Address:    host,
		Port:       port,
		ServerName: host,
		Enabled:    true,
	}, nil
}

func parseHost(input string) (domain.Target, error) {
	host := input
	port := defaultHTTPSPort

	if parsedHost, parsedPort, err := net.SplitHostPort(input); err == nil {
		host = parsedHost

		parsedPortInt, err := strconv.Atoi(parsedPort)
		if err != nil {
			return domain.Target{}, fmt.Errorf(
				"invalid port %q",
				parsedPort,
			)
		}

		if parsedPortInt < 1 || parsedPortInt > 65535 {
			return domain.Target{}, fmt.Errorf(
				"port %d is out of range",
				parsedPortInt,
			)
		}

		port = parsedPortInt
	} else if strings.Count(input, ":") == 1 {
		// Something like "example.com:abc".
		return domain.Target{}, fmt.Errorf(
			"invalid target %q",
			input,
		)
	}

	host = strings.TrimSpace(host)

	if host == "" {
		return domain.Target{}, fmt.Errorf("hostname is empty")
	}

	// Remove IPv6 brackets if they were supplied without a port.
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")

	return domain.Target{
		Address:    host,
		Port:       port,
		ServerName: host,
		Enabled:    true,
	}, nil
}
