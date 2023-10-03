package main

import (
	"fmt"
	"strings"
)

type config struct {
	// Issuer is the JWT issuer
	Issuer string
	// Aud is the expected aud(ience) value for valid OIDC tokens
	Aud string

	//TODO: Add source_identity and other fields as part of the authz implementation
}

func configFromArgs(args []string) (*config, error) {
	c := &config{}

	for _, arg := range args {
		parts := strings.SplitN(arg, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("malformed arg: %v", arg)
		}

		switch parts[0] {
		case "issuer":
			c.Issuer = parts[1]
		case "aud":
			c.Aud = parts[1]
		default:
			return nil, fmt.Errorf("unknown option: %v", parts[0])
		}
	}

	return c, nil
}
