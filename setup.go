package session

import (
	"github.com/gorilla/sessions"
	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func init() {
	caddy.RegisterPlugin("session", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

func setup(c *caddy.Controller) error {
	cfg, err := sessionParse(c)
	if err != nil {
		return err
	}

	httpserver.GetConfig(c).AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		return cfg.Handler(next)
	})

	return nil
}

type config struct {
	BasePath    string
	SessionPath string
	SessionName string

	JWTSecret  string
	SessionKey string
}

func (cfg config) Handler(next httpserver.Handler) Handler {
	return Handler{
		Next:  next,
		Store: sessions.NewCookieStore([]byte(cfg.SessionName)),

		BasePath:    cfg.BasePath,
		SessionPath: cfg.SessionPath,
		SessionName: cfg.SessionName,

		JWTSecret: cfg.JWTSecret,
	}
}

func sessionParse(c *caddy.Controller) (config, error) {
	cfg := config{}

	c.Next()
	if c.NextArg() {
		cfg.BasePath = c.Val()
	} else {
		return cfg, c.ArgErr()
	}

	for c.NextBlock() {
		k := c.Val()
		args := c.RemainingArgs()
		if len(args) != 1 {
			return cfg, c.ArgErr()
		}
		v := args[0]

		switch k {
		case "sessionPath":
			cfg.SessionPath = v
		case "sessionName":
			cfg.SessionName = v
		case "jwtSecret":
			cfg.JWTSecret = v
		case "sessionKey":
			cfg.SessionKey = v
		default:
			return cfg, c.ArgErr()
		}
	}

	if cfg.JWTSecret == "" || cfg.SessionKey == "" {
		return cfg, c.ArgErr()
	}
	if cfg.SessionPath == "" {
		cfg.SessionPath = "/token"
	}
	if cfg.SessionName == "" {
		cfg.SessionName = "ss"
	}

	return cfg, nil
}
