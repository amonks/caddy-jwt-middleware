package session

import (
	"testing"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
	"github.com/stretchr/testify/assert"
)

func TestSessionParse(t *testing.T) {
	c := caddy.NewTestController("http", `
	  session / {
	    sessionPath /token
	    sessionName s
	    jwtSecret secret
	    sessionKey key
	  }
	`)
	cfg, err := sessionParse(c)
	assert.NoError(t, err)

	assert.Equal(t, cfg, config{
		BasePath:    "/",
		SessionPath: "/token",
		SessionName: "s",
		JWTSecret:   "secret",
		SessionKey:  "key",
	})
}

func TestSessionSetup(t *testing.T) {
	c := caddy.NewTestController("http", `
	  session / {
	    sessionPath /token
	    sessionName s
	    jwtSecret secret
	    sessionKey key
	  }
	`)
	err := setup(c)
	assert.NoError(t, err)

	mids := httpserver.GetConfig(c).Middleware()
	assert.Equal(t, len(mids), 1)

	handler := mids[0](httpserver.EmptyNext)
	myHandler, ok := handler.(Handler)
	assert.Equal(t, ok, true)

	if !httpserver.SameNext(myHandler.Next, httpserver.EmptyNext) {
		t.Error("'Next' field of handler was not set properly")
	}
}
