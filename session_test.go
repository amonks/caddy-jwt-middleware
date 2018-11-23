package session

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/sessions"
	"github.com/mholt/caddy/caddyhttp/httpserver"
	"github.com/quasoft/memstore"
	"github.com/stretchr/testify/assert"
)

func makeClient() http.Client {
	jar, _ := cookiejar.New(nil)
	return http.Client{
		Jar: jar,
	}
}

func makeHandler(store sessions.Store, next httpserver.HandlerFunc) Handler {
	return Handler{
		Next:        httpserver.HandlerFunc(next),
		BasePath:    "/base",
		SessionPath: "/token",
		SessionName: "s",
		Store:       store,
		JWTSecret:   "secret",
	}
}

func helpTestSessionHandler(
	t *testing.T,
	store *memstore.MemStore,
	method string,
	url string,
	claims *map[string]string,
	h httpserver.HandlerFunc) *http.Response {

	handler := makeHandler(store, h)

	var req *http.Request
	var err error
	req, err = http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal("Could not create HTTP request:", err)
	}

	if claims != nil {
		// Make token with claims
		mapclaims := jwt.MapClaims{}
		for k, v := range *claims {
			mapclaims[k] = v
		}
		token, err := handler.makeToken("secret", mapclaims)
		if err != nil {
			t.Fatal("Failed to make token:", err.Error())
		}

		// Set header
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Result()
}

func TestSessionMiddlewareBehavior(t *testing.T) {
	store := memstore.NewMemStore([]byte("secret"))

	helpTestSessionHandler(t,
		store,
		http.MethodPost,
		"http://localhost/token",
		&map[string]string{"a": "one"},
		func(w http.ResponseWriter, r *http.Request) (int, error) {
			return 0, nil
		},
	)
	helpTestSessionHandler(t,
		store,
		http.MethodPost,
		"http://localhost/token",
		&map[string]string{"b": "two"},
		func(w http.ResponseWriter, r *http.Request) (int, error) {
			return 0, nil
		},
	)
	res := helpTestSessionHandler(t,
		store,
		http.MethodGet,
		"http://localhost/token",
		nil,
		func(w http.ResponseWriter, r *http.Request) (int, error) {
			return 0, nil
		},
	)
	buf := new(bytes.Buffer)
	buf.ReadFrom(res.Body)
	tokenString := buf.String()

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			t.Fatal()
		}

		return []byte("secret"), nil
	})
	assert.NoError(t, err)

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// TODO
		fmt.Println(claims)
	} else {
		t.Fatal()
	}
}

func TestSessionMiddlewareDoesNotCrash(t *testing.T) {
	store := memstore.NewMemStore([]byte("secret"))

	// Ignored path
	middlewareWasCalled := false
	helpTestSessionHandler(t,
		store,
		http.MethodGet,
		"http://localhost/something",
		nil,
		func(w http.ResponseWriter, r *http.Request) (int, error) {
			middlewareWasCalled = true
			return 0, nil
		},
	)
	if !middlewareWasCalled {
		t.Fatal()
	}

	// Proxied path
	middlewareWasCalled = false
	helpTestSessionHandler(t,
		store,
		http.MethodGet,
		"http://localhost/base/something",
		nil,
		func(w http.ResponseWriter, r *http.Request) (int, error) {
			middlewareWasCalled = true
			return 0, nil
		},
	)
	if !middlewareWasCalled {
		t.Fatal()
	}

	// Get token
	helpTestSessionHandler(t,
		store,
		http.MethodGet,
		"http://localhost/token",
		nil,
		func(w http.ResponseWriter, r *http.Request) (int, error) {
			t.Fatal()
			return 0, nil
		},
	)

	// Set session kv
	helpTestSessionHandler(t,
		store,
		http.MethodPost,
		"http://localhost/token",
		nil,
		func(w http.ResponseWriter, r *http.Request) (int, error) {
			t.Fatal()
			return 0, nil
		},
	)
}

func TestTokenCreation(t *testing.T) {
	tokenFromJwtIo := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4ifQ.m0CF2My0uwEjcJXQzHibukFCbYzPHv-dvwuU2BUTwkc"
	secret := "secret"

	// creating a token with the library works as expected
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"role": "admin",
	})
	tokenString, err := token.SignedString([]byte(secret))
	assert.NoError(t, err)
	assert.Equal(t, tokenFromJwtIo, tokenString)
}

func TestTokenValidation(t *testing.T) {
	tokenFromJwtIo := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4ifQ.m0CF2My0uwEjcJXQzHibukFCbYzPHv-dvwuU2BUTwkc"
	secret := "secret"

	// validating a token with the library works as expected
	token, err := jwt.Parse(tokenFromJwtIo, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			t.Fatal()
		}

		return []byte(secret), nil
	})
	assert.NoError(t, err)

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		assert.Equal(t, claims["role"], "admin")
		assert.Equal(t, len(claims), 1)
	} else {
		t.Fatal()
	}
}
