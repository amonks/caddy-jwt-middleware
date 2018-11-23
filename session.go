package session

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/sessions"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

// Handler is a middleware handler
type Handler struct {
	Next  httpserver.Handler
	Store sessions.Store

	BasePath    string
	SessionPath string
	SessionName string

	JWTSecret string
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	path := httpserver.Path(r.URL.Path)
	if path.Matches(h.SessionPath) {
		switch r.Method {
		case http.MethodPost:
			return h.updateSession(w, r, true)
		case http.MethodPatch:
			return h.updateSession(w, r, false)
		case http.MethodGet:
			return h.getToken(w, r)
		default:
			return 400, errors.New("bad method for session req")
		}
	} else if path.Matches(h.BasePath) {
		return h.proxyWithJWT(w, r)
	}
	return h.Next.ServeHTTP(w, r)

}

func (h Handler) proxyWithJWT(w http.ResponseWriter, r *http.Request) (int, error) {
	if existingHeader := r.Header.Get("Authorization"); existingHeader != "" {
		return h.Next.ServeHTTP(w, r)
	}

	claims := h.getSessionClaims(w, r)
	tokenString, err := h.makeToken(h.JWTSecret, claims)
	if err != nil {
		return 400, err
	}

	// Set header
	r.Header.Set("Authorization", fmt.Sprintf("Bearer: %s", tokenString))
	return h.Next.ServeHTTP(w, r)
}

func (h Handler) getToken(w http.ResponseWriter, r *http.Request) (int, error) {
	claims := h.getSessionClaims(w, r)
	tokenString, err := h.makeToken(h.JWTSecret, claims)
	if err != nil {
		return 400, err
	}

	w.Write([]byte(tokenString))
	return 0, nil
}

type setSessionRequest map[string]string

func (h Handler) updateSession(w http.ResponseWriter, r *http.Request, clearFirst bool) (int, error) {
	// Get token
	header := r.Header.Get("Authorization")
	if header == "" {
		return 400, errors.New("no update supplied")
	}
	tokenString := strings.Replace(header, "Bearer ", "", 1)

	// Parse token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("Unexpected signing method")
		}
		return []byte(h.JWTSecret), nil
	})
	if err != nil {
		return 502, err
	}

	// Get session
	session, _ := h.Store.Get(r, h.SessionName)

	// Clear session
	if clearFirst {
		for k := range session.Values {
			delete(session.Values, k)
		}
	}

	// Update session
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		for k, v := range claims {
			session.Values[k] = v
		}
	}
	session.Save(r, w)

	w.Write([]byte("ok"))
	return 200, nil
}

func (h Handler) getSessionClaims(w http.ResponseWriter, r *http.Request) jwt.MapClaims {
	session, _ := h.Store.Get(r, h.SessionName)
	values := session.Values
	claims := jwt.MapClaims{}
	for k, v := range values {
		claims[k.(string)] = v
	}
	return claims
}

func (h Handler) makeToken(secret string, claims jwt.MapClaims) (string, error) {
	claims["iss"] = "jwt-proxy"
	now := time.Now().Unix()
	claims["iat"] = now
	claims["exp"] = now + 60

	// Sign JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}
