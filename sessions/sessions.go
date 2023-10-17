package sessions

import (
	"context"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	authz "github.com/tiagoposse/go-auth/authorization"
)

type SessionField struct {
	Name      string
	JsonField string
	Type      string
}

type ContextSessionKey struct {}

type SessionInfo interface {}

type Session struct {
	jwt.RegisteredClaims

	SessionInfo `json:",inline"`
}

func (Session) Name() string {
	return "go-auth-session"
}

func (s Session) GetScopes() authz.Scopes {
	return authz.Scopes{} 
}

type SessionsController struct {
	secretKey      string
	expirationTime time.Duration
}

func NewSessionsController(key string, expiration time.Duration) *SessionsController {
	return &SessionsController{
		secretKey:      key,
		expirationTime: expiration,
	}
}

func (sc *SessionsController) CreateSessionToken(ctx context.Context, info any) (string, error) {
	expirationTime := time.Now().Add(sc.expirationTime).In(time.FixedZone("GMT", 0))

	s := &Session{
		RegisteredClaims: jwt.RegisteredClaims{
			// In JWT, the expiry time is expressed as unix milliseconds
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
		SessionInfo:    info,
	}

	tokenString, err := jwt.NewWithClaims(jwt.SigningMethodHS256, s).SignedString([]byte(sc.secretKey))

	return tokenString, err
}

func (sc *SessionsController) ValidateSessionToken(ctx context.Context, token string) (authz.ScopedSession, error) {
	session := &Session{}

	tkn, err := jwt.ParseWithClaims(token, session, func(token *jwt.Token) (interface{}, error) {
		return []byte(sc.secretKey), nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return nil, errors.New("invalid signature")
		}

		return nil, errors.New("bad request")
	}

	if !tkn.Valid {
		return nil, errors.New("token invalid")
	}

	return session, nil
}
