package sessions

import (
	"context"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type Scopes []Scope
type Scope string

type SessionField struct {
	Name      string
	JsonField string
	Type      string
}

type Session struct {
	jwt.RegisteredClaims

	Scopes Scopes `json:"scopes"`
	any
}

func (s *Session) GetScopes() Scopes {
	return s.Scopes
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

func (sc *SessionsController) CreateSessionToken(ctx context.Context, scopes Scopes, item any) (string, error) {
	expirationTime := time.Now().Add(sc.expirationTime).In(time.FixedZone("GMT", 0))

	s := &Session{
		RegisteredClaims: jwt.RegisteredClaims{
			// In JWT, the expiry time is expressed as unix milliseconds
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
		Scopes: scopes,
		any:    item,
	}

	tokenString, err := jwt.NewWithClaims(jwt.SigningMethodHS256, s).SignedString([]byte(sc.secretKey))

	return tokenString, err
}

func (sc *SessionsController) ValidateSessionToken(ctx context.Context, token string) (*Session, error) {
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
