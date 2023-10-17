package authorization

import (
	"database/sql/driver"
	"encoding/json"
	"strings"
)

type ScopedSession interface {
  GetScopes() Scopes
}

type Scope string
type Scopes []Scope

func (ss Scopes) Value() (driver.Value, error) {
	scopeVals := []string{}
	for _, s := range ss {
		scopeVals = append(scopeVals, string(s))
	}

	// return , nil
	return strings.Join(scopeVals, ","), nil
}

func (ss *Scopes) Scan(src any) error {
	scopes := make([]Scope, 0)
	for _, s := range strings.Split(src.(string), ",") {
		scopes = append(scopes, Scope(s))
	}

	*ss = Scopes(scopes)

	return nil
}

func (ss *Scopes) ToRaw() []json.RawMessage {
	msgs := make([]json.RawMessage, 0)
	for _, s := range *ss {
		msgs = append(msgs, json.RawMessage(`"` + s + `"`))
	}
	
	return msgs
}


func NewScopes(ss ...string) Scopes {
	scopes := Scopes{}
	for _, s := range scopes {
		scopes = append(scopes, Scope(s))
	}
	return scopes
}

func NewScope(s string) Scope {
	return Scope(s)
}
