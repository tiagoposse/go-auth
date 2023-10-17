package authorization

import (
	"context"
	"errors"
)

type ScopeValidator struct {
  scopes map[string]Scopes
}

func NewScopeValidator(operationScopes map[string]Scopes) *ScopeValidator {
  return &ScopeValidator{
    scopes: operationScopes,
  }
}

func (h *ScopeValidator) ValidateScopes(ctx context.Context, operationName string, reqScopes Scopes) error {
  if opScopes, ok := h.scopes[operationName]; ok {
    found := false
    for _, reqScope := range reqScopes {
      for _, opScope := range opScopes {
        if reqScope == opScope {
          found = true
          break
        }
      }
      if found {
        break
      }
    }

    if !found {
      return errors.New("no scopes match")
    }
  }

  return nil
}
