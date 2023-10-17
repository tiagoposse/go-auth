# go-auth

Set of utilities to handle authorization in go. Included are:
- A session controller, to create and validate sessions using jwt tokens
- An authorization controller, that validates scopes against a set map

## Example

```
import (
  "context"
  "log"

  sessions "github.com/tiagoposse/go-auth"
)

type SessionItems struct {
  Email string
}

func main() {
  ctx := context.TODO()
  ctrl := sessions.NewSessionsController("RANDOMKEY", 8*time.Hour))
  token, err := ctrl.CreateSessionToken(ctx, sessions.Scopes{"authorizeUserEdit"}, SessionItems{Email: "test@example.com"})
  if err != nil {
    log.Fatal(err)
  }
  
  sessObject, err := ctrl.ValidateSessionToken(ctx, token)
  if err != nil {
    log.Fatal(err)
  }
}
```
