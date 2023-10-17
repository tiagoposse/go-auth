# go-jwt-session

Provides an implementation of a session controller that creates a JWT token to represent a session.

## Example

```
import (
  "context"
  "log"

  sessions "github.com/tiagoposse/go-jwt-session"
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
