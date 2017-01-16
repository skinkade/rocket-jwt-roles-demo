# Rocket JSON Web Token & Access Roles Demo

See [this blogpost](https://skinkade.github.io/rocket-jwt-roles-demo).

To get this working, you need PostgreSQL set up, and run:

```bash
echo DATABASE_URL=postgres://user:pass@host/site > .env
head -c16 /dev/urandom > secret.key
```
