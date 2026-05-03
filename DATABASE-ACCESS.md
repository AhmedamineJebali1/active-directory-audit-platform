# Database Access — Quick Reference

## How to open the databases

Double-click **`open-dbs.bat`** in this folder.
That's it. PostgreSQL and Neo4j will be accessible from your machine.

---

## Connection details

| Database   | Tool to use                        | Address              | User     | Password  |
|------------|------------------------------------|----------------------|----------|-----------|
| PostgreSQL | pgAdmin / DBeaver / TablePlus / terminal | `localhost:5432` | `adaudit`  | `changeme` |
| Neo4j      | Browser → http://localhost:7474    | `localhost:7687`     | `neo4j`  | `changeme` |

---

## Terminal access (no install needed)

```bash
# PostgreSQL
docker compose exec postgres psql -U adaudit -d adaudit

# Neo4j
docker compose exec neo4j cypher-shell -u neo4j -p changeme
```

---

## Security — what is and isn't exposed

By default (normal `docker compose up -d`), **the databases have zero open ports**.
They only talk to the backend container, inside a private Docker network.
Nothing outside Docker can reach them.

When you run `open-dbs.bat`, ports are opened — but **bound to 127.0.0.1 only**.
This means:

- Your own machine → can connect (pgAdmin, browser, terminal)
- Another machine on the same WiFi → cannot connect
- The internet → cannot connect

The moment you restart normally with `docker compose up -d`, the ports close again automatically.

---

## One-line explanation for anyone who asks

> "The databases are locked inside Docker and not reachable from outside.
> When I need to inspect them I run a script that opens a local-only port
> on my machine — visible only to me, closed again on next restart."
