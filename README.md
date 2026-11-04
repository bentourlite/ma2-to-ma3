# MA2 to MA3 Fixture Converter

Converts grandMA2 fixture type XML exports into a grandMA3 fixture type (plus a GDTF fallback), behind a login. Admins create single-use invite links from `/admin`.

## Run

```
npm install
ADMIN_EMAIL=you@example.com ADMIN_PASSWORD='a long password' npm start
```

Environment variables:

- `ADMIN_EMAIL`, `ADMIN_PASSWORD`, `ADMIN_NAME`: create the first admin when the database is empty.
- `DATA_DIR`: where the SQLite database lives (default `./data`). On Railway, mount a volume at `/data` and set `DATA_DIR=/data`.
- `PORT`: set by Railway.

Requires Node 22.13 or newer (uses the built-in `node:sqlite`).
