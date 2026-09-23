# Sulis Example Web App

A runnable example that wires the sulis authentication library end to end
against a local SQLite database. It is living documentation: every page
names, in its footer, which library calls it just made.

## Run

    cd examples/webapp
    go run .

The server listens on `:8443` over HTTPS with a self-signed certificate
generated at startup. Your browser will warn about the certificate; accept
it to continue.

## Flags

- `-addr` — address to listen on (default `:8443`)
- `-db` — path to the SQLite database file (default `webapp.db`)
- `-tls` — serve over TLS with a self-signed certificate (default `true`)

## Local development

Safari refuses `Secure` cookies over plain HTTP, even on localhost, so this
app defaults to TLS. Run with `-tls=false` only if your browser accepts
insecure cookies on localhost (Chrome and Firefox do).
