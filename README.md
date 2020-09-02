Google CTF 2020 Teleport
===

Exploit code for the Chromium exploitation challenge `teleport` at Google CTF 2020

# Building
- Extract the challenge zip to ./chall
- Docker build

# Hacking notes

`make all` to build the shellcodes

The server code is in [main.go](./main.go). Line 30, 36 are for HTTPS, HTTP serving, respectively

`cert.pem` and `key.pem` are needed for HTTPS hosting.
