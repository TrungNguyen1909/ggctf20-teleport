Google CTF 2020 Teleport
===

Exploit code for the Chromium exploitation challenge `teleport` at Google CTF 2020

# Challenge files

As the time of writing, you can find the challenge files on [Google CTF website](https://g.co/ctf) or [this original attachment link](https://storage.googleapis.com/gctf-2020-attachments-project/706c6a5526310585dbb974fd5c681dc11f627f1b2d59b094e8f056b1372045fba54f384f020ab122fba3fbdd83667fd2e5323f344b59734ffc0e66768f1b2357)

# Building
- Extract the challenge zip to ./chall
- Docker build

# Running
- Serve HTTPS (because of service worker)

# Hacking notes

`make all` to build the shellcodes

The server code is in [main.go](./main.go). Line 30, 36 are for HTTPS, HTTP serving, respectively

`cert.pem` and `key.pem` are needed for HTTPS hosting.

# Writeup

Checkout [my blog](https://trungnguyen1909.github.io/blog/post/GGCTF20/)
