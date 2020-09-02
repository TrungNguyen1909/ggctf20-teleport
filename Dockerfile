FROM golang:alpine as build-env

WORKDIR /teleport

RUN apk --no-cache add --virtual .build-deps build-base nasm tzdata

COPY . .

RUN make all

RUN go build -o /bin/server main.go

FROM alpine

WORKDIR /www
COPY --from=build-env /bin/server /bin/server

COPY --from=build-env /teleport/chall chall
COPY --from=build-env /teleport/index.html index.html
COPY --from=build-env /teleport/pwn.js pwn.js
COPY --from=build-env /teleport/service_worker.js service_worker.js
COPY --from=build-env /teleport/leakptr.bin leakptr.bin
COPY --from=build-env /teleport/memread.bin memread.bin
COPY --from=build-env /teleport/portinit.bin portinit.bin
COPY --from=build-env /teleport/sendmsg.bin sendmsg.bin
ENTRYPOINT [ "/bin/server" ]
EXPOSE 8888