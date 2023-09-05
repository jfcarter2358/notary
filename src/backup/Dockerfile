FROM golang:1.18.1-alpine

RUN apk update && apk add git

WORKDIR /notary-build
COPY src /notary-build
RUN env GOOS=linux CGO_ENABLED=0 go build -v -o notary

FROM alpine:latest

RUN adduser --disabled-password notary

WORKDIR /home/notary

COPY --from=0 /notary-build/notary ./

RUN apk update \
    && apk add \
    bash

SHELL ["/bin/bash", "-c"]

RUN mkdir /home/notary/data

ADD src/start-notary.sh /home/notary/start-notary.sh
RUN chmod u+x /home/notary/start-notary.sh

COPY src/ui /home/notary

RUN chown -R notary:notary /home/notary

USER notary

ENTRYPOINT ["./start-notary.sh"]
