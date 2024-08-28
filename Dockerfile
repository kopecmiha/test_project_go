FROM golang:1.22-alpine AS build

ENV GOPATH="/go/src"

WORKDIR /go/src/application

COPY . .

RUN GOOS=linux go build -ldflags="-s -w" -o main .

FROM alpine

RUN apk add --no-cache tzdata
ENV TZ=Europe/Moscow

WORKDIR /go/app

COPY --from=build /go/src/application/main .

EXPOSE 8000

ENTRYPOINT  ["./main"]