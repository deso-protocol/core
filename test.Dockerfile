FROM alpine:latest AS core

RUN apk update
RUN apk upgrade
RUN apk add --update go gcc g++ vips vips-dev

WORKDIR /deso/src/core

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY desohash desohash
COPY cmd       cmd
COPY lib       lib
COPY test_data test_data
COPY migrate   migrate
COPY main.go   .

# build backend
RUN GOOS=linux go build -mod=mod -a -installsuffix cgo -o bin/core main.go

ENTRYPOINT ["go", "test", "-v", "github.com/deso-protocol/core/lib"]
