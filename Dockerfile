FROM alpine:latest AS core

RUN apk update && apk upgrade
RUN apk add --update bash cmake g++ gcc git make vips vips-dev

COPY --from=golang:1.24-alpine /usr/local/go/ /usr/local/go/
ENV PATH="/usr/local/go/bin:${PATH}"

WORKDIR /deso/src/core

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY bls         bls
COPY cmd         cmd
COPY collections collections
COPY consensus   consensus
COPY desohash    desohash
COPY lib         lib
COPY migrate     migrate
COPY scripts     scripts
COPY test_data   test_data
COPY main.go     .

# build backend
RUN CGO_CFLAGS="-std=gnu11" GOOS=linux go build -mod=mod -a -installsuffix cgo -o bin/core main.go

# create tiny image
FROM alpine:latest

RUN apk add --update vips-dev

COPY --from=core /deso/src/core/bin/core /deso/bin/core

ENTRYPOINT ["/deso/bin/core"]
