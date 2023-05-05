FROM alpine:latest AS core

RUN apk update
RUN apk upgrade
RUN apk add --update bash cmake git go gcc g++ make vips vips-dev

COPY --from=golang:1.20-alpine /usr/local/go/ /usr/local/go/
ENV PATH="/usr/local/go/bin:${PATH}"

WORKDIR /deso/src/core

COPY go.mod .
COPY go.sum .
RUN go mod download

COPY scripts/install-relic.sh .
RUN ./install-relic.sh

COPY desohash desohash
COPY cmd       cmd
COPY lib       lib
COPY test_data test_data
COPY migrate   migrate
COPY main.go   .

# build backend
RUN GOOS=linux go build -mod=mod -a -installsuffix cgo -o bin/core main.go

ENTRYPOINT ["go", "test", "-tags", "relic", "-v", "github.com/deso-protocol/core/lib"]
