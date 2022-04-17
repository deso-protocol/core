FROM alpine:latest AS core

RUN apk update && apk upgrade
RUN apk add --update go gcc g++ vips vips-dev

WORKDIR /deso/src/core

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY desohash desohash
COPY cmd       cmd
COPY lib       lib
COPY migrate   migrate
COPY test_data test_data
COPY main.go   .

# build backend
RUN GOOS=linux go build -mod=mod -a -installsuffix cgo -o bin/core main.go

# create tiny image
FROM alpine:edge

RUN apk add --update vips-dev

COPY --from=core /deso/src/core/bin/core /deso/bin/core

ENTRYPOINT ["/deso/bin/core"]
