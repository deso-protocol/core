module github.com/bitclout/core

go 1.14

replace github.com/golang/glog => ./third_party/github.com/golang/glog

replace github.com/laser/go-merkle-tree => ./third_party/github.com/laser/go-merkle-tree

replace github.com/sasha-s/go-deadlock => ./third_party/github.com/sasha-s/go-deadlock

require (
	cloud.google.com/go/storage v1.14.0
	github.com/DataDog/datadog-go v4.5.0+incompatible
	github.com/Microsoft/go-winio v0.4.16 // indirect
	github.com/btcsuite/btcd v0.21.0-beta
	github.com/btcsuite/btcutil v1.0.2
	github.com/btcsuite/go-socks v0.0.0-20170105172521-4720035b7bfd
	github.com/bxcodec/faker v2.0.1+incompatible
	github.com/davecgh/go-spew v1.1.1
	github.com/decred/dcrd/lru v1.0.0
	github.com/dgraph-io/badger/v3 v3.2011.1
	github.com/dgrijalva/jwt-go/v4 v4.0.0-preview1
	github.com/ethereum/go-ethereum v1.9.19
	github.com/fatih/structs v1.1.0
	github.com/gernest/mention v2.0.0+incompatible
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/snappy v0.0.2 // indirect
	github.com/google/uuid v1.2.0 // indirect
	github.com/gorilla/mux v1.7.4
	github.com/h2non/bimg v1.1.5
	github.com/kevinburke/go-types v0.0.0-20201208005256-aee49f568a20 // indirect
	github.com/kevinburke/go.uuid v1.2.0 // indirect
	github.com/kevinburke/rest v0.0.0-20210222204520-f7a2e216372f // indirect
	github.com/kevinburke/twilio-go v0.0.0-20210106192831-51cae4e2b9d8
	github.com/klauspost/compress v1.11.7 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/laser/go-merkle-tree v0.0.0-20180821204614-16c2f6ea4444
	github.com/montanaflynn/stats v0.0.0-20171201202039-1bf9dbcd8cbe
	github.com/nyaruka/phonenumbers v1.0.66
	github.com/onsi/ginkgo v1.15.0 // indirect
	github.com/onsi/gomega v1.10.5 // indirect
	github.com/philhofer/fwd v1.1.1 // indirect
	github.com/pkg/errors v0.9.1
	github.com/pmezard/go-difflib v1.0.0
	github.com/rollbar/rollbar-go v1.2.0
	github.com/sasha-s/go-deadlock v0.2.0
	github.com/shibukawa/configdir v0.0.0-20170330084843-e180dbdc8da0
	github.com/spf13/cobra v1.1.3 // indirect
	github.com/spf13/viper v1.7.1 // indirect
	github.com/stretchr/testify v1.7.0
	github.com/tidwall/pretty v1.0.2 // indirect
	github.com/ttacon/builder v0.0.0-20170518171403-c099f663e1c2 // indirect
	github.com/ttacon/libphonenumber v1.1.0 // indirect
	github.com/tyler-smith/go-bip39 v1.0.2
	github.com/unrolled/secure v1.0.8
	github.com/xdg/stringprep v1.0.0 // indirect
	go.mongodb.org/mongo-driver v1.4.5
	golang.org/x/crypto v0.0.0-20210322153248-0c34fe9e7dc2
	golang.org/x/mod v0.4.2 // indirect
	golang.org/x/net v0.0.0-20210415231046-e915ea6b2b7d // indirect
	golang.org/x/oauth2 v0.0.0-20210413134643-5e61552d6c78 // indirect
	golang.org/x/sys v0.0.0-20210415045647-66c3f260301c // indirect
	golang.org/x/time v0.0.0-20201208040808-7e3f01d25324 // indirect
	google.golang.org/api v0.44.0
	google.golang.org/genproto v0.0.0-20210416161957-9910b6c460de // indirect
	google.golang.org/grpc v1.37.0 // indirect
	gopkg.in/DataDog/dd-trace-go.v1 v1.29.0
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b // indirect
)
