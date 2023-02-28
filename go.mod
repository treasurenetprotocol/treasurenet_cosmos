go 1.15

module github.com/cosmos/cosmos-sdk

require (
	github.com/99designs/keyring v1.2.1
	github.com/armon/go-metrics v0.4.1
	github.com/bgentry/speakeasy v0.1.0
	github.com/btcsuite/btcd v0.22.1
	github.com/btcsuite/btcutil v1.0.3-0.20201208143702-a53e38424cce
	github.com/coinbase/rosetta-sdk-go v0.7.9
	github.com/confio/ics23/go v0.9.0
	github.com/cosmos/go-bip39 v1.0.0
	github.com/cosmos/iavl v0.19.4
	github.com/cosmos/ledger-cosmos-go v0.12.1
	github.com/danieljoos/wincred v1.1.2 // indirect
	github.com/dgraph-io/ristretto v0.1.0 // indirect
	github.com/dvsekhvalnov/jose2go v1.5.0 // indirect
	github.com/enigmampc/btcutil v1.0.3-0.20200723161021-e2fb6adb2a25
	github.com/facebookgo/ensure v0.0.0-20200202191622-63f1cf65ac4c // indirect
	github.com/facebookgo/subset v0.0.0-20200203212716-c811ad88dec4 // indirect
	github.com/gin-gonic/gin v1.7.0 // indirect
	github.com/gogo/gateway v1.1.0
	github.com/gogo/protobuf v1.3.3
	github.com/golang/glog v1.0.0 // indirect
	github.com/golang/mock v1.6.0
	github.com/golang/protobuf v1.5.2
	github.com/gorilla/handlers v1.5.1
	github.com/gorilla/mux v1.8.0
	github.com/grpc-ecosystem/go-grpc-middleware v1.3.0
	github.com/grpc-ecosystem/grpc-gateway v1.16.0
	github.com/hashicorp/golang-lru v0.5.5-0.20210104140557-80c98217689d
	github.com/hdevalence/ed25519consensus v0.0.0-20220222234857-c00d1f31bab3
	github.com/improbable-eng/grpc-web v0.15.0
	github.com/jhump/protoreflect v1.13.1-0.20220928232736-101791cb1b4c
	github.com/magiconair/properties v1.8.6
	github.com/mattn/go-isatty v0.0.16
	github.com/onsi/ginkgo/v2 v2.7.0 // indirect
	github.com/onsi/gomega v1.24.2 // indirect
	github.com/otiai10/copy v1.6.0
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.12.2
	github.com/prometheus/common v0.34.0
	github.com/rakyll/statik v0.1.7
	github.com/regen-network/cosmos-proto v0.3.1
	github.com/rs/cors v1.8.3 // indirect
	github.com/rs/zerolog v1.27.0
	github.com/spf13/cast v1.5.0
	github.com/spf13/cobra v1.6.1
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.14.0
	github.com/stretchr/testify v1.8.1
	github.com/tendermint/btcd v0.1.1
	github.com/tendermint/crypto v0.0.0-20191022145703-50d29ede1e15
	github.com/tendermint/go-amino v0.16.0
	github.com/tendermint/tendermint v0.34.24
	github.com/tendermint/tm-db v0.6.7
	golang.org/x/crypto v0.3.0
	golang.org/x/net v0.5.0 // indirect
	google.golang.org/genproto v0.0.0-20221118155620-16455021b5e6
	google.golang.org/grpc v1.52.0
	google.golang.org/protobuf v1.28.2-0.20220831092852-f930b1dc76e8
	gopkg.in/yaml.v2 v2.4.0
)

replace google.golang.org/grpc => google.golang.org/grpc v1.33.2

replace github.com/gogo/protobuf => github.com/regen-network/protobuf v1.3.3-alpha.regen.1

replace github.com/99designs/keyring => github.com/cosmos/keyring v1.1.7-0.20210622111912-ef00f8ac3d76

replace github.com/tendermint/tendermint v0.34.21 => ./tendermint_pack2

replace github.com/tendermint/tm-db v0.6.7 => ./tendermint_pack2/tm-db_pack

replace github.com/hashicorp/golang-lru v0.5.5-0.20210104140557-80c98217689d => github.com/hashicorp/golang-lru v0.5.4

replace github.com/spf13/viper v1.12.0 => github.com/spf13/viper v1.8.0

replace github.com/armon/go-metrics v0.4.0 => github.com/armon/go-metrics v0.3.9

replace github.com/coinbase/rosetta-sdk-go v0.7.0 => github.com/coinbase/rosetta-sdk-go v0.6.10

replace github.com/confio/ics23/go v0.7.0 => github.com/confio/ics23/go v0.6.6

replace github.com/cosmos/iavl v0.19.1 => github.com/cosmos/iavl v0.16.0
