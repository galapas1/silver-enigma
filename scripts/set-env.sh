export PATH=$PATH:$HOME/go/bin
GOPATH=$HOME/go

mkdir -p .ninjapanda/var/lib/ninjapanda
mkdir .ninjapanda/var/run

## Notes (jrb)
go clean -modcache
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.28
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2
