module github.com/keith991001/agent-shield

go 1.25.0

require (
	github.com/cilium/ebpf v0.21.0
	golang.org/x/sys v0.45.0
)

require gopkg.in/yaml.v3 v3.0.1

require github.com/gorilla/websocket v1.5.3 // indirect

tool github.com/cilium/ebpf/cmd/bpf2go
