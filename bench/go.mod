module github.com/qursa-uc3m/dnssec_pqc_plugin/bench

go 1.23.3

require (
	github.com/miekg/dns v1.1.66
	github.com/open-quantum-safe/liboqs-go v0.0.0-20250119172907-28b5301df438
)

require (
	github.com/coredns/coredns v1.12.0 // indirect
	golang.org/x/mod v0.18.0 // indirect
	golang.org/x/net v0.31.0 // indirect
	golang.org/x/sync v0.9.0 // indirect
	golang.org/x/sys v0.27.0 // indirect
	golang.org/x/tools v0.22.0 // indirect
)

replace github.com/miekg/dns => github.com/qursa-uc3m/dns v1.1.63-0.20250710172324-2029d9fc17bf
