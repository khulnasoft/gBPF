//go:build linux

// getting_started_gen {
package main

//go:generate go run github.com/khulnasoft/gbpf/cmd/bpf2go -tags linux counter counter.c

// }
