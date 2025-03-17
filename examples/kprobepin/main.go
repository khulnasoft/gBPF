//go:build linux

// This program demonstrates attaching an gBPF program to a kernel symbol.
// The gBPF program will be attached to the start of the sys_execve
// kernel function and prints out the number of times it has been called
// every second.
package main

import (
	"log"
	"os"
	"path"
	"time"

	"github.com/khulnasoft/gbpf"
	"github.com/khulnasoft/gbpf/link"
	"github.com/khulnasoft/gbpf/rlimit"
)

//go:generate go run github.com/khulnasoft/gbpf/cmd/bpf2go -tags linux bpf kprobe_pin.c -- -I../headers

const (
	mapKey    uint32 = 0
	bpfFSPath        = "/sys/fs/bpf"
)

func main() {

	// Name of the kernel function to trace.
	fn := "sys_execve"

	// Allow the current process to lock memory for gBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	pinPath := path.Join(bpfFSPath, fn)
	if err := os.MkdirAll(pinPath, os.ModePerm); err != nil {
		log.Fatalf("failed to create bpf fs subpath: %+v", err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, &gbpf.CollectionOptions{
		Maps: gbpf.MapOptions{
			// Pin the map to the BPF filesystem and configure the
			// library to automatically re-write it in the BPF
			// program so it can be re-used if it already exists or
			// create it if not
			PinPath: pinPath,
		},
	}); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Open a Kprobe at the entry point of the kernel function and attach the
	// pre-compiled program. Each time the kernel function enters, the program
	// will increment the execution counter by 1. The read loop below polls this
	// map value once per second.
	kp, err := link.Kprobe(fn, objs.KprobeExecve, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	log.Println("Waiting for events..")

	for range ticker.C {
		var value uint64
		if err := objs.KprobeMap.Lookup(mapKey, &value); err != nil {
			log.Fatalf("reading map: %v", err)
		}
		log.Printf("%s called %d times\n", fn, value)
	}
}
