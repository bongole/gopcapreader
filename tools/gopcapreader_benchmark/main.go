// Copyright 2012 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"code.google.com/p/gopcapreader"
	"flag"
	"fmt"
	pcap "github.com/akrennmair/gopcap"
	"log"
	"runtime"
	"time"
)

var filter *string = flag.String("filter", "tcp", "BPF filter for packet capture")
var interfaceName *string = flag.String("interface", "eth0", "Interface to pcap")
var maxPackets *int64 = flag.Int64("packets", -1, "Max packets to process")
var maxStreams *int = flag.Int("max_streams", 10000, "Max number of streams to have at once")
var goMaxProcs *int = flag.Int("go_max_procs", 2, "GOMAXPROCS to set for Go.")

func main() {
	flag.Parse()
	// Set this to at least 2, or performance will DRASTICALLY decrease.
	runtime.GOMAXPROCS(*goMaxProcs)
	// Turn on pcap, and filter it.
	h, err := pcap.Openlive(*interfaceName, 8192, true, 0)
	if h == nil {
		log.Fatal("pcap.OpenLive:", err)
	}
	if filtErr := h.Setfilter(*filter); filtErr != nil {
		log.Fatal("Setfilter:", err)
	}
	// Run the multiplexer.
	// Use an empty StreamHandlerSlice to ignore all streams (they'll fall back to
	// having their data discarded by DiscardBytes())
	var emptyHandler gopcapreader.StreamHandlerSlice
	multiplexer := gopcapreader.NewMultiplexer(emptyHandler)
	multiplexer.GarbageCollectMaxStreams = *maxStreams
	fmt.Println("Starting benchmark")
	startTime := time.Now()
	multiplexer.MultiplexPcap(h, *maxPackets)
	pcapStats, statsErr := h.Getstats()
	multiplexer.Close()
	endTime := time.Now()
	h.Close()
	if statsErr != nil {
		log.Fatal("Pcap stats error:", err)
	}
	fmt.Println("--- STATS ---")
	fmt.Println("  Run time:                     ", endTime.Sub(startTime))
	fmt.Println("  -- PCAP --")
	fmt.Println("  Packets received:             ", pcapStats.PacketsReceived)
	fmt.Println("  Packets dropped:              ", pcapStats.PacketsDropped)
	fmt.Println("  Packets dropped by interface: ", pcapStats.PacketsIfDropped)
	fmt.Println("  -- Multiplexer --")
	fmt.Println("  Packets processed:            ", multiplexer.PacketsProcessed)
	fmt.Println("  Packets dropped (full buffer):", multiplexer.PacketsDroppedPrimaryBufferFull)
	fmt.Println("  Packets dropped (decode fail):", multiplexer.PacketDecodeFailures)
	fmt.Println("  Bytes processed:              ", multiplexer.BytesProcessed)
	fmt.Println("  Streams garbage collected:    ", multiplexer.StreamsGarbageCollected)
}
