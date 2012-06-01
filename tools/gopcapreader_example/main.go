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
	pcap "github.com/akrennmair/gopcap"
	"io"
	"log"
	"net/http"
)

// HTTP Request handler, reads HTTP requests in real-time off the wire and
// prints them out to STDOUT.
type HttpRequests struct{}

func (h *HttpRequests) HandleStream(stream *gopcapreader.Stream) {
	log.Println("GOT NEW HTTP STREAM", stream.Key)
	eof := false
	for !eof {
		if req, err := http.ReadRequest(stream.BufferedReader()); req != nil {
			bodyBytes := gopcapreader.DiscardBytes(req.Body)
			req.Body.Close()
			log.Println("HTTP REQUEST:", req)
			log.Println("Read", bodyBytes, "bytes from request body")
		} else if err == io.EOF || err == io.ErrUnexpectedEOF {
			eof = true
		} else {
			log.Println("UNEXPECTED ERROR:", err)
		}
	}
}

func main() {
	// Turn on pcap, and filter it.
	h, err := pcap.Openlive("eth0", 8192, true, 0)
	if h == nil {
		log.Fatal("pcap.OpenLive:", err)
	}
	if filtErr := h.Setfilter("tcp and port 80"); filtErr != nil {
		log.Fatal("Setfilter:", err)
	}
	// Run the multiplexer.
	multiplexer := gopcapreader.NewMultiplexer(&HttpRequests{})
	multiplexer.MultiplexPcap(h, 0)
}
