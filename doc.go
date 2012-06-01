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

// This file contains documentation for the gopcapreader package.

/*
Package gopcapreader provides pcap TCP data through a simple
io.Reader interface, for easy analysis of real-time TCP streams.

Library users initially set up a gopcap packet capture object to read packets
off the wire, then pass that object into a gopcapreader.Multiplexer.  The
Multiplexer breaks up packets into unidirectional Stream objects, keyed by
[srcip,srcport,dstip,dstport], then reorders/reassembles the payloads of those
packets into an ordered stream of bytes.  Those bytes can then be read in with
the io.Reader interface to any code that wants to use it.

Example (see actual working implementation in tools/simple/main.go):

  import (
    "gopcapreader"
    "net/http"
    "pcap"
    ...
  )

  // HTTP Request handler, reads HTTP requests in real-time off the wire and
  // prints them out to STDOUT.
  type HttpRequests interface{}
  func (h *HttpRequests) HandleStream(stream *gopcapreader.Stream) {
    fmt.Println("GOT NEW HTTP STREAM", stream.Key)
    eof := false
    for !eof {
      if req, err := http.ReadRequest(stream.BufferedReader()); req != nil {
        bodyBytes := gopcapreader.DiscardBytes(req.Body)
        req.Body.Close()
        fmt.Println("HTTP REQUEST:", req)
        fmt.Println("Read", bodyBytes, "bytes from request body")
      } else if err == io.EOF || err == io.ErrUnexpectedEOF {
        eof = true
      } else {
        fmt.Println("UNEXPECTED ERROR:", err)
      }
    }
  }

  func main() {
    pcap := // set up pcap with filter 'tcp and dst port 80'
    multiplexer := gopcapreader.NewMultiplexer(&HttpRequests{})
    multiplexer.MultiplexPcap(h, 0)  // 0 == never stop processing
  }

This example uses the built-in net/http package's HTTP parsing to parse HTTP
requests out of all live packet streams with destination port 80.
*/
package gopcapreader
