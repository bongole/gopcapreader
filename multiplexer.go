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

// This file contains logic for multiplexing packets into a set of TCP streams.

package gopcapreader

import (
	"bufio"
	pcap "github.com/akrennmair/gopcap"
	"io"
	"sync"
	"time"
)

type streamReader interface {
	Read([]byte) (int, error)
	ReadByte() (byte, error)
}

// Stream contains all information about a single unidirectional TCP
// stream.  It implements the io.Reader interface, so processors can
// read in the data flowing over that stream (in realtime) and process it.
// Users receive streams by creating a StreamHandler and passing it
// to a Multiplexer.
type Stream struct {
	Key                           TcpKey
	reader                        io.Reader
	buffered                      *bufio.Reader
	blockingDataStream            *blockingDataStream
	currentReader                 streamReader
	dataStreamReader              *dataStreamReader
	data                          chan *orderedData
	lastSeen                      time.Time
	lastRollover, currentRollover uint64
	// Number of packets dropped because input buffer was full
	DroppedFullBuffer int
	// Channel into which the reverse stream will be placed should it be found.
	// NOTE:  We do these channel writes in a non-blocking fashion.  There is
	// the potential for us to write into stream.ReverseStream two or more
	// times.  Consider the case where A is the reverse of B.  A gets garbage
	// collected, then immediately gets some new data.  B will receive 2
	// reverse streams, and without this non-blocking write, the second call
	// could block forever.
	// To protect against this, a client that carse should make sure that the
	// ReverseStream channel remains empty by reading from it regularly.
	// This channel has a capacity of one.
	ReverseStream chan *Stream
}

// Read implements the io.Reader interface
func (s *Stream) Read(p []byte) (int, error) {
	return s.currentReader.Read(p)
}

func (s *Stream) ReadByte() (byte, error) {
	return s.currentReader.ReadByte()
}

// BufferedReader eturns a bufio.Reader for this stream.
// Multiple calls to BufferedReader will return the same object.
// This enables multiple stream handlers to
// Peek() in order to attempt to discover the underlying protocol.
func (s *Stream) BufferedReader() *bufio.Reader {
	if s.buffered == nil {
		s.buffered = bufio.NewReader(s.dataStreamReader)
		s.currentReader = s.buffered
	}
	return s.buffered
}

// handleData attempts to push a new data object into the stream.
func (s *Stream) handleData(d *orderedData) {
	// Do our write non-blocking... we could lose some data, but
	// better than blocking the entire multiplexer on a single stream.
	select {
	case s.data <- d:
	default:
		s.DroppedFullBuffer++
	}
}

// tearDown closes a stream when the multiplexer decides it will no longer
// write packets into it.
func (s *Stream) tearDown() {
	close(s.data)
}

// StreamHandler tells the Multiplexer how to process a new stream.
type StreamHandler interface {
	// HandleStream handles each new Stream a Multiplexer sees.
	// Whenever the Multiplexer sees a new stream, it will call HandleStream on
	// that new stream inside a GoRoutine.  The HandleStream call can do all the
	// (blocking) processing it wants on the given Stream object.  When a call to
	// HandleStream returns, all data still in the stream will be discarded until
	// the stream closes.
	HandleStream(*Stream)
}

// StreamHandlerFunction allows a function to implement StreamHandler.
type StreamHandlerFunction func(stream *Stream)

// HandleStream implementation of the StreamHandler interface, calls self.
func (shf StreamHandlerFunction) HandleStream(stream *Stream) {
	shf(stream)
}

// DiscardBytes reads in all bytes from the given io.Reader, throwing
// them away immediately. Returns when it it hits EOF, returning the
// total number of bytes discarded.
func DiscardBytes(r io.Reader) (total int) {
	body := make([]byte, 2048)
	for n, _ := r.Read(body); n > 0; n, _ = r.Read(body) {
		total += n
	}
	return
}

// Multiplexer handles multiplexing incoming data into a set of streams.
// New streams are passed to the StreamHandler's HandleStream function.
type Multiplexer struct {
	streams map[TcpKey]*Stream
	packets chan *pcap.Packet
	// Defaults to 1000, reset before calling MultiplexPcap to change.  Users
	// should reset this before calling MultiplexPcap if they want to override the
	// default.
	GarbageCollectMaxStreams int
	readCreator              StreamHandler
	// Statistics.  Shouldn't be set by user, but can be read.
	BytesProcessed                  int64
	PacketsProcessed                int64
	PacketDecodeFailures            int64
	PacketsDroppedPrimaryBufferFull int64
	StreamsGarbageCollected         int64
	// Waits for streams to finish.
	closeWaiter sync.WaitGroup
}

// newStream is called by the multiplexer to create a new stream.
func (m *Multiplexer) newStream(k TcpKey) *Stream {
	gplog(logInfo, "Multiplexer creating new stream for key", k)
	stream := &Stream{
		data:          make(chan *orderedData, 10),
		Key:           k,
		ReverseStream: make(chan *Stream, 1),
	}
	stream.blockingDataStream = &blockingDataStream{
		Input: stream.data,
		//SkipTimeout: time.Second * 1,
		SkipLength: 10,
	}
	stream.dataStreamReader = newDataStreamReader(stream.blockingDataStream)
	stream.currentReader = stream.dataStreamReader
	m.closeWaiter.Add(1)
	go func() {
		defer m.closeWaiter.Done()
		// Handle the stream with our read creator's HandleStream.
		m.readCreator.HandleStream(stream)
		// If HandleStream doesn't read everything, we still want to discard
		// all bytes going into the stream.
		// So we have a default fallback to do just that.
		DiscardBytes(stream)
	}()
	return stream
}

// NewMultiplexer creates a new Multiplexer object.
// The passed-in StreamHandler will be used to
// handle all new streams created by the Multiplexer.
func NewMultiplexer(creator StreamHandler) *Multiplexer {
	m := &Multiplexer{
		streams:                  make(map[TcpKey]*Stream),
		packets:                  make(chan *pcap.Packet, 1000),
		GarbageCollectMaxStreams: 1000,
		readCreator:              creator,
	}
	m.closeWaiter.Add(1)
	go m.run()
	return m
}

// run reads packets from the input channel, farming them out to streams,
// creating new streams if necessary.
func (m *Multiplexer) run() {
	defer m.closeWaiter.Done()
	for pcapPacket := range m.packets {
		m.PacketsProcessed++
		m.BytesProcessed += int64(len(pcapPacket.Data))
		p, err := NewTcpPacket(pcapPacket)
		if err != nil {
			m.PacketDecodeFailures++
			continue
		}
		d := p.asData()
		// Discard uninteresting packets
		if d.IsFirst || d.IsLast || d.Start != d.Limit {
			k, kerr := p.TcpKey()
			if kerr != nil {
				gplog(logDebug, "Packet keying error: ", kerr.Error())
				continue
			}

			stream := m.getStream(k)

			// Update metadata and handle data
			stream.handleRollover(d)
			stream.lastSeen = time.Now()
			stream.handleData(d)
		}
		// Garbage collect if we have to many packets
		if len(m.streams) > m.GarbageCollectMaxStreams {
			m.garbageCollect()
		}
	}
	for _, stream := range m.streams {
		stream.tearDown()
	}
}

// getStream gets the stream associated with the given key,
// creating it if necessary.
func (m *Multiplexer) getStream(k TcpKey) (stream *Stream) {
	var ok bool
	if stream, ok = m.streams[k]; !ok {
		stream = m.newStream(k)
		m.streams[k] = stream
		if len(m.streams)%10000 == 0 {
			gplog(logInfo, "STREAMS", len(m.streams))
		}

		// Find the reverse stream.  If it exists, set ReverseStream in both
		// directions.
		if reverseStream, ok := m.streams[k.Reverse()]; ok {
			select {
			case stream.ReverseStream <- reverseStream:
			default:
			}
			select {
			case reverseStream.ReverseStream <- stream:
			default:
			}
		}
	}
	return
}

// handleRollover handle rollovers of TCP sequence numbers.
func (stream *Stream) handleRollover(d *orderedData) {
	// Uses the following logic:
	//          0         1<<30            1<<31      3<<30         1<<32
	// USE:     [current    ][current       ][last      ][last        ]
	// DO ONCE: [           ][last = current][          ][current += 1]
	// This allows us to roll over as many times as we want, and keep track of
	// very little in the process (just the number of times we've rolled over)
	if d.Start > (3<<30) && stream.lastRollover == stream.currentRollover {
		stream.currentRollover += 1
	}
	if d.Start > (1<<30) && d.Start < (1<<31) && stream.lastRollover != stream.currentRollover {
		stream.lastRollover = stream.currentRollover
	}
	if d.Start > (1 << 31) {
		d.Start += (2 << 32) * stream.lastRollover
		d.Limit += (2 << 32) * stream.lastRollover
	} else {
		d.Start += (2 << 32) * stream.currentRollover
		d.Limit += (2 << 32) * stream.currentRollover
	}
}

// garbageCollect garbage collect streams based on the last time a packet was
// seen for the given stream.  Newer streams are kept, older streams are
// discarded.
func (m *Multiplexer) garbageCollect() {
	gplog(logInfo, "Garbage collecting, have", len(m.streams))
	now := time.Now()
	// Our current method for garbage collecting is extremely simple, pretty fast
	// (O(n)), and really inexact.  We determine the average age of all streams
	// and the maximum age...
	var ageSum time.Duration
	var ageMax time.Duration
	for _, stream := range m.streams {
		diff := now.Sub(stream.lastSeen)
		ageSum += diff
		if ageMax < diff {
			ageMax = diff
		}
	}
	// We use the age sum to compute an average age...
	ageAverage := ageSum / time.Duration(len(m.streams))
	// And we create an age cutoff halfway between the average age and the max
	// age.  This is silly... we should attempt to do some standard deviation
	// stuff here.  But this was a lot quicker to code, and I didn't have to go
	// look up how to do standard deviation calculations again.
	cutoff := now.Add(-(ageAverage + ageMax) / 2)
	keysToDiscard := make([]TcpKey, 0, len(m.streams))
	for k, stream := range m.streams {
		if stream.lastSeen.Before(cutoff) {
			keysToDiscard = append(keysToDiscard, k)
			stream.tearDown()
		}
	}
	for _, k := range keysToDiscard {
		m.StreamsGarbageCollected++
		delete(m.streams, k)
	}
	gplog(logWarning, "Garbage collected at cutoff", cutoff, time.Now().Sub(cutoff),
		"ago, removed", len(keysToDiscard), "kept", len(m.streams))
}

// Close flushes all current streams and stops the multiplexer from accepting
// any new packets.
// Note that a close called while another goroutine is adding packets into the
// multiplexer is not recommended, and could result in a runtime panic.
// Close() will block until all streams have been flushed and all handlers
// have returned.
func (m *Multiplexer) Close() {
	close(m.packets)
	m.closeWaiter.Wait()
}
