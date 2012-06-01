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

// This file contains code for reordering possibly out-of-order data

package gopcapreader

import (
	"container/heap"
	"fmt"
	"io"
	"time"
)

// orderedData is data with a fixed position, which we can reorder.
type orderedData struct {
	// The data payload
	Payload []byte
	// The start and end position of our data in our sequence.  Note that
	// Limit is not always Start + len(Payload).  In TCP in particular, we add
	// one for SYN and FIN packets.
	Start, Limit uint64
	// Specifies whether this data should be considered the initiator of our
	// stream or the terminator of the stream.
	IsFirst, IsLast bool
}

// dataHeap orders data elements by d.Start
type dataHeap []*orderedData

// heap functions that don't mutate dataHeap
func (dh dataHeap) Len() int           { return len(dh) }
func (dh dataHeap) Less(i, j int) bool { return dh[i].Start < dh[j].Start }
func (dh dataHeap) Swap(i, j int)      { dh[i], dh[j] = dh[j], dh[i] }

// heap functions that mutate dataHeap
func (dh *dataHeap) Push(x interface{}) { *dh = append(*dh, x.(*orderedData)) }
func (dh *dataHeap) Pop() (x interface{}) {
	h := *dh
	*dh, x = h[:len(h)-1], h[len(h)-1]
	return
}

// data-specific functions for dataHeap
func (dh *dataHeap) PushData(d *orderedData) { heap.Push(dh, d) }
func (dh *dataHeap) PopData() *orderedData   { return heap.Pop(dh).(*orderedData) }
func (dh dataHeap) PeekData() *orderedData   { return dh[0] }

// Error type for errors returned from dataStream.GetNext
type dataErrorType int

const (
	dataErrorMissing dataErrorType = iota
	dataErrorOverlap
	dataErrorDataNotAvailableYet
	dataErrorFirstDataNotAvailableYet
	dataErrorEndAlreadyReturned
)

// An error returned from dataStream.GetNext
type dataError struct {
	typ      dataErrorType
	from, to uint64
}

// Some errors that don't require ranges, so we only have to create them once.
var deNotAvailable error = &dataError{typ: dataErrorDataNotAvailableYet}
var deFirstNotAvailable error = &dataError{typ: dataErrorFirstDataNotAvailableYet}
var deEndAlreadyReturned error = &dataError{typ: dataErrorEndAlreadyReturned}

// Error renders dataError as an error string.
func (d dataError) Error() string {
	switch d.typ {
	case dataErrorMissing:
		return fmt.Sprintf("Missing data from %v to %v", d.from, d.to)
	case dataErrorOverlap:
		return fmt.Sprintf("Data overlapped from %v to %v", d.from, d.to)
	case dataErrorDataNotAvailableYet:
		return fmt.Sprintf("Data not available from %v to %v", d.from, d.to)
	case dataErrorFirstDataNotAvailableYet:
		return "Waiting for first data to become available"
	case dataErrorEndAlreadyReturned:
		return "Final data has already been returned"
	}
	return "Unknown data error"
}

// dataStream is sn ordered stream of Data objects.
//
// This class takes in orderedData objects unordered, and returns an ordered
// set of non-overlapping data objects.
type dataStream struct {
	heap              dataHeap
	sawFirst, sawLast bool
	seq               uint64
	bytes             int
}

// Add adds a new orderedData object to the stream.
// orderedData objects may be added in any order.
func (ds *dataStream) Add(d *orderedData) error {
	if ds.sawLast {
		return deEndAlreadyReturned
	}
	ds.bytes += len(d.Payload)
	ds.heap.PushData(d)
	return nil
}

// popNext pops the next data element off our heap and decrements our
// bytes counter.
func (ds *dataStream) popNext() *orderedData {
	d := ds.heap.PopData()
	ds.bytes -= len(d.Payload)
	return d
}

// getNextDataInternal determines which data to return next.
func (ds *dataStream) getNextDataInternal(skipIfNecessary bool) (*orderedData, error) {
	switch {
	case ds.sawLast:
		return nil, deEndAlreadyReturned
	case ds.sawFirst:
		d := ds.heap.PeekData()
		switch {
		case d.Start < ds.seq:
			d := ds.popNext()
			if d.Limit <= ds.seq {
				return nil, &dataError{dataErrorOverlap, d.Start, d.Limit}
			}
			oldStart := d.Start
			toSkip := int(ds.seq - d.Start)
			if toSkip > len(d.Payload) {
				toSkip = len(d.Payload)
			}
			toReturn := &orderedData{
				Start:   ds.seq,
				Limit:   d.Limit,
				IsFirst: d.IsFirst,
				IsLast:  d.IsLast,
				Payload: d.Payload[toSkip:],
			}
			return toReturn, &dataError{dataErrorOverlap, oldStart, ds.seq}
		case d.Start == ds.seq:
			return ds.popNext(), nil
		case skipIfNecessary:
			return ds.popNext(), &dataError{dataErrorMissing, ds.seq, d.Start}
		}
		return nil, &dataError{dataErrorDataNotAvailableYet, ds.seq, d.Start}
	case ds.heap.PeekData().IsFirst:
		return ds.popNext(), nil
	case skipIfNecessary:
		d := ds.popNext()
		return d, &dataError{dataErrorMissing, 0, d.Start}
	}
	return nil, deFirstNotAvailable
}

// GetNext returns the next orderedData object from the stream.
// orderedData objects returned from GetNext will be returned in order,
// and if overlaps exist, they will be removed (currently, the orderedData
// with the lowest Start number has precedence).
func (ds *dataStream) GetNext(skipIfNecessary bool) (*orderedData, error) {
	if ds.Len() > 0 {
		d, err := ds.getNextDataInternal(skipIfNecessary)
		// Update ds state based on returned data
		if d != nil {
			ds.seq = d.Limit
			ds.sawFirst = true
			if d.IsLast {
				ds.sawLast = true
				// Discard all data we currently have.  It'll never be returned.
				ds.heap = nil
			}
		}
		if err != nil && err != deFirstNotAvailable {
			gplog(logPedantic, "DataStream error:", err)
		}
		return d, err
	}
	return nil, deNotAvailable
}

// Done returns true if we're not going to return any more data.
func (ds *dataStream) Done() bool {
	return ds.sawLast
}

// Len returns the number of Data objects currently stored in the stream
// and waiting to be returned.
func (ds *dataStream) Len() int {
	return ds.heap.Len()
}

// Bytes returns the total number of payload bytes in the data stream.
func (ds *dataStream) Bytes() int {
	return ds.bytes
}

// blockingDataStream takes in orderedData objects over a channel, and provides
// a blocking GetNext() call that only returns once data is available.
type blockingDataStream struct {
	Input <-chan *orderedData
	ds    dataStream
	// GetNext will skip to the next piece of data if it hasn't received
	// the next logical piece during this timeframe.
	SkipTimeout time.Duration
	// GetNext will skip to the next piece of data if the size of its buffered
	// data exceeds this many bytes.
	SkipBytes int
	// GetNext will skip to the next piece of data if this many data pieces have
	// been buffered internally.
	SkipLength  int
	inputClosed bool
}

// Done returns true if this stream is guaranteed to never return anything again
// from GetNext()
func (bds *blockingDataStream) Done() bool {
	return bds.ds.Done() || (bds.inputClosed && bds.ds.Len() == 0)
}

// GetNext gets the next data in the stream, blocking as long as necessary.
// Blocking behavior can be configured by setting the Skip* configuration
// parameters.
func (bds *blockingDataStream) GetNext() (*orderedData, error) {
	var skipAndReturn bool
	for {
		skipAndReturn = skipAndReturn ||
			(bds.SkipBytes > 0 && bds.ds.Bytes() >= bds.SkipBytes) ||
			(bds.SkipLength > 0 && bds.ds.Len() >= bds.SkipLength)
		// If we hit our max bytes limit, give back our next data
		if bds.Done() {
			return nil, io.EOF
		}
		dataFromStream, err := bds.ds.GetNext(skipAndReturn)
		if dataFromStream != nil || skipAndReturn {
			return dataFromStream, err
		}
		var timer chan bool
		if bds.SkipTimeout > 0 {
			timer = make(chan bool, 1)
			go func() {
				time.Sleep(bds.SkipTimeout)
				timer <- true
			}()
		}
		select {
		case <-timer:
			// we timed out, give the best we've got
			skipAndReturn = true
		case dataFromInput, ok := <-bds.Input:
			if ok {
				bds.ds.Add(dataFromInput)
			} else {
				skipAndReturn = true
				bds.inputClosed = true
			}
		}
		// input has been closed down, so there's no point in waiting
	}
	panic("Reached end of blockingDataStream's GetNext")
}

// dataStreamReader implements the io.Reader interface on top of a
// blockingDataStream.
type dataStreamReader struct {
	bds            *blockingDataStream
	currentPayload []byte
}

// Returns a new dataStreamReader.
//   input:  Channel to read new data from.
func newDataStreamReader(bds *blockingDataStream) *dataStreamReader {
	return &dataStreamReader{bds: bds}
}

// Attempt to grab the next payload we can use, if we don't already have one.
func (dsr *dataStreamReader) maybeSetCurrentPayload() error {
	for dsr.currentPayload == nil || len(dsr.currentPayload) == 0 {
		if dsr.bds.Done() {
			return io.EOF
		}
		newDataFromStream, _ := dsr.bds.GetNext()
		if newDataFromStream != nil {
			dsr.currentPayload = newDataFromStream.Payload
		}
	}
	return nil
}

// Read implements the io.Reader interface
func (dsr *dataStreamReader) Read(p []byte) (int, error) {
	err := dsr.maybeSetCurrentPayload()
	if err != nil {
		return 0, io.EOF
	}
	size := len(p)
	currentSize := len(dsr.currentPayload)
	if size >= currentSize {
		size = currentSize
	}
	copy(p, dsr.currentPayload[:size])
	dsr.currentPayload = dsr.currentPayload[size:]
	return size, nil
}

// ReadByte implements the io.ByteReader interface.
func (dsr *dataStreamReader) ReadByte() (x byte, err error) {
	err = dsr.maybeSetCurrentPayload()
	if err == nil {
		x, dsr.currentPayload = dsr.currentPayload[0], dsr.currentPayload[1:]
	}
	return
}
