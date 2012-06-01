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

package gopcapreader

import (
	"io"
	"testing"
	"time"
)

func TestFirstWriteRead(t *testing.T) {
	ds := &dataStream{}
	ds.Add(&orderedData{
		Payload: []byte("abcdefg"),
		Start:   0,
		Limit:   7,
		IsFirst: true,
		IsLast:  true,
	})
	out, err := ds.GetNext(false)
	if err != nil {
		t.Errorf("Non-nil output %q", err)
	}
	if string(out.Payload) != "abcdefg" {
		t.Errorf("Invalid payload %q", out.Payload)
	}
	t.Log("Blah")
}

func TestUsageRun(t *testing.T) {
	ds := &dataStream{}
	ds.Add(&orderedData{
		Payload: []byte("abc"),
		Start:   16,
		Limit:   19,
	})
	if ds.Bytes() != 3 {
		t.Errorf("Incorrect bytes 1: %q", ds.Bytes())
	}
	ds.Add(&orderedData{
		Payload: []byte("def"),
		Start:   19,
		Limit:   22,
	})
	if ds.Bytes() != 6 {
		t.Errorf("Incorrect bytes 2: %q", ds.Bytes())
	}
	ds.Add(&orderedData{
		Payload: []byte("ghi"),
		Start:   20,
		Limit:   23,
	})
	if ds.Bytes() != 9 {
		t.Errorf("Incorrect bytes 3: %q", ds.Bytes())
	}
	if ds.Len() != 3 {
		t.Errorf("Incorrect number of packets: %q", ds.Len())
	}
	// Try to get next without skip
	out, err := ds.GetNext(false)
	if err != deFirstNotAvailable {
		t.Errorf("Bad error %q", err)
	}
	if out != nil {
		t.Errorf("No nil %q", out)
	}
	// Try to get next with skip
	out, err = ds.GetNext(true)
	if err == nil {
		t.Error("Nil error")
	}
	derr := err.(*dataError)
	if derr.from != 0 || derr.to != 16 {
		t.Errorf("Range: %q %q", derr.from, derr.to)
	}
	if derr.typ != dataErrorMissing {
		t.Errorf(derr.Error())
	}
	if out == nil {
		t.Error("Nil output 1")
	}
	if string(out.Payload) != "abc" {
		t.Errorf("Incorrect payload 1 %q", out.Payload)
	}
	if ds.Bytes() != 6 {
		t.Errorf("Incorrect bytes 3: %q", ds.Bytes())
	}
	// Now a normal read of data that doesn't require a skip
	out, err = ds.GetNext(false)
	if err != nil {
		t.Errorf("Nonnil error %q", err)
	}
	if out == nil {
		t.Error("Nil output 2")
	}
	if string(out.Payload) != "def" {
		t.Errorf("Incorrect payload 2 %q", out.Payload)
	}
	if ds.Bytes() != 3 {
		t.Errorf("Incorrect bytes 4: %q", ds.Bytes())
	}
	// Finally, a read with overlap
	out, err = ds.GetNext(false)
	if err == nil {
		t.Errorf("NNil error 2")
	} else if err.(*dataError).typ != dataErrorOverlap || err.(*dataError).from != 20 || err.(*dataError).to != 22 {
		t.Errorf("Bad error 2: %q", err)
	}
	if out == nil {
		t.Error("Nil output 3")
	}
	if string(out.Payload) != "i" {
		t.Errorf("Incorrect payload 3 %q", out.Payload)
	}
	if ds.Bytes() != 0 {
		t.Errorf("Incorrect bytes 4: %q", ds.Bytes())
	}
	// Read but no data's available
	out, err = ds.GetNext(true)
	if out != nil {
		t.Errorf("Nonnil output %q", out.Payload)
	}
	if err != deNotAvailable {
		t.Errorf("Unexpected error: %q", err)
	}
}

func TestBlockingRead(t *testing.T) {
	input := make(chan *orderedData, 1)
	bds := &blockingDataStream{Input: input}
	dsr := newDataStreamReader(bds)
	data := make([]byte, 10)
	go func() {
		time.Sleep(time.Second / 10)
		input <- &orderedData{Payload: []byte("abc"), IsFirst: true}
	}()
	i, err := dsr.Read(data)
	if i != 3 {
		t.Errorf("Incorrect bytes returned: %v", i)
	}
	if err != nil {
		t.Errorf("Non-nil error: %q", err)
	}
	if string(data[:i]) != "abc" {
		t.Errorf("Incorrect data: %q", data[:i])
	}
}

func TestCloseInput(t *testing.T) {
	input := make(chan *orderedData, 1)
	bds := &blockingDataStream{Input: input}
	dsr := newDataStreamReader(bds)
	data := make([]byte, 10)
	go func() {
		time.Sleep(time.Second / 10)
		close(input)
	}()
	i, err := dsr.Read(data)
	if i != 0 {
		t.Errorf("Incorrect bytes returned: %v", i)
	}
	if err != io.EOF {
		t.Errorf("Non-nil error: %q", err)
	}
}

func TestBlockingReadWithSkips(t *testing.T) {
	input := make(chan *orderedData, 1)
	bds := &blockingDataStream{Input: input}
	dsr := newDataStreamReader(bds)
	bds.SkipTimeout = time.Second / 100
	data := make([]byte, 10)
	go func() {
		time.Sleep(time.Second / 10)
		input <- &orderedData{Payload: []byte("abc"), IsFirst: true}
	}()
	i, err := dsr.Read(data)
	if i != 3 {
		t.Errorf("Incorrect bytes returned: %v", i)
	}
	if err != nil {
		t.Errorf("Non-nil error: %q", err)
	}
	if string(data[:i]) != "abc" {
		t.Errorf("Incorrect data: %q", data[:i])
	}
}

func TestSkipTimeoutRead(t *testing.T) {
	input := make(chan *orderedData, 1)
	bds := &blockingDataStream{Input: input}
	dsr := newDataStreamReader(bds)
	bds.SkipTimeout = time.Second / 10
	data := make([]byte, 10)
	input <- &orderedData{Payload: []byte("abc"), Start: 10}
	i, err := dsr.Read(data)
	if i != 3 {
		t.Errorf("Incorrect bytes returned: %v", i)
	}
	if err != nil {
		t.Errorf("Non-nil error: %q", err)
	}
	if string(data[:i]) != "abc" {
		t.Errorf("Incorrect data: %q", data[:i])
	}
}

func BenchmarkOneWriteOneRead(b *testing.B) {
	ds := &dataStream{}
	in := &orderedData{Payload: []byte("")}
	for i := 0; i < b.N; i++ {
		ds.Add(in)
		_, _ = ds.GetNext(true)
	}
}
