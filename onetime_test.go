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
	"testing"
	"time"
)

var handler StreamHandlerFunction = StreamHandlerFunction(func(stream *Stream) {
	copy(stream.Key.SrcIp[:], []byte("RAN"))
})

func TestExpirationAfterTimeout(t *testing.T) {
	onetime := NewOneTimeStreamHandler()
	s := &Stream{}
	onetime.SetUpOneTimeHandler(s.Key, handler, time.Microsecond)
	time.Sleep(time.Millisecond * 100)
	handled := onetime.MaybeHandleStream(s)
	if handled {
		t.Error("Onetime handled stream after handler timeout expired")
	}
}

func TestHandledWithinTimeout(t *testing.T) {
	onetime := NewOneTimeStreamHandler()
	s := &Stream{}
	onetime.SetUpOneTimeHandler(s.Key, handler, time.Millisecond*100)
	handled := onetime.MaybeHandleStream(s)
	if !handled {
		t.Error("Onetime handled stream after handler timeout expired")
	}
}

func TestHalfKeysCatchStream(t *testing.T) {
	onetime := NewOneTimeStreamHandler()
	s := &Stream{}
	s.Key.SrcPort = 1000
	s.Key.DestPort = 2000
	src, dst := s.Key.HalfKeys()
	onetime.SetUpOneTimeHalfHandlers(src, handler, nil, time.Millisecond*100)
	handled := onetime.MaybeHandleStream(s)
	if !handled {
		t.Error("Onetime src handler didn't get called")
	}
	onetime.SetUpOneTimeHalfHandlers(dst, nil, handler, time.Millisecond*100)
	handled = onetime.MaybeHandleStream(s)
	if !handled {
		t.Error("Onetime dst handler didn't get called")
	}
}

func TestHalfKeysIgnoreOtherDirection(t *testing.T) {
	onetime := NewOneTimeStreamHandler()
	s := &Stream{}
	s.Key.SrcPort = 1000
	s.Key.DestPort = 2000
	src, dst := s.Key.HalfKeys()
	onetime.SetUpOneTimeHalfHandlers(src, nil, handler, time.Millisecond*100)
	handled := onetime.MaybeHandleStream(s)
	if handled {
		t.Error("Onetime matched src half to dst handler")
	}
	onetime.SetUpOneTimeHalfHandlers(dst, handler, nil, time.Millisecond*100)
	handled = onetime.MaybeHandleStream(s)
	if handled {
		t.Error("Onetime matched dst half to src handler")
	}
}
