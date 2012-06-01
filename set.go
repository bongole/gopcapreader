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

// This file contains a helper to allow a set of handlers to handle streams.

package gopcapreader

// MaybeHandleStream provides an interface for an object that conditionally
// handles certain streams.
type MaybeStreamHandler interface {
	// MaybeHandleStream either handles a stream and returns true, or ignores the
	// stream and returns false.
	// Should return true only if this function has already completely
	// handled the passed-in stream.
	// Should return false only if this function has NOT destructively
	// read from this stream.  Calls to stream.BufferedReader().Peek()
	// are acceptable, but calls to stream.Read() are destructive and
	// should not be done by a function that's going to return false.
	MaybeHandleStream(stream *Stream) bool
}

// MaybeStreamHandlerFunction is a convenience function type that implements
// the MaybeStreamHandler interface
type MaybeStreamHandlerFunction func(stream *Stream) bool

// MaybeHandleStream implements the MaybeStreamHandler interface
func (m MaybeStreamHandlerFunction) MaybeHandleStream(stream *Stream) bool {
	return m(stream)
}

// StreamHandlerSet acts as a switch{} statement for a set of
// MaybeStreamHandler objects, calling them in sequence until one of them
// returns true.
type StreamHandlerSlice []MaybeStreamHandler

// HandleStream implements the StreamHandler interface.
func (set StreamHandlerSlice) HandleStream(stream *Stream) {
	for _, handler := range set {
		if handler.MaybeHandleStream(stream) {
			return
		}
	}
}
