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

// This file contains code to register one-time handlers for a specific stream key.

package gopcapreader

import (
	"sync"
	"time"
)

// OneTimeStreamHandler implements MaybeHandleStream and allows users to set up
// one-time handlers for TCP sessions using either TcpKey or TcpHalfKey keys.
// To use, the user calls one of the SetUp*Handler functions to set up the
// handler on the given key.  The next time a stream matching that key is
// seen, it will be handled with the passed-in handler.
// Given the asynchronous nature of the Multiplexer, sometimes a race condition
// occurs between the call to SetUp*Handler and the new stream's creation.
// To handle this, we can place unprocessed streams in a 'waiting' state.
// We hold onto streams we don't know what to do with for some period of time,
// and if, during that time, a SetUp*Handler call occurs that matches that
// stream, we pull the stream out of the waiting state and call the handler
// on it.  The WaitForOneTimeHandler call allows us to place a stream into
// this waiting state for a duration of time.
//
// An example of where this could be useful:  Some protocols use commands in one
// TCP stream to set up other TCP streams.  The canonical example is FTP, where
// a single command channel sets up additional channels over which to send
// files.  This API allows the user to see the command creating a channel on one
// stream, and define a handler to handle that stream when it's created.
type OneTimeStreamHandler struct {
	mu sync.RWMutex
	// Implementation note:
	// Handler maps map to *StreamHandler, not StreamHandler.  It's very important
	// that it stays this way.  When setting handlers, we use the pattern:
	//   handlers[key] = &handler
	//   sleep(timeout)
	//   if h, ok := handlers[key]; ok && h == &handler {
	//     delete(handlers, key)
	//   }
	// If we just used StreamHandler instead of *StreamHandler, the above code
	// would runtime fail at 'h == handler', since sometimes the value pointed to
	// by the StreamHandler interface is not able to be compared (specifically, if
	// it's a StreamHandlerFunction).  Pointer comparisons, though, always work.
	handlers        map[TcpKey]*StreamHandler
	srcHalfHandlers map[TcpHalfKey]*StreamHandler
	dstHalfHandlers map[TcpHalfKey]*StreamHandler
	waiting         map[TcpKey]chan StreamHandler
	waitingSrcHalf  map[TcpHalfKey]chan StreamHandler
	waitingDstHalf  map[TcpHalfKey]chan StreamHandler
}

func NewOneTimeStreamHandler() *OneTimeStreamHandler {
	return &OneTimeStreamHandler{
		handlers:        make(map[TcpKey]*StreamHandler),
		srcHalfHandlers: make(map[TcpHalfKey]*StreamHandler),
		dstHalfHandlers: make(map[TcpHalfKey]*StreamHandler),
		waiting:         make(map[TcpKey]chan StreamHandler),
		waitingSrcHalf:  make(map[TcpHalfKey]chan StreamHandler),
		waitingDstHalf:  make(map[TcpHalfKey]chan StreamHandler),
	}
}

// MaybeHandleStream implements MaybeStreamHandler.  It checks if it has
// a one-time handler for the given stream.  If it does, it handles it and
// return true.  If not, it immediately returns false.
func (set *OneTimeStreamHandler) MaybeHandleStream(stream *Stream) bool {
	srcHalf, dstHalf := stream.Key.HalfKeys()

	// Look for a handler for the given stream in our set of known handlers.
	set.mu.Lock()
	var handler *StreamHandler
	var haveHandler bool
	if handler, haveHandler = set.handlers[stream.Key]; haveHandler {
		delete(set.handlers, stream.Key)
	} else if handler, haveHandler = set.srcHalfHandlers[srcHalf]; haveHandler {
		delete(set.srcHalfHandlers, srcHalf)
	} else if handler, haveHandler = set.dstHalfHandlers[dstHalf]; haveHandler {
		delete(set.dstHalfHandlers, dstHalf)
	}
	set.mu.Unlock()

	// If we have a handler, run it.
	if haveHandler {
		(*handler).HandleStream(stream)
		return true
	}
	return false
}

// SetUpOneTimeHalfHandlers sets up a set of handlers for both directions of
// a TcpHalfKey.
// src and dst can be nil, in which case only the other direction is set up
// for handling.  After timeout has passed, both handlers are discarded.
func (set *OneTimeStreamHandler) SetUpOneTimeHalfHandlers(halfKey TcpHalfKey, src, dst StreamHandler, timeout time.Duration) {
	set.mu.Lock()
	if src != nil {
		if waiting, ok := set.waitingSrcHalf[halfKey]; ok {
			delete(set.waitingSrcHalf, halfKey)
			select {
			case waiting <- src:
			default:
			}
		} else {
			set.srcHalfHandlers[halfKey] = &src
		}
	}
	if dst != nil {
		if waiting, ok := set.waitingDstHalf[halfKey]; ok {
			delete(set.waitingDstHalf, halfKey)
			select {
			case waiting <- dst:
			default:
			}
		} else {
			set.dstHalfHandlers[halfKey] = &dst
		}
	}
	set.mu.Unlock()

	// Schedule the removal of handlers at a later time.
	go func() {
		time.Sleep(timeout)
		set.mu.Lock()
		if src != nil {
			if h, ok := set.srcHalfHandlers[halfKey]; ok && h == &src {
				delete(set.srcHalfHandlers, halfKey)
			}
		}
		if dst != nil {
			if h, ok := set.dstHalfHandlers[halfKey]; ok && h == &dst {
				delete(set.dstHalfHandlers, halfKey)
			}
		}
		set.mu.Unlock()
	}()
}

// SetUpOneTimeHandler sets up a one-time handler for a given TcpKey.
// After timeout has passed, the handler is discarded.
func (set *OneTimeStreamHandler) SetUpOneTimeHandler(key TcpKey, handler StreamHandler, timeout time.Duration) {
	set.mu.Lock()
	if waiting, ok := set.waiting[key]; ok {
		delete(set.waiting, key)
		select {
		case waiting <- handler:
		default:
		}
	} else {
		set.handlers[key] = &handler
	}
	set.mu.Unlock()

	// Schedule the removal of the handler at a later time.
	go func() {
		time.Sleep(timeout)
		set.mu.Lock()
		if h, ok := set.handlers[key]; ok && h == &handler {
			delete(set.handlers, key)
		}
		set.mu.Unlock()
	}()
}

// WaitForOneTimeHandler places a stream in a waiting state.
// If, during the given duration,
// a call to SetUp*Handler matches the given stream, that stream will
// be pulled out of waiting and handled.  After the given time, the stream
// is discarded.
func (set *OneTimeStreamHandler) WaitForOneTimeHandler(stream *Stream, timeout time.Duration) bool {
	handlerChan := make(chan StreamHandler, 1)
	src, dst := stream.Key.HalfKeys()

	// Store the stream as waiting.
	set.mu.Lock()
	set.waiting[stream.Key] = handlerChan
	set.waitingSrcHalf[src] = handlerChan
	set.waitingDstHalf[dst] = handlerChan
	set.mu.Unlock()

	// Wait for a handler to be sent to us.
	timer := make(chan bool, 1)
	go func() { time.Sleep(timeout); timer <- true }()
	var handler StreamHandler
	select {
	case <-timer:
	case handler = <-handlerChan:
	}

	// Remove the stream from waiting state.
	set.mu.Lock()
	if w, ok := set.waiting[stream.Key]; ok && w == handlerChan {
		delete(set.waiting, stream.Key)
	}
	if w, ok := set.waitingSrcHalf[src]; ok && w == handlerChan {
		delete(set.waitingSrcHalf, src)
	}
	if w, ok := set.waitingDstHalf[dst]; ok && w == handlerChan {
		delete(set.waitingDstHalf, dst)
	}
	set.mu.Unlock()

	// If we got a handler, run it, otherwise ignore the stream and return.
	if handler != nil {
		handler.HandleStream(stream)
		return true
	}
	return false
}

// WaitForOneTimeHandler returns a call to WaitForOneTimeHandler as a
// MaybeStreamHandler, so it can be passed into a StreamHandlerSet.
// The returned handler should should be the last handler placed into the set,
// since it always returns true.
func (set *OneTimeStreamHandler) WaitingStreamHandler(timeout time.Duration) MaybeStreamHandler {
	return MaybeStreamHandlerFunction(func(stream *Stream) bool {
		return set.WaitForOneTimeHandler(stream, timeout)
	})
}
