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

// This file contains a simple logging library used throughout the rest of the library.

package gopcapreader

import (
	"flag"
	"log"
)

var loglevel *int = flag.Int("gopcapreader_log_level", 0, "The logging level to use with gopcapreader.  The default will log nothing from then internal gopcapreader client library.  Values up to 5 will log progressively more information")

const (
	logError    int = 1
	logWarning      = 2
	logInfo         = 3
	logDebug        = 4
	logPedantic     = 5
)

// A simple logging function, controlled by our logging flag.
func gplog(level int, v ...interface{}) {
	if level <= *loglevel {
		log.Print(v)
	}
}

// A simple logging function, controlled by our logging flag.
func gplogf(level int, format string, v ...interface{}) {
	if level <= *loglevel {
		log.Printf(format, v)
	}
}
