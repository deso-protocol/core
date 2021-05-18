// Go support for leveled logs, analogous to https://code.google.com/p/google-glog/
//
// Copyright 2013 Google Inc. All Rights Reserved.
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

// File I/O for logs.

package glog

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// MaxSize is the maximum size of a log file in bytes.
var MaxSize uint64 = 1024 * 1024 * 1800

// logName returns a new log file name containing tag, with start time t, and
// the name for the symlink for tag.
func tstampDirName(t time.Time) string {
	return fmt.Sprintf("%s.%s.%s.log.%04d%02d%02d-%02d%02d%02d.%d",
		program,
		host,
		userName,
		t.Year(),
		t.Month(),
		t.Day(),
		t.Hour(),
		t.Minute(),
		t.Second(),
		pid)
}

// create creates a new log file and returns the file and its filename, which
// contains tag ("INFO", "FATAL", etc.) and t.  If the file is created
// successfully, create also attempts to update the symlink for that tag, ignoring
// errors.
func (ll *loggingT) create(tag string, t time.Time) (f *os.File, filename string, err error) {
	// Create the log directory.
	if err := os.MkdirAll(string(ll.logDir), os.ModePerm); err != nil {
		return nil, "", err
	}

	nn := fmt.Sprintf("%s_%s", tag, tstampDirName(t))
	fname := filepath.Join(string(ll.logDir), nn)
	f, err = os.Create(fname)
	if err != nil {
		return nil, "", fmt.Errorf("log: cannot create log: %v", err)
	}
	symlink := filepath.Join(string(ll.logDir), tag)
	os.Remove(symlink)      // ignore err
	os.Symlink(nn, symlink) // ignore err
	return f, fname, nil
}
