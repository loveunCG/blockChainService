// Copyright (C) 2014 The Syncthing Authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

package discover

import (
	"os"
	"strings"

	"github.com/dappbox/dappbox/lib/logger"
)

var (
	l = logger.DefaultLogger.NewFacility("discover", "Remote device discovery")
)

func init() {
	l.SetDebug("discover", strings.Contains(os.Getenv("STTRACE"), "discover") || os.Getenv("STTRACE") == "all")
}
