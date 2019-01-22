// Copyright (C) 2015 Audrius Butkevicius and Contributors (see the CONTRIBUTORS file).

package client

import (
	"os"
	"strings"

	"github.com/dappbox/dappbox/lib/logger"
)

var (
	l = logger.DefaultLogger.NewFacility("relay", "")
)

func init() {
	l.SetDebug("relay", strings.Contains(os.Getenv("STTRACE"), "relay") || os.Getenv("STTRACE") == "all")
}
