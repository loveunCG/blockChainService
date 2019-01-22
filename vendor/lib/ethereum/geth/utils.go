package geth

import (
	"os"
	"fmt"
	"log"
	"path/filepath"
	"runtime"

	"github.com/dappbox/dappbox/lib/osutil"
)

func defaultConfigDir() string {
	switch runtime.GOOS {
	case "windows":
		if p := os.Getenv("LocalAppData"); p != "" {
			return filepath.Join(p, "DappBox")
		}
			return filepath.Join(os.Getenv("AppData"), "DappBox")

	case "darwin":
		dir, err := osutil.ExpandTilde("~/Library/Application Support/DappBox")
		if err != nil {
			log.Fatal(err)
		}
		return dir

	default:
		if xdgCfg := os.Getenv("XDG_CONFIG_HOME"); xdgCfg != "" {
			return filepath.Join(xdgCfg, "DappBox")
		}
		dir, err := osutil.ExpandTilde("~/.config/DappBox")
		if err != nil {
			log.Fatal(err)
		}
		return dir
	}
}

func dealwithErr(err error) {
  if err != nil {
    fmt.Println(err)
    panic(err)
  }
}
