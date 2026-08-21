//go:build linux && nestwg_integration

package engine

import (
	"fmt"
	"os"
	"strings"
)

func init() {
	runtimeFailpoint = func(point string) error {
		for _, configured := range strings.Split(os.Getenv("NESTWG_FAILPOINT"), ",") {
			if configured == point {
				return fmt.Errorf("integration failure at %s", point)
			}
		}
		return nil
	}
}
