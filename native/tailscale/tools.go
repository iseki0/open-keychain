//go:build tools

package tailagent

// Keep the gomobile binding support module pinned for reproducible AAR builds.
import _ "golang.org/x/mobile/bind"
