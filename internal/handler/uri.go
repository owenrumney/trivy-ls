package handler

import (
	"net/url"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/owenrumney/go-lsp/lsp"
)

// uriToPath converts a file:// document URI to a local filesystem path.
func uriToPath(uri lsp.DocumentURI) (string, bool) {
	s := string(uri)
	if !strings.HasPrefix(s, "file://") {
		return "", false
	}

	parsed, err := url.Parse(s)
	if err != nil {
		return "", false
	}

	path := parsed.Path
	if runtime.GOOS == "windows" {
		// file:///C:/x parses with a leading slash that is not part of the path.
		path = strings.TrimPrefix(path, "/")
		path = filepath.FromSlash(path)
	}

	if path == "" {
		return "", false
	}
	return filepath.Clean(path), true
}

// pathToURI converts a local filesystem path to a file:// document URI.
func pathToURI(path string) lsp.DocumentURI {
	path = filepath.ToSlash(path)
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	u := url.URL{Scheme: "file", Path: path}
	return lsp.DocumentURI(u.String())
}
