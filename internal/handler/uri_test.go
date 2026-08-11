package handler

import "testing"

func TestURIRoundTrip(t *testing.T) {
	for _, path := range []string{
		"/home/owen/code/main.tf",
		"/tmp/dir with spaces/main.tf",
		"/tmp/hash#name/a+b.tf",
	} {
		uri := pathToURI(path)

		got, ok := uriToPath(uri)
		if !ok {
			t.Errorf("uriToPath(%q) failed", uri)
			continue
		}
		if got != path {
			t.Errorf("round trip of %q via %q gave %q", path, uri, got)
		}
	}
}

func TestURIToPathRejectsNonFileSchemes(t *testing.T) {
	for _, uri := range []string{"https://example.com/x", "untitled:Untitled-1", ""} {
		if _, ok := uriToPath(lspURI(uri)); ok {
			t.Errorf("uriToPath(%q) should have been rejected", uri)
		}
	}
}

func TestPathToURIHasFileScheme(t *testing.T) {
	if got := pathToURI("/tmp/main.tf"); got != "file:///tmp/main.tf" {
		t.Errorf("got %q", got)
	}
}
