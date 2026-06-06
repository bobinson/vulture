module github.com/vulture/cli

go 1.24.0

require (
	github.com/vulture/backend v0.0.0
	golang.org/x/term v0.27.0
)

require golang.org/x/sys v0.38.0 // indirect

replace github.com/vulture/backend => ../backend
