// Separate module on purpose: server-monitor is a standalone, zero-dependency
// diagnostic binary meant to be scp'd onto a production host. Keeping it out of
// the parent module means `go build ./...` / lint / vendor in the skywire repo
// never see it, and building it on a server needs no module cache at all.
module github.com/skycoin/skywire/server-monitor

go 1.22
