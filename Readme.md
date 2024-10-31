# OAuther

[![Go Reference](https://pkg.go.dev/badge/github.com/bobg/oauther/v5.svg)](https://pkg.go.dev/github.com/bobg/oauther/v5)
[![Go Report Card](https://goreportcard.com/badge/github.com/bobg/oauther/v5)](https://goreportcard.com/report/github.com/bobg/oauther/v5)

This package contains convenience wrappers for Google’s OAuth library,
and an implementation of [loopback authorization](https://developers.google.com/identity/protocols/oauth2/native-app#redirect-uri_loopback),
in which a specially formatted request to Google’s authentication service
redirects to a web server running locally to verify an auth challenge.
