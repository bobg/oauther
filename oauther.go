// Package oauther encapsulates common OAuth patterns for Google data APIs.
package oauther

import (
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"os"

	"github.com/bobg/errors"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// Token obtains an oauth2 token from the given filename.
// If the file does not exist,
// or the token is invalid
// (e.g. expired),
// Token first tries to refresh the token (if applicable)
// and falls back to doing "loopback auth" in the user's browser,
// storing the resulting token in the named file on success
// before returning it.
// Creds are the bytes of a JSON credentials file.
func Token(ctx context.Context, filename string, creds []byte, scope ...string) (*oauth2.Token, error) {
	tok, _, err := getToken(ctx, filename, creds, scope...)
	return tok, err
}

// Client obtains an oauth2-authorized HTTP client.
// Arguments are the same as for [Token],
// and authorization works the same way.
func Client(ctx context.Context, filename string, creds []byte, scope ...string) (*http.Client, error) {
	tok, conf, err := getToken(ctx, filename, creds, scope...)
	if err != nil {
		return nil, err
	}
	return conf.Client(ctx, tok), nil
}

func getToken(ctx context.Context, filename string, creds []byte, scope ...string) (*oauth2.Token, *oauth2.Config, error) {
	conf, err := google.ConfigFromJSON(creds, scope...)
	if err != nil {
		return nil, nil, errors.Wrap(err, "parsing credentials")
	}

	f, err := os.Open(filename)
	if errors.Is(err, fs.ErrNotExist) {
		tok, err := getToken2(ctx, conf, nil, filename)
		return tok, conf, err
	}
	if err != nil {
		return nil, nil, errors.Wrapf(err, "opening %s", filename)
	}
	defer f.Close()

	tok := new(oauth2.Token)
	if err = json.NewDecoder(f).Decode(tok); err != nil {
		return nil, nil, errors.Wrapf(err, "decoding token in %s", filename)
	}
	if !tok.Valid() {
		tok, err = getToken2(ctx, conf, tok, filename)
		return tok, conf, err
	}
	return tok, conf, nil
}

func getToken2(ctx context.Context, conf *oauth2.Config, expiredtok *oauth2.Token, filename string) (tok *oauth2.Token, err error) {
	defer func() {
		if err != nil {
			return
		}

		var f io.WriteCloser
		f, err = os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			err = errors.Wrapf(err, "opening %s for writing", filename)
			return
		}
		defer f.Close()

		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ") // because why not
		if err = enc.Encode(tok); err != nil {
			err = errors.Wrap(err, "JSON-encoding token")
			return
		}
	}()

	tok, err = conf.TokenSource(ctx, expiredtok).Token()
	if err == nil { // sic
		return tok, nil
	}

	return doLoopback(ctx, conf)
}
