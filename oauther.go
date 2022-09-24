package oauther

import (
	"context"
	"encoding/json"
	"io/fs"
	"net/http"
	"os"

	"github.com/pkg/errors"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// OAuther is any type that can produce an OAuth2 token.
type OAuther interface {
	Token(context.Context) (*oauth2.Token, error)
}

// File is an OAuther that reads a token from a file.
type File struct {
	Filename string
	Next     OAuther
}

func (a File) Token(ctx context.Context) (*oauth2.Token, error) {
	f, err := os.Open(a.Filename)
	if errors.Is(err, fs.ErrNotExist) {
		return a.doNext(ctx)
	}
	if err != nil {
		return nil, errors.Wrapf(err, "opening %s", a.Filename)
	}
	defer f.Close()

	var tok oauth2.Token
	if err = json.NewDecoder(f).Decode(&tok); err != nil {
		return nil, errors.Wrapf(err, "decoding token in %s", a.Filename)
	}
	if !tok.Valid() {
		return a.doNext(ctx)
	}
	return &tok, nil
}

func (a File) doNext(ctx context.Context) (*oauth2.Token, error) {
	tok, err := a.Next.Token(ctx)
	if err != nil {
		return nil, err
	}

	f, err := os.OpenFile(a.Filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0400)
	if err != nil {
		return nil, errors.Wrapf(err, "opening %s for writing", a.Filename)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ") // because why not
	if err = enc.Encode(tok); err != nil {
		return nil, errors.Wrap(err, "JSON-encoding token")
	}

	err = f.Close()
	return tok, errors.Wrapf(err, "storing file %s", a.Filename)
}

// Token obtains an oauth2 token from the given filename.
// If the file does not exist,
// or the token is invalid
// (e.g. expired),
// Token does "loopback auth" in the user's browser,
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
	a := File{
		Filename: filename,
		Next: Loopback{
			Conf:   conf,
			Scopes: scope,
		},
	}
	tok, err := a.Token(ctx)
	return tok, conf, err
}
