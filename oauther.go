package oauther

import (
	"context"
	"encoding/json"
	"net/http"
	"os"

	"github.com/pkg/errors"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// Token obtains an oauth2 token.
// It first tries to read it from filename
// (if filename is not "").
// If that fails,
// it tries to exchange authcode for one
// (if authcode is not ""),
// then stores the token in filename
// (if filename is not "").
// If that fails,
// it returns an ErrNeedAuthCode,
// which contains the URL where the user can interactively obtain a new authcode
// (which can then be passed to a retry of this function).
func Token(ctx context.Context, filename, authcode string, creds []byte, scope ...string) (*oauth2.Token, error) {
	tok, _, err := helper(ctx, filename, authcode, creds, scope...)
	return tok, err
}

// Client obtains an oauth2-authorized HTTP client.
// It is called in the same way as Token and may also produce an ErrNeedAuthCode error.
// See Token for more information.
func Client(ctx context.Context, filename, authcode string, creds []byte, scope ...string) (*http.Client, error) {
	tok, conf, err := helper(ctx, filename, authcode, creds, scope...)
	if err != nil {
		return nil, err
	}
	if conf == nil {
		conf, err = google.ConfigFromJSON(creds, scope...)
		if err != nil {
			return nil, errors.Wrap(err, "reading oauth config")
		}
	}
	return conf.Client(ctx, tok), nil
}

func helper(ctx context.Context, filename, authcode string, creds []byte, scope ...string) (*oauth2.Token, *oauth2.Config, error) {
	var (
		tok *oauth2.Token
		err error
	)

	if filename != "" {
		tok, err = tryFile(filename)
		if tok != nil && err == nil {
			return tok, nil, nil
		}
		if !os.IsNotExist(err) {
			return nil, nil, errors.Wrapf(err, "opening %s", filename)
		}
	}

	conf, err := google.ConfigFromJSON(creds, scope...)
	if err != nil {
		return nil, nil, errors.Wrap(err, "reading oauth config")
	}

	if authcode != "" {
		tok, err = conf.Exchange(ctx, authcode)
		if tok != nil && err == nil {
			if filename != "" {
				f, err := os.Create(filename)
				if err != nil {
					return nil, nil, errors.Wrapf(err, "opening %s for writing", filename)
				}
				defer f.Close()

				err = json.NewEncoder(f).Encode(tok)
				if err != nil {
					return nil, nil, errors.Wrapf(err, "writing %s", filename)
				}
			}
			return tok, conf, nil
		}
	}

	return nil, nil, ErrNeedAuthCode{URL: conf.AuthCodeURL("state-token", oauth2.AccessTypeOffline)}
}

func tryFile(filename string) (*oauth2.Token, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var tok oauth2.Token
	err = json.NewDecoder(f).Decode(&tok)
	return &tok, errors.Wrapf(err, "decoding token in %s", filename)
}

// ErrNeedAuthCode is the error returned by Token when the user must obtain an auth code.
// They can do this interactively at the URL contained in the error.
type ErrNeedAuthCode struct {
	// URL is the web address where the user can interactively obtain an auth code.
	// This can be used in a retry of the Token function.
	URL string
}

func (e ErrNeedAuthCode) Error() string {
	return "need auth code from " + e.URL
}
