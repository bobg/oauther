package oauther

import (
	"context"
	"encoding/json"
	"net/http"
	"os"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// TokenSrc is a source of OAuth tokens.
type TokenSrc interface {
	Get(context.Context, *oauth2.Config) (*oauth2.Token, error)
}

// Convert converts a TokenSrc to an oauth2.TokenSource
func Convert(src TokenSrc, ctx context.Context, conf *oauth2.Config) oauth2.TokenSource {
	return &converted{
		src:  src,
		ctx:  ctx,
		conf: conf,
	}
}

type converted struct {
	src  TokenSrc
	ctx  context.Context
	conf *oauth2.Config
}

func (c *converted) Token() (*oauth2.Token, error) {
	return c.src.Get(c.ctx, c.conf)
}

// HTTPClient produces a *http.Client with OAuth authorization based on creds (source of JSON-encoded OAuth credentials) and scope.
func HTTPClient(ctx context.Context, creds []byte, src TokenSrc, scope ...string) (*http.Client, error) {
	config, err := google.ConfigFromJSON(creds, scope...)
	if err != nil {
		return nil, err
	}
	var tok *oauth2.Token
	tok, err = src.Get(ctx, config)
	if err != nil {
		return nil, err
	}
	return config.Client(ctx, tok), nil
}

type websrc struct {
	authCodeFn func(string) (string, error)
}

func (w websrc) Get(ctx context.Context, conf *oauth2.Config) (*oauth2.Token, error) {
	url := conf.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	code, err := w.authCodeFn(url)
	if err != nil {
		return nil, err
	}
	return conf.Exchange(ctx, code)
}

// NewWebTokenSrc produces a TokenSrc that converts a config+URL into a token.
// It requires a function that takes a URL and retrieves an auth code string from there.
//
// Note, the URL typically requires human interaction to authorize issuance of the code.
// A simple version of the function is therefore something like this:
//
//   func(url string) (string, error) {
//     fmt.Printf("Get an auth code from the following URL, then enter it here:\n%s\n", url)
//     var code string
//     _, err := fmt.Scan(&code)
//     return code, err
//   }
func NewWebTokenSrc(authCodeFn func(string) (string, error)) TokenSrc {
	return websrc{authCodeFn: authCodeFn}
}

type codeSrc struct {
	src  TokenSrc
	code string
}

func (c codeSrc) Get(ctx context.Context, conf *oauth2.Config) (*oauth2.Token, error) {
	if c.code != "" {
		return conf.Exchange(ctx, c.code)
	}
	return c.src.Get(ctx, conf)
}

// NewCodeTokenSrc produces a TokenSrc that produces an oauth token from the given auth code if it's non-empty,
// falling back to the next TokenSrc otherwise.
func NewCodeTokenSrc(src TokenSrc, code string) TokenSrc {
	return codeSrc{src: src, code: code}
}

type filecache struct {
	src      TokenSrc
	filename string
}

// Get implements TokenSrc.
func (fc filecache) Get(ctx context.Context, conf *oauth2.Config) (*oauth2.Token, error) {
	f, err := os.Open(fc.filename)
	if os.IsNotExist(err) {
		tok, err := fc.src.Get(ctx, conf)
		if err != nil {
			return nil, err
		}
		f, err := os.OpenFile(fc.filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		err = json.NewEncoder(f).Encode(tok)
		return tok, err
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	tok := new(oauth2.Token)
	err = json.NewDecoder(f).Decode(tok)
	return tok, err
}

// NewFileCache produces a TokenSrc that uses a named file as persistent storage and another TokenSrc for cache misses.
func NewFileCache(src TokenSrc, filename string) TokenSrc {
	return filecache{
		src:      src,
		filename: filename,
	}
}
