package oauther

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/bobg/errors"
	"github.com/bobg/mid"
	"github.com/pkg/browser"
	"golang.org/x/oauth2"
)

//go:embed done.html
var doneHTML []byte

const codebytes = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"

// DoLoopback does loopback authorization.
// The user's browser is opened on a specially constructed URL,
// and an HTTP server is spun up on a port on localhost.
// If the user grants access via the browser flow,
// a callback request containing an authorization code is sent to the localhost server,
// which exchanges the code for an OAuth token.
//
// For details, see https://developers.google.com/identity/protocols/oauth2/native-app#obtainingaccesstokens.
func doLoopback(ctx context.Context, conf *oauth2.Config) (*oauth2.Token, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, errors.Wrap(err, "creating listener")
	}
	defer listener.Close()

	// TODO: Use crypto/rand instead of math/rand. Es más macho.
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))

	var codeVerifier, state [64]byte
	for i := 0; i < 64; i++ {
		r := rnd.Intn(len(codebytes))
		codeVerifier[i] = codebytes[r]
		r = rnd.Intn(len(codebytes))
		state[i] = codebytes[r]
	}
	var (
		cvhash   = sha256.Sum256(codeVerifier[:])
		cvbase64 = base64.RawURLEncoding.EncodeToString(cvhash[:])
	)

	var (
		tok  *oauth2.Token
		done = make(chan struct{})
	)

	var (
		srv  *http.Server
		once sync.Once
	)
	srv = &http.Server{
		Handler: mid.Err(func(w http.ResponseWriter, req *http.Request) error {
			switch req.URL.Path {
			case "", "/":
				// do nothing
			default:
				// e.g. /favicon.ico
				return mid.CodeErr{C: http.StatusNotFound}
			}

			defer once.Do(func() { close(done) })

			if errorstr := req.FormValue("error"); errorstr != "" {
				return mid.CodeErr{
					C:   http.StatusUnauthorized,
					Err: errors.New(errorstr),
				}
			}

			code := req.FormValue("code")
			if code == "" {
				return fmt.Errorf("no value for code (or error)")
			}

			gotState := req.FormValue("state")
			if gotState != string(state[:]) {
				return mid.CodeErr{
					C:   http.StatusUnauthorized,
					Err: fmt.Errorf("state mismatch"),
				}
			}

			conf2 := *conf
			conf2.RedirectURL = "http://" + listener.Addr().String()

			tok, err = conf2.Exchange(
				ctx,
				code,
				oauth2.SetAuthURLParam("code_verifier", string(codeVerifier[:])),
			)
			if err != nil {
				return mid.CodeErr{
					C:   http.StatusUnauthorized,
					Err: err,
				}
			}

			http.ServeContent(w, req, "done.html", time.Time{}, bytes.NewReader(doneHTML))

			return nil
		}),
	}

	go srv.Serve(listener)
	defer srv.Shutdown(ctx)

	v := url.Values{}
	v.Set("client_id", conf.ClientID)
	v.Set("redirect_uri", "http://"+listener.Addr().String())
	v.Set("response_type", "code")
	v.Set("scope", strings.Join(conf.Scopes, " "))
	v.Set("code_challenge", cvbase64)
	v.Set("code_challenge_method", "S256")
	v.Set("state", string(state[:]))

	u, err := url.Parse(conf.Endpoint.AuthURL)
	if err != nil {
		return nil, errors.Wrapf(err, "parsing auth URL %s", conf.Endpoint.AuthURL)
	}
	u.RawQuery = v.Encode()

	if err = browser.OpenURL(u.String()); err != nil {
		return nil, errors.Wrapf(err, "opening browser on %s", conf.Endpoint.AuthURL)
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-done:
		if tok == nil {
			return nil, fmt.Errorf("no token")
		}
		return tok, nil
	}
}
