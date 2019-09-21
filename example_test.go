package oauther_test

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"google.golang.org/api/gmail/v1"
	"google.golang.org/api/option"

	"github.com/bobg/oauther/v2"
)

func main() {
	var (
		credsFile = flag.String("creds", "creds.json", "path to credentials file")
		tokenFile = flag.String("token", "token.json", "path to token cache file")
		code      = flag.String("code", "", "auth code")
	)

	flag.Parse()

	creds, err := ioutil.ReadFile(*credsFile)
	if err != nil {
		log.Fatal(err)
	}
	tokSrc := oauther.NewWebTokenSrc(func(url string) (string, error) {
		return "", fmt.Errorf("get an auth code at %s, then rerun this program as %s -code <code>", url, strings.Join(os.Args, " "))
	})
	tokSrc = oauther.NewCodeTokenSrc(tokSrc, *code)
	tokSrc = oauther.NewFileCache(tokSrc, *tokenFile)

	ctx := context.Background()

	oauthClient, err := oauther.HTTPClient(ctx, creds, tokSrc, gmail.GmailInsertScope)
	if err != nil {
		log.Fatal(err)
	}

	_, err = gmail.NewService(ctx, option.WithHTTPClient(oauthClient))
	if err != nil {
		log.Fatal(err)
	}
}
