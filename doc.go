// Package oauthhelp encapsulates common OAuth patterns for Google data APIs.
//
// The caller will typically have a JSON-encoded credentials file and want an OAuth-authorized *http.Client.
// Usage in that case is:
//
//   creds, err := os.Open("credentials.json")
//   if err != nil { ... }
//   defer credsFile.Close()
//   src := oauthhelp.NewWebTokenSrc(interact)
//   src = oauthhelp.NewFileCache(src, "token.json") // optional file caching of the token from NewWebTokenSrc
//   client, err := oauthhelp.HTTPClient(ctx, creds, src, people.ContactsScope)
//   if err != nil { ... }
//
// where interact is a function that takes a URL,
// sends the user to that URL,
// waits for the user to report the authcode produced by that URL,
// then returns that authcode as a string.
package oauthhelp
