// The following code is AUTO-GENERATED. Please DO NOT edit.
// To update this generated code, run `go generate` in the
// clients/client-go/codegenerator/model subdirectory of the
// taskcluster git repository.

// This package was generated from the reference schema of
// the Secrets service, which is also published here:
//
//   * ${TASKCLUSTER_ROOT_URL}/references/secrets/v1/api.json
//
// where ${TASKCLUSTER_ROOT_URL} points to the root URL of
// your taskcluster deployment.

// The secrets service provides a simple key/value store for small bits of secret
// data.  Access is limited by scopes, so values can be considered secret from
// those who do not have the relevant scopes.
//
// Secrets also have an expiration date, and once a secret has expired it can no
// longer be read.  This is useful for short-term secrets such as a temporary
// service credential or a one-time signing key.
//
// See:
//
// # How to use this package
//
// First create a Secrets object:
//
//	secrets := tcsecrets.New(nil)
//
// and then call one or more of secrets's methods, e.g.:
//
//	err := secrets.Ping(.....)
//
// handling any errors...
//
//	if err != nil {
//		// handle error...
//	}
//
// # Taskcluster Schema
//
// The source code of this go package was auto-generated from the API definition at
// <rootUrl>/references/secrets/v1/api.json together with the input and output schemas it references,
package tcsecrets

import (
	"net/url"
	"time"

	tcclient "github.com/taskcluster/taskcluster/v88/clients/client-go"
)

type Secrets tcclient.Client

// New returns a Secrets client, configured to run against production. Pass in
// nil credentials to create a client without authentication. The
// returned client is mutable, so returned settings can be altered.
//
//	secrets := tcsecrets.New(
//	    nil,                                      // client without authentication
//	    "http://localhost:1234/my/taskcluster",   // taskcluster hosted at this root URL on local machine
//	)
//	err := secrets.Ping(.....)                    // for example, call the Ping(.....) API endpoint (described further down)...
//	if err != nil {
//		// handle errors...
//	}
func New(credentials *tcclient.Credentials, rootURL string) *Secrets {
	return &Secrets{
		Credentials:  credentials,
		RootURL:      rootURL,
		ServiceName:  "secrets",
		APIVersion:   "v1",
		Authenticate: credentials != nil,
	}
}

// NewFromEnv returns a *Secrets configured from environment variables.
//
// The root URL is taken from TASKCLUSTER_PROXY_URL if set to a non-empty
// string, otherwise from TASKCLUSTER_ROOT_URL if set, otherwise the empty
// string.
//
// The credentials are taken from environment variables:
//
//	TASKCLUSTER_CLIENT_ID
//	TASKCLUSTER_ACCESS_TOKEN
//	TASKCLUSTER_CERTIFICATE
//
// If TASKCLUSTER_CLIENT_ID is empty/unset, authentication will be
// disabled.
func NewFromEnv() *Secrets {
	c := tcclient.CredentialsFromEnvVars()
	rootURL := tcclient.RootURLFromEnvVars()
	return &Secrets{
		Credentials:  c,
		RootURL:      rootURL,
		ServiceName:  "secrets",
		APIVersion:   "v1",
		Authenticate: c.ClientID != "",
	}
}

// Respond without doing anything.
// This endpoint is used to check that the service is up.
//
// See #ping
func (secrets *Secrets) Ping() error {
	cd := tcclient.Client(*secrets)
	_, _, err := (&cd).APICall(nil, "GET", "/ping", nil, nil)
	return err
}

// Respond without doing anything.
// This endpoint is used to check that the service is up.
//
// See #lbheartbeat
func (secrets *Secrets) Lbheartbeat() error {
	cd := tcclient.Client(*secrets)
	_, _, err := (&cd).APICall(nil, "GET", "/__lbheartbeat__", nil, nil)
	return err
}

// Respond with the JSON version object.
// https://github.com/mozilla-services/Dockerflow/blob/main/docs/version_object.md
//
// See #version
func (secrets *Secrets) Version() error {
	cd := tcclient.Client(*secrets)
	_, _, err := (&cd).APICall(nil, "GET", "/__version__", nil, nil)
	return err
}

// Set the secret associated with some key.  If the secret already exists, it is
// updated instead.
//
// Required scopes:
//
//	secrets:set:<name>
//
// See #set
func (secrets *Secrets) Set(name string, payload *Secret) error {
	cd := tcclient.Client(*secrets)
	_, _, err := (&cd).APICall(payload, "PUT", "/secret/"+url.QueryEscape(name), nil, nil)
	return err
}

// Delete the secret associated with some key. It will succeed whether or not the secret exists
//
// Required scopes:
//
//	secrets:set:<name>
//
// See #remove
func (secrets *Secrets) Remove(name string) error {
	cd := tcclient.Client(*secrets)
	_, _, err := (&cd).APICall(nil, "DELETE", "/secret/"+url.QueryEscape(name), nil, nil)
	return err
}

// Read the secret associated with some key.  If the secret has recently
// expired, the response code 410 is returned.  If the caller lacks the
// scope necessary to get the secret, the call will fail with a 403 code
// regardless of whether the secret exists.
//
// Required scopes:
//
//	secrets:get:<name>
//
// See #get
func (secrets *Secrets) Get(name string) (*Secret, error) {
	cd := tcclient.Client(*secrets)
	responseObject, _, err := (&cd).APICall(nil, "GET", "/secret/"+url.QueryEscape(name), new(Secret), nil)
	return responseObject.(*Secret), err
}

// Returns a signed URL for Get, valid for the specified duration.
//
// Required scopes:
//
//	secrets:get:<name>
//
// See Get for more details.
func (secrets *Secrets) Get_SignedURL(name string, duration time.Duration) (*url.URL, error) {
	cd := tcclient.Client(*secrets)
	return (&cd).SignedURL("/secret/"+url.QueryEscape(name), nil, duration)
}

// List the names of all secrets.
//
// By default this end-point will try to return up to 1000 secret names in one
// request. But it **may return less**, even if more tasks are available.
// It may also return a `continuationToken` even though there are no more
// results. However, you can only be sure to have seen all results if you
// keep calling `listTaskGroup` with the last `continuationToken` until you
// get a result without a `continuationToken`.
//
// If you are not interested in listing all the members at once, you may
// use the query-string option `limit` to return fewer.
//
// Required scopes:
//
//	secrets:list-secrets
//
// See #list
func (secrets *Secrets) List(continuationToken, limit string) (*SecretsList, error) {
	v := url.Values{}
	if continuationToken != "" {
		v.Add("continuationToken", continuationToken)
	}
	if limit != "" {
		v.Add("limit", limit)
	}
	cd := tcclient.Client(*secrets)
	responseObject, _, err := (&cd).APICall(nil, "GET", "/secrets", new(SecretsList), v)
	return responseObject.(*SecretsList), err
}

// Returns a signed URL for List, valid for the specified duration.
//
// Required scopes:
//
//	secrets:list-secrets
//
// See List for more details.
func (secrets *Secrets) List_SignedURL(continuationToken, limit string, duration time.Duration) (*url.URL, error) {
	v := url.Values{}
	if continuationToken != "" {
		v.Add("continuationToken", continuationToken)
	}
	if limit != "" {
		v.Add("limit", limit)
	}
	cd := tcclient.Client(*secrets)
	return (&cd).SignedURL("/secrets", v, duration)
}

// Respond with a service heartbeat.
//
// This endpoint is used to check on backing services this service
// depends on.
//
// See #heartbeat
func (secrets *Secrets) Heartbeat() error {
	cd := tcclient.Client(*secrets)
	_, _, err := (&cd).APICall(nil, "GET", "/__heartbeat__", nil, nil)
	return err
}
