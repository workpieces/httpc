/*
Copyright 2022 The Workpieces LLC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package httpc

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/workpieces/log"
)

// ClientOptFn are options to set different parameters on the Client.
type ClientOptFn func(*clientOpt) error

type clientOpt struct {
	addr               string
	log                log.Logger
	insecureSkipVerify bool
	doer               doer
	headers            http.Header
	authFn             func(*http.Request) error
	respFn             func(*http.Response) error
	statusFn           func(*http.Response) error
	writerFns          []WriteCloserFn
}

// WithAddr sets the host address on the client.
func WithAddr(addr string) ClientOptFn {
	return func(opt *clientOpt) error {
		opt.addr = addr
		return nil
	}
}

// WithLogger sets the host address on the client.
func WithLogger(log log.Logger) ClientOptFn {
	return func(opt *clientOpt) error {
		opt.log = log
		return nil
	}
}

// WithAuth provides a means to set a custom auth that doesn't match
// the provided auth types here.
func WithAuth(fn func(r *http.Request) error) ClientOptFn {
	return func(opt *clientOpt) error {
		opt.authFn = fn
		return nil
	}
}

// WithAuthToken provides token auth for requests.
func WithAuthToken(token string) ClientOptFn {
	return WithAuth(func(r *http.Request) error {
		r.Header.Set("Authorization", "Token "+token)
		return nil
	})
}

// WithAuthBasic provides basic auth for requests.
func WithAuthBasic(token string) ClientOptFn {
	return WithAuth(func(r *http.Request) error {
		r.Header.Set("Authorization", "Basic "+token)
		return nil
	})
}

// WithSessionCookie provides cookie auth for requests to mimic the browser.
// Typically, session is influxdb.Session.Key.
func WithSessionCookie(session string) ClientOptFn {
	// TODO WithAuth call http request, authentication here will be modified.
	//  request cookie will be change.
	return WithAuth(func(r *http.Request) error {
		r.AddCookie(&http.Cookie{
			Name:  "session",
			Value: session,
		})

		return nil
	})
}

// WithContentType sets the content type that will be applied to the requests created
// by the Client.
func WithContentType(ct string) ClientOptFn {
	return WithHeader(headerContentType, ct)
}

func withDoer(d doer) ClientOptFn {
	return func(opt *clientOpt) error {
		opt.doer = d
		return nil
	}
}

// WithHeader sets a default header that will be applied to all requests created
// by the client.
func WithHeader(header, val string) ClientOptFn {
	return func(opt *clientOpt) error {
		if opt.headers == nil {
			opt.headers = make(http.Header)
		}
		opt.headers.Add(header, val)
		return nil
	}
}

// WithUserAgentHeader sets the user agent for the http client requests.
func WithUserAgentHeader(userAgent string) ClientOptFn {
	return WithHeader("User-Agent", userAgent)
}

// WithHTTPClient sets the raw http client on the httpc Client.
func WithHTTPClient(c *http.Client) ClientOptFn {
	return func(opt *clientOpt) error {
		opt.doer = c
		return nil
	}
}

// WithInsecureSkipVerify sets the insecure skip verify on the http client's htp transport.
func WithInsecureSkipVerify(b bool) ClientOptFn {
	return func(opts *clientOpt) error {
		opts.insecureSkipVerify = b
		return nil
	}
}

// WithRespFn sets the default resp fn for the client that will be applied to all requests
// generated from it.
func WithRespFn(fn func(*http.Response) error) ClientOptFn {
	return func(opt *clientOpt) error {
		opt.respFn = fn
		return nil
	}
}

// WithStatusFn sets the default status fn for the client that will be applied to all requests
// generated from it.
func WithStatusFn(fn func(*http.Response) error) ClientOptFn {
	return func(opt *clientOpt) error {
		opt.statusFn = fn
		return nil
	}
}

// WithWriterFn applies the provided writer behavior to all the request bodies'
// generated from the client.
func WithWriterFn(fn WriteCloserFn) ClientOptFn {
	return func(opt *clientOpt) error {
		opt.writerFns = append(opt.writerFns, fn)
		return nil
	}
}

// WithWriterGZIP gzips the request body generated from this client.
func WithWriterGZIP() ClientOptFn {
	return WithWriterFn(func(w io.WriteCloser) (string, string, io.WriteCloser) {
		return headerContentEncoding, "gzip", gzip.NewWriter(w)
	})
}

// DefaultTransportInsecure is identical to http.DefaultTransport, with
// the exception that tls.Config is configured with InsecureSkipVerify
// set to true.
var DefaultTransportInsecure http.RoundTripper = &http.Transport{
	Proxy:                 http.ProxyFromEnvironment,
	DialContext:           dialContext,
	ForceAttemptHTTP2:     true,
	MaxIdleConns:          100,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
	TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true,
	},
}

func dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d := net.Dialer{
		Timeout:   5 * time.Minute,
		KeepAlive: 5 * time.Minute,
		DualStack: true,
	}
	return d.Dial(network, addr)
}

func defaultHTTPClient(scheme string, insecure bool) *http.Client {
	if scheme == "https" && insecure {
		return &http.Client{Transport: DefaultTransportInsecure}
	}
	return &http.Client{Transport: http.DefaultTransport}
}
