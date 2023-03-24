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
	"errors"
	"io"
	"net/http"
	"net/url"
	"path"

	"github.com/workpieces/log"
)

type (
	// WriteCloserFn is a White closer wrapper than indicates the type of writer by
	// returning the header and header value associated with the writer closer.
	//	i.e. GZIP writer returns header Content-Encoding with value gzip alongside
	//	the writer.
	WriteCloserFn func(closer io.WriteCloser) (string, string, io.WriteCloser)

	// doer provides an abstraction around the actual http client behavior. The doer
	// can be faked out in tests or another http client provided in its place.
	doer interface {
		Do(*http.Request) (*http.Response, error)
	}
)

// Client is a basic http client that can make cReqs without having to juggle
// the token and so forth. It provides sane defaults for checking response
// statuses, sets auth token when provided, and sets the content type to
// application/json for each request. The token, response checker, and
// content type can be overridden on the Req as well.
type Client struct {
	addr           url.URL
	log            log.Logger
	doer           doer
	defaultHeaders http.Header

	writerFns []WriteCloserFn

	authFn   func(*http.Request) error
	respFn   func(*http.Response) error
	statusFn func(*http.Response) error
}

// New creates a new httpc client.
func New(opts ...ClientOptFn) (*Client, error) {
	opt := clientOpt{
		authFn: func(*http.Request) error {
			return nil
		},
		log: log.NewNop(),
	}
	for _, o := range opts {
		if err := o(&opt); err != nil {
			return nil, err
		}
	}

	if opt.addr == "" {
		return nil, errors.New("must provide a non empty host address")
	}

	u, err := url.Parse(opt.addr)
	if err != nil {
		return nil, err
	}

	if opt.doer == nil {
		opt.doer = defaultHTTPClient(u.Scheme, opt.insecureSkipVerify)
	}

	return &Client{
		addr:           *u,
		log:            opt.log,
		doer:           opt.doer,
		defaultHeaders: opt.headers,
		authFn:         opt.authFn,
		statusFn:       opt.statusFn,
		writerFns:      opt.writerFns,
	}, nil
}

// Delete generates a DELETE request.
func (c *Client) Delete(urlPath ...string) *Req {
	return c.Req(http.MethodDelete, nil, urlPath...)
}

// Get generates a GET request.
func (c *Client) Get(urlPath ...string) *Req {
	return c.Req(http.MethodGet, nil, urlPath...)
}

// Patch generates a PATCH request.
func (c *Client) Patch(bFn BodyFn, urlPath ...string) *Req {
	return c.Req(http.MethodPatch, bFn, urlPath...)
}

// PatchJSON generates a PATCH request. This is to be used with value or pointer to value type.
// Providing a stream/reader will result in disappointment.
func (c *Client) PatchJSON(v interface{}, urlPath ...string) *Req {
	return c.Patch(BodyJSON(v), urlPath...)
}

// Post generates a POST request.
func (c *Client) Post(bFn BodyFn, urlPath ...string) *Req {
	return c.Req(http.MethodPost, bFn, urlPath...)
}

// PostJSON generates a POST request and json encodes the body. This is to be
// used with value or pointer to value type. Providing a stream/reader will result
// in disappointment.
func (c *Client) PostJSON(v interface{}, urlPath ...string) *Req {
	return c.Post(BodyJSON(v), urlPath...)
}

// Put generates a PUT request.
func (c *Client) Put(bFn BodyFn, urlPath ...string) *Req {
	return c.Req(http.MethodPut, bFn, urlPath...)
}

// PutJSON generates a PUT request. This is to be used with value or pointer to value type.
// Providing a stream/reader will result in disappointment.
func (c *Client) PutJSON(v interface{}, urlPath ...string) *Req {
	return c.Put(BodyJSON(v), urlPath...)
}

// Req constructs a request.
func (c *Client) Req(method string, bFn BodyFn, urlPath ...string) *Req {
	bodyF := BodyEmpty
	if bFn != nil {
		bodyF = bFn
	}

	headers := make(http.Header, len(c.defaultHeaders))
	for header, vals := range c.defaultHeaders {
		for _, v := range vals {
			headers.Add(header, v)
		}
	}
	var buf nopBufCloser
	var w io.WriteCloser = &buf
	for _, writerFn := range c.writerFns {
		header, headerVal, ww := writerFn(w)
		w = ww
		headers.Add(header, headerVal)
	}

	header, headerVal, err := bodyF(w)
	if err != nil {
		return &Req{
			err: err,
		}
	}
	if header != "" {
		headers.Set(header, headerVal)
	}
	// w.Close here is necessary since we have to close any gzip writer
	// or other writer that requires closing.
	if err := w.Close(); err != nil {
		return &Req{
			err: err,
		}
	}

	var body io.Reader
	if buf.Len() > 0 {
		body = &buf
	}

	req, err := http.NewRequest(method, c.buildURL(urlPath...), body)
	if err != nil {
		return &Req{
			err: err,
		}
	}

	cr := &Req{
		client:   c.doer,
		req:      req,
		log:      c.log,
		authFn:   c.authFn,
		respFn:   c.respFn,
		statusFn: c.statusFn,
	}
	return cr.Headers(headers)
}

// Clone creates a new *Client type from an existing client. This may be
// useful if you want to have a shared base client, then take a specific
// client from that base and tack on some extra goodies like specific headers
// and whatever else that suits you.
// Note: a new net.http.Client type will not be created. It will share the existing
// http.Client from the parent httpc.Client. Same connection pool, different specifics.
func (c *Client) Clone(opts ...ClientOptFn) (*Client, error) {
	existingOpts := []ClientOptFn{
		WithAuth(c.authFn),
		withDoer(c.doer),
		WithRespFn(c.respFn),
		WithStatusFn(c.statusFn),
	}
	for h, vals := range c.defaultHeaders {
		for _, v := range vals {
			existingOpts = append(existingOpts, WithHeader(h, v))
		}
	}
	for _, fn := range c.writerFns {
		existingOpts = append(existingOpts, WithWriterFn(fn))
	}

	return New(append(existingOpts, opts...)...)
}

func (c *Client) buildURL(urlPath ...string) string {
	u := c.addr
	if len(urlPath) > 0 {
		u.Path = path.Join(u.Path, path.Join(urlPath...))
	}
	return u.String()
}
