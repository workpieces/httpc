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
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/workpieces/log"
)

const (
	headerContentType     = "Content-Type"
	headerContentEncoding = "Content-Encoding"
)

// Req is a request type.
type Req struct {
	client doer

	req    *http.Request
	log    log.Logger
	authFn func(*http.Request) error

	decodeFn func(*http.Response) error
	respFn   func(*http.Response) error
	statusFn func(*http.Response) error

	err error
}

// Accept sets the Accept header to the provided content type on the request.
func (r *Req) Accept(contentType string) *Req {
	return r.Header("Accept", contentType)
}

// Auth sets the authorization for a request.
func (r *Req) Auth(authFn func(r *http.Request) error) *Req {
	if r.err != nil {
		return r
	}
	r.authFn = authFn
	return r
}

// ContentType sets the Content-Type header to the provided content type on the request.
func (r *Req) ContentType(contentType string) *Req {
	return r.Header("Content-Type", contentType)
}

// Decode sets the decoding functionality for the request. All Decode calls are called
// after the status and response functions are called. Decoding will not happen if error
// encountered in the status check.
func (r *Req) Decode(fn func(resp *http.Response) error) *Req {
	if r.err != nil {
		return r
	}
	r.decodeFn = fn
	return r
}

// DecodeGob sets the decoding functionality to decode gob for the request.
func (r *Req) DecodeGob(v interface{}) *Req {
	return r.Decode(func(resp *http.Response) error {
		r := decodeReader(resp.Body, resp.Header)
		return gob.NewDecoder(r).Decode(v)
	})
}

// DecodeJSON sets the decoding functionality to decode json for the request.
func (r *Req) DecodeJSON(v interface{}) *Req {
	return r.Decode(func(resp *http.Response) error {
		r := decodeReader(resp.Body, resp.Header)
		return json.NewDecoder(r).Decode(v)
	})
}

// Header adds the header to the http request.
func (r *Req) Header(k, v string) *Req {
	if r.err != nil {
		return r
	}
	r.req.Header.Add(k, v)
	return r
}

// Headers adds all the headers to the http request.
func (r *Req) Headers(m map[string][]string) *Req {
	if r.err != nil {
		return r
	}
	for header, vals := range m {
		if header == "" {
			continue
		}
		for _, v := range vals {
			r = r.Header(header, v)
		}
	}
	return r
}

// QueryParams adds the query params to the http request.
func (r *Req) QueryParams(pairs map[string]string) *Req {
	if r.err != nil || len(pairs) == 0 {
		return r
	}
	params := r.req.URL.Query()
	for k, p := range pairs {
		params.Add(k, p)
	}
	r.req.URL.RawQuery = params.Encode()
	return r
}

// RespFn provides a means to inspect the entire http response. This function runs first
// before the status and decode functions are called.
func (r *Req) RespFn(fn func(*http.Response) error) *Req {
	r.respFn = fn
	return r
}

// StatusFn sets a status check function. This runs after the resp func
// but before the decode fn.
func (r *Req) StatusFn(fn func(*http.Response) error) *Req {
	r.statusFn = fn
	return r
}

// Do makes the HTTP request. Any errors that had been encountered in
// the lifetime of the Req type will be returned here first, in place of
// the call. This makes it safe to call Do at anytime.
func (r *Req) Do(ctx context.Context) error {
	if r.err != nil {
		return r.err
	}

	// TODO setting a cookie or session authentication is called here.
	//  take a attention to the later increase of permission authentication.
	if err := r.authFn(r.req); err != nil {
		return err
	}

	return r.do(ctx)
}

func (r *Req) do(ctx context.Context) error {
	u := r.req.URL

	r.log.
		WithField("scheme", u.Scheme).
		WithField("host", u.Host).
		WithField("path", u.Path).
		WithField("query_params", u.Query().Encode()).
		Info("request")

	resp, err := r.client.Do(r.req.WithContext(ctx))
	if err != nil {
		return err
	}

	defer func() {
		io.Copy(io.Discard, resp.Body) // drain body completely
		resp.Body.Close()
	}()

	if r.respFn != nil {
		if err := r.respFn(resp); err != nil {
			return err
		}
	}

	if r.statusFn != nil {
		if err := r.statusFn(resp); err != nil {
			return err
		}
	}

	if r.decodeFn != nil {
		if err := r.decodeFn(resp); err != nil {
			return err
		}
	}
	return nil
}

// StatusIn validates the status code matches one of the provided statuses.
func StatusIn(code int, rest ...int) func(*http.Response) error {
	return func(resp *http.Response) error {
		for _, code := range append(rest, code) {
			if code == resp.StatusCode {
				return nil
			}
		}
		return fmt.Errorf("received unexpected status: %s %d", resp.Status, resp.StatusCode)
	}
}

var encodingReaders = map[string]func(io.Reader) io.Reader{
	"gzip": func(r io.Reader) io.Reader {
		if gr, err := gzip.NewReader(r); err == nil {
			return gr
		}
		return r
	},
}

func decodeReader(r io.Reader, headers http.Header) io.Reader {
	contentEncoding := strings.TrimSpace(headers.Get(headerContentEncoding))
	fn, ok := encodingReaders[contentEncoding]
	if ok {
		return fn(r)
	}
	return r
}
