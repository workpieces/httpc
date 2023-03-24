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
	"context"
	"github.com/stretchr/testify/require"
	"io"
	"net/http"
	"testing"
)

func TestClientManyHeaders(t *testing.T) {
	newClient := func(addr string, opts ...ClientOptFn) *Client {
		client, err := New(append(opts, WithAddr(addr))...)
		require.NoError(t, err)
		return client
	}

	var html string
	htmlResp := func(resp *http.Response) error {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		html = string(body)
		return nil
	}

	err := newClient(
		"http://www.jyeoo.com",
		WithContentType("application/x-www-form-urlencoded"),
		WithSessionCookie("test-1"),
		WithUserAgentHeader("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36"),
		WithInsecureSkipVerify(false)).
		Get("/math/ques/search").
		Accept("*/*").
		RespFn(htmlResp).
		StatusFn(StatusIn(http.StatusOK)).
		Do(context.TODO())

	require.NoError(t, err)
	require.NotEmpty(t, html)
}

func TestClientCookie(t *testing.T) {
	newClient := func(addr string, opts ...ClientOptFn) *Client {
		client, err := New(append(opts, WithAddr(addr))...)
		require.NoError(t, err)
		return client
	}

	var html string
	htmlResp := func(resp *http.Response) error {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		html = string(body)
		return nil
	}

	err := newClient(
		"http://www.jyeoo.com",
		WithContentType("application/x-www-form-urlencoded"),
		WithUserAgentHeader("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36"),
		WithInsecureSkipVerify(false)).
		Get("/math/ques/search").
		Accept("*/*").
		Auth(func(r *http.Request) error {
			r.AddCookie(&http.Cookie{
				Name:  "k1",
				Value: "v1",
			})
			r.AddCookie(&http.Cookie{
				Name:  "k2",
				Value: "v2",
			})
			return nil
		}).
		RespFn(htmlResp).
		StatusFn(StatusIn(http.StatusOK)).
		Do(context.TODO())

	require.NoError(t, err)
	require.NotEmpty(t, html)
}

func httpClient(scheme string, insecure bool) *http.Client {
	if scheme == "https" && insecure {
		return &http.Client{Transport: DefaultTransportInsecure}
	}
	return &http.Client{Transport: http.DefaultTransport}
}
