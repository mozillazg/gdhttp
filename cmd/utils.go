// Copyright © 2017 mozillazg
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package cmd

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	homedir "github.com/mitchellh/go-homedir"
)

var reJSONUnicode = regexp.MustCompile("\\\\u[a-z\\d]{4}")
var reQueryItem = regexp.MustCompile("^([^=]+)=($|[^=](.*)$)")
var reURLOnlyPort = regexp.MustCompile("^:\\d+")
var reURLHasScheme = regexp.MustCompile("^https?://")
var reURLFormat = regexp.MustCompile("^([^=]+)==(.*)$")

const queryItemFlag = "="
const formatItemFlag = "=="

type PositionalArgument struct {
	httpMethod   string
	uri          *url.URL
	requestItems []string
}

// 解析位置参数
func parsePositionalArguments(args []string) (p PositionalArgument, err error) {
	if len(args) < 1 {
		err = errors.New("too few arguments")
		return
	}

	p.httpMethod = http.MethodGet
	uriStr := ""
	p.requestItems = []string{}

	switch len(args) {
	case 1:
		uriStr = args[0]
	default:
		p.httpMethod = strings.ToUpper(args[0])
		if isValidMethod(p.httpMethod) {
			uriStr = args[1]
			p.requestItems = args[2:]
		} else {
			p.httpMethod = http.MethodGet
			uriStr = args[0]
			for _, item := range args[1:] {
				p.requestItems = append(p.requestItems, item)
			}
		}
	}

	p.uri, err = buildURL(uriStr, p.requestItems)
	if err != nil {
		return
	}
	return
}

// \\uXXXX -> \uXXXX 方便显示 json 中的中文
func replaceJSONUnicode(s string) string {
	s = reJSONUnicode.ReplaceAllStringFunc(s, func(m string) string {
		hexS := strings.TrimLeft(m, "\\\\u")
		if r, err := strconv.ParseInt(hexS, 16, 64); err == nil {
			return string(rune(r))
		}
		return m
	})
	return s
}

func isValidMethod(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodGet,
		http.MethodHead,
		http.MethodPost,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
		http.MethodOptions,
		http.MethodConnect,
		http.MethodTrace:
		return true
	}
	return false
}

func buildURL(uri string, requestItems []string) (u *url.URL, err error) {
	uri = fillURL(uri, requestItems)

	u, err = url.Parse(uri)
	if err != nil {
		return
	}

	queryItems := u.Query()
	for _, item := range requestItems {
		if reQueryItem.Match([]byte(item)) {
			arr := strings.Split(item, queryItemFlag)
			queryItems.Add(arr[0], arr[1])
		}
	}
	u.RawQuery = queryItems.Encode()
	return
}

func errorString(err error) string {
	return fmt.Sprintf("gdhttp: error: %s", err)
}

func absPathify(inPath string) (string, error) {
	if strings.HasPrefix(inPath, "$HOME") {
		home, err := homedir.Dir()
		inPath = home + inPath[5:]
		return inPath, err
	}

	if strings.HasPrefix(inPath, "$") {
		end := strings.Index(inPath, string(os.PathSeparator))
		inPath = os.Getenv(inPath[1:end]) + inPath[end:]
	}

	if filepath.IsAbs(inPath) {
		return filepath.Clean(inPath), nil
	}

	p, err := filepath.Abs(inPath)
	if err == nil {
		return filepath.Clean(p), nil
	}

	return inPath, nil
}

func fillURL(uri string, requestItems []string) string {
	// :/xxx -> 127.0.0.1/xxx
	if strings.HasPrefix(uri, ":") {
		uri = fmt.Sprintf("%s%s", defaultHost, strings.TrimLeft(uri, ":"))
	}
	// :8000/xxx -> 127.0.0.1:8000/xxx
	if reURLOnlyPort.Match([]byte(uri)) {
		uri = fmt.Sprintf("%s%s", defaultHost, uri)
	}
	// example.com/xxx -> http://example.com/xxx
	if !reURLHasScheme.Match([]byte(uri)) {
		uri = fmt.Sprintf("%s://%s", defaultScheme, uri)
	}
	// /<id> id==123  ->  /123
	formatMapping := map[string]interface{}{}
	for _, item := range requestItems {
		if reURLFormat.Match([]byte(item)) {
			arr := strings.Split(item, formatItemFlag)
			formatMapping[arr[0]] = arr[1]
		}
	}
	uri = substitute(uri, formatMapping)

	return uri
}
