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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"bitbucket.org/mozillazg/gdauth"
	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
)

const version = "0.3.1"
const defaultConfigPath = "$HOME/.gdhttp.json"
const defaultScheme = "http"
const defaultHost = "localhost"

var defaultHeaders = map[string]string{
	"Content-Type":    "application/json",
	"User-Agent":      "gdhttp/" + version,
	"Accept":          "application/json",
	"Accept-Encoding": "application/json",
	"Connection":      "keep-alive",
	// "Content-Length":  "0",
}

const defaultTimeout int64 = 30

var cfgFile string
var accessKeyID string
var accessKeySecret string
var onlyBody bool
var noAuth bool
var verbose bool
var askVersion bool
var httpMethod string
var uri *url.URL
var requestItems []string
var timeout int64
var params []byte

var RootCmd = &cobra.Command{
	PreRun: func(cmd *cobra.Command, args []string) {
		if askVersion {
			fmt.Println(version)
			os.Exit(0)
		}

		if len(args) > 0 && args[0] == "help" {
			fmt.Println(usageDetail())
			os.Exit(1)
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		pa, err := parsePositionalArguments(args)
		if err != nil {
			fmt.Println(usageShort())
			fmt.Println(errorString(err))
			os.Exit(1)
		}
		if !isatty.IsTerminal(os.Stdin.Fd()) {
			if params, err = ioutil.ReadAll(os.Stdin); err != nil {
				exitWithError(err)
			}
		}
		httpMethod = pa.httpMethod
		requestItems = pa.requestItems
		uri = pa.uri
		dumpConfig := &DumpConfig{
			verbose:  verbose,
			onlyBody: onlyBody,
		}
		initConfig()

		c := NewClient(accessKeyID, accessKeySecret, time.Duration(timeout)*time.Second)
		resp, err := c.doRequest(
			httpMethod, uri, params, noAuth, dumpConfig,
		)
		if err != nil {
			exitWithError(err)
		}
		defer resp.Body.Close()
	},
}

func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	RootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file (default is $HOME/.gdhttp.json)")
	RootCmd.PersistentFlags().StringVar(&accessKeyID, "access-key-id", "", "Access key ID")
	RootCmd.PersistentFlags().StringVar(&accessKeySecret, "access-key-secret", "", "Access key secret")
	RootCmd.PersistentFlags().BoolVarP(&onlyBody, "body", "b", false, "Print only the response body")
	RootCmd.PersistentFlags().BoolVar(&noAuth, "no-auth", false, "Don't add Authorization header")
	RootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output. Print the whole request as well as the response")
	RootCmd.PersistentFlags().Int64VarP(&timeout, "timeout", "t", defaultTimeout, "The connection timeout of the request in seconds (default: 30)")
	RootCmd.PersistentFlags().BoolVarP(&askVersion, "version", "V", false, "Show version and exit")

	RootCmd.SetUsageFunc(func(cmd *cobra.Command) error {
		fmt.Println(usageDetail())
		return nil
	})
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile == "" {
		cfgFile = defaultConfigPath
	}
	cfgFile, err := absPathify(cfgFile)
	if err != nil {
		return
	}

	config, err := parseConfig(cfgFile)
	if err != nil {
		if _, ok := err.(*os.PathError); ok {
			return
		} else {
			msg := fmt.Sprintf("parse config file %s error %s", cfgFile, err)
			exitWithError(errors.New(msg))
		}
	}

	if value, ok := config.Auths[uri.Host]; ok {
		accessKeyID = value.AccessKeyID
		accessKeySecret = value.AccessKeySecret
	}
}

// Client ...
type Client struct {
	http.Client
	accessKeyID     string
	accessKeySecret string
	sign            gdauth.Signature
}

// Hook for request
type Hook interface {
	before(req *http.Request)
	after(resp *http.Response)
}

// DumpConfig config for dump http request and response
type DumpConfig struct {
	verbose  bool
	onlyBody bool
}

// NewClient ...
func NewClient(accessKeyID, accessKeySecret string, timeout time.Duration) *Client {
	c := http.Client{}
	c.Timeout = timeout
	return &Client{
		Client:          c,
		accessKeyID:     accessKeyID,
		accessKeySecret: accessKeySecret,
	}
}

func (c *Client) doRequest(method string, uri *url.URL, params []byte, noAuth bool, hook Hook) (resp *http.Response, err error) {
	var body io.Reader
	if params != nil && len(params) > 0 {
		switch method {
		case http.MethodGet:
		case http.MethodHead:
		case http.MethodOptions:

		default:
			body = bytes.NewReader(params)
		}
	}
	req, err := http.NewRequest(method, uri.String(), body)
	if err != nil {
		return
	}
	for key, value := range defaultHeaders {
		req.Header.Set(key, value)
	}
	if !noAuth {
		sign := gdauth.Signature{
			Method:          gdauth.HMACSHA1V1,
			AccessKeyID:     c.accessKeyID,
			AccessKeySecret: c.accessKeySecret,
		}
		sign.SignReq(req)
	}

	hook.before(req)

	if resp, err = c.Do(req); err != nil {
		return
	}

	hook.after(resp)
	return
}

type configAuth struct {
	AccessKeyID     string `json:"accessKeyID"`
	AccessKeySecret string `json:"accessKeySecret"`
}

// Config ...
type Config struct {
	Auths map[string]configAuth `json:"auths"`
}

func parseConfig(p string) (config Config, err error) {
	_, err = os.Stat(p)
	if err != nil {
		return
	}
	data, err := ioutil.ReadFile(p)
	if err != nil {
		return
	}

	err = json.Unmarshal(data, &config)
	return
}

func (dump *DumpConfig) before(req *http.Request) {
	if dump.verbose {
		b, _ := httputil.DumpRequest(req, true)
		fmt.Println(string(b))
		fmt.Println("")
	}
}

func (dump *DumpConfig) after(resp *http.Response) {
	if !dump.onlyBody {
		b, _ := httputil.DumpResponse(resp, false)
		fmt.Print(string(b))
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(string(body))
		return
	}

	prettyBody, err := prettyJSON(body)
	if err != nil {
		fmt.Println(string(body))
		return
	}

	bodyStr := string(prettyBody)
	bodyStr = replaceJSONUnicode(bodyStr)
	fmt.Println(bodyStr)
}

func prettyJSON(b []byte) ([]byte, error) {
	var out bytes.Buffer
	err := json.Indent(&out, b, "", "  ")
	return out.Bytes(), err
}

func exitWithError(err error) {
	fmt.Println(err)
	os.Exit(1)
}

func usageDetail() string {
	return fmt.Sprintf(`%s

gdhttp - a CLI, cURL-like tool for you.

Positional Arguments:
    METHOD
      The HTTP method to be used for the request (GET, POST, PUT, DELETE, ...) (default: GET).

    URL
      The scheme defaults to 'http://' if the URL does not include one.

      You can also use a shorthand for localhost

          $ http :3000                    # => http://localhost:3000
          $ http :/foo                    # => http://localhost/foo

    REQUEST_ITEM
      Optional key-value pairs to be included in the request. The separator used
      determines the type:

      '=' URL parameters to be appended to the request URI:

          search=httpie

Optional Arguments:
    --help, -h
        Show this help message and exit.
    --version, -V
        Show version and exit.
    --access-key-id ACCESSKEYID
        Access key id.
    --access-key-secret ACCESSKEYSECRET
        Access key secret.
    --config CONFIG, -c
        Configuration file (default: $HOME/.gdhttp.json).
    --timeout TIMEOUT, -t
        The connection timeout of the request in seconds (default: 30).
    --body, -b
        Print only the response body.
    --verbose, -v
        Verbose output. Print the whole request as well as the response.
    --no-auth
        Don't add Authorization header.

Sample configuration file:

{
    "auths": {
        "localhost": {
            "accessKeyID" : "id",
            "accessKeySecret": "secret"
        }
    }
}`, usageShort())
}

func usageShort() string {
	return `usage: gdhttp [-h | --help] [-V | --version]
              [--access-key-id ACCESSKEYID] [--access-key-secret ACCESSKEYSECRET]
              [--config CONFIG] [--body] [--no-auth] [--verbose]
              [METHOD] URL [REQUEST_ITEM [REQUEST_ITEM ...]]`
}
