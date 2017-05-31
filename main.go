package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/user"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/docopt/docopt-go"
	"github.com/mattn/go-isatty"
	"github.com/mozillazg/gdauth"
)

const version = "0.1.0"
const defaultConfigPath = ".gdhttp/config.json"

var defaultHeaders = map[string]string{
	"Content-Type":    "application/json",
	"User-Agent":      "gdhttp/" + version,
	"Accept":          "application/json",
	"Accept-Encoding": "application/json",
	"Connection":      "keep-alive",
	// "Content-Length":  "0",
}

const defaultTimeout = 30 * time.Second
const usage = `gdhttp.

Usage:
    gdhttp [-h | --help] [-V | --version]
           [--accesskeyid=<accessKeyID>]
           [--accesskeysecret=<accessKeySecret>]
           [--config=<config>]
           [--body] [--no-auth] [--verbose]
           [METHOD] URL [REQUEST_ITEM...]

Arguments:

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

      '==' URL parameters to be appended to the request URI:

          search==httpie

Options:
    -h --help                            Show this screen.
    -V, --version                        Show version info.
    --accesskeyid=<accessKeyID>          Access key id.
    --accesskeysecret=<accessKeySecret>  Access key secret.
    -c, --config=<config>                Configuration file (default: ~/.gdhttp/config.json).
    -t, --timeout=<timeout>              The connection timeout of the request in seconds (default: 30).
    -b, --body                           Print only the response body.
    -v, --verbose                        Verbose output. Print the whole request as well as the response.
    --no-auth                            Don't add Authorization header.

Sample configuration file:

{
    "auths": {
        "localhost": {
            "accessKeyID" : "id",
            "accessKeySecret": "secret"
        }
    }
}
`

var reJSONUnicode = regexp.MustCompile("\\\\u[a-z\\d]{4}")
var reQueryItem = regexp.MustCompile("^([^=]+)==([^\\s]*)$")
const queryItemFlag = "=="

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
	data, err := ioutil.ReadFile(p)
	if err != nil {
		return
	}

	err = json.Unmarshal(data, &config)
	return
}

// Args ...
type Args struct {
	auths           map[string]configAuth
	accessKeyID     string
	accessKeySecret string
	timeout         time.Duration
	method          string
	uri             string
	params          []byte
	noAuth          bool
	requestItems	[]string
}

func parseArgs() (args *Args, dumpConfig *DumpConfig, err error) {
	configPath, err := getDefaultConfigFile()
	if err != nil {
		exitWithError(err)
	}
	arguments, err := docopt.Parse(usage, nil, true, fmt.Sprintf("gdhttp %s", version), false)
	if err != nil {
		exitWithError(err)
	}
	fmt.Println(arguments)

	noAuth := getArgBoolean(arguments, "--no-auth", false)
	configPath = getArgString(arguments, "--config", configPath)
	accessKeyID := getArgString(arguments, "--accesskeyid", "")
	accessKeySecret := getArgString(arguments, "--accesskeysecret", "")
	verbose := getArgBoolean(arguments, "--verbose", false)
	onlyBody := getArgBoolean(arguments, "--body", false)
	timeout := getArgSecond(arguments, "--timeout", defaultTimeout)
	method := strings.ToUpper(getArgString(arguments, "METHOD", http.MethodGet))
	uri := getArgString(arguments, "URL", "")
	requestItems := getArgStringArray(arguments, "REQUEST_ITEM", []string{})
	params := []byte{}
	if !isatty.IsTerminal(os.Stdin.Fd()) {
		if params, err = ioutil.ReadAll(os.Stdin); err != nil {
			exitWithError(err)
		}
	}
	if !isValidMethod(method) {
		uri = method
		method = http.MethodGet
		oldRequestItems := requestItems[:]
		requestItems = []string{}
		for _, item := range(oldRequestItems) {
			requestItems = append(requestItems, item)
		}
	}

	auths := map[string]configAuth{}
	if !noAuth {
		config, err := parseConfig(string(configPath))
		if err != nil {
			exitWithError(err)
		} else {
			u, err := url.Parse(uri)
			if err != nil {
				exitWithError(err)
			}
			if value, ok := config.Auths[u.Host]; ok {
				accessKeyID = value.AccessKeyID
				accessKeySecret = value.AccessKeySecret
			}
		}
		auths = config.Auths
	}

	args = &Args{
		accessKeyID:     accessKeyID,
		accessKeySecret: accessKeySecret,
		auths:           auths,
		timeout:         timeout,
		method:          method,
		uri:             uri,
		params:          params,
		noAuth:          noAuth,
		requestItems:	requestItems,
	}
	dumpConfig = &DumpConfig{
		verbose:  verbose,
		onlyBody: onlyBody,
	}
	return
}

func main() {
	args, dumpConfig, err := parseArgs()
	if err != nil {
		exitWithError(err)
	}
	uri, err := buildURL(args.uri, args.requestItems)
	if err != nil {
		exitWithError(err)
	}

	c := NewClient(args.accessKeyID, args.accessKeySecret, args.timeout)

	resp, err := c.doRequest(
		args.method, uri, args.params, args.noAuth, dumpConfig,
	)
	if err != nil {
		exitWithError(err)
	}
	defer resp.Body.Close()
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

func getDefaultConfigFile() (p string, err error) {
	usr, err := user.Current()
	if err != nil {
		return
	}

	p = path.Join(usr.HomeDir, defaultConfigPath)
	return
}

func getMapValue(m map[string]interface{}, key string, defaultValue interface{}) interface{} {
	if value, ok := m[key]; ok && value != nil {
		return value
	}
	return defaultValue
}

func getArgSecond(m map[string]interface{}, key string, defaultValue interface{}) time.Duration {
	v := time.Nanosecond
	if value := getMapValue(m, key, defaultValue); value != nil {
		v, _ = value.(time.Duration)
		v = v * time.Second
	}
	return v
}

func getArgString(m map[string]interface{}, key string, defaultValue interface{}) string {
	v := ""
	if value := getMapValue(m, key, defaultValue); value != nil {
		v, _ = value.(string)
	}
	return v
}

func getArgBoolean(m map[string]interface{}, key string, defaultValue interface{}) bool {
	v := false
	if value := getMapValue(m, key, defaultValue); value != nil {
		v, _ = value.(bool)
	}
	return v
}

func getArgStringArray(m map[string]interface{}, key string, defaultValue interface{}) []string {
	v := []string{}
	if value := getMapValue(m, key, defaultValue); value != nil {
		v, _ = value.([]string)
	}
	return v
}

// \\uXXXX -> \uXXXX 方便显示 json 中的中文
func replaceJSONUnicode(s string) string {
	s = reJSONUnicode.ReplaceAllStringFunc(s, func(m string) string {
		hexS := strings.TrimLeft(m, "\\\\u")
		if r, err := strconv.ParseInt(hexS, 16, 16); err == nil {
			return string(rune(r))
		}
		return m
	})
	return s
}


func isValidMethod(method string) bool {
	switch strings.ToUpper(method) {
		case http.MethodGet:
		case http.MethodHead:
		case http.MethodPost:
		case http.MethodPut:
		case http.MethodPatch:
		case http.MethodDelete:
		case http.MethodOptions:
		case http.MethodConnect:
		case http.MethodTrace:
			return true
	}
	return false
}


func buildURL(uri string, requestItems []string) (u *url.URL, err error) {
	u, err = url.Parse(uri)
	if err != nil {
		return
	}

	queryItems := u.Query()
	for _, item := range(requestItems) {
		if reQueryItem.Match([]byte(item)) {
			arr := strings.Split(item, queryItemFlag)
			queryItems.Add(arr[0], arr[1])
		}
	}
	return
}
