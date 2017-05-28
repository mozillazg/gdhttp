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
	"time"

	"github.com/docopt/docopt-go"
	"github.com/mattn/go-isatty"
	"github.com/mozillazg/gdauth"
)

const version = "0.1.0"
const defaultContentTypeJSON = "application/json; charset=utf-8"
const userAgent = "gdhttp/" + version
const defaultConfigPath = ".gdhttp/config.json"
const defaultTimeout = 30 * time.Second
const usage = `gdhttp.

Usage:
    gdhttp URL
    gdhttp [METHOD] URL
    gdhttp [options] URL
    gdhttp [options] [METHOD] URL
    gdhttp -h | --help
    gdhttp -V | --version

Arguments:
    METHOD                               HTTP method (default: GET).
    URL                                  URL.

options:
    -h --help                            Show this screen.
    -V, --version                        Show version info.
    --accesskeyid=<accessKeyID>          Access key id.
    --accesskeysecret=<accessKeySecret>  Access key secret.
    -c, --config=<config>                Configuration file (default: ~/.gdhttp/config.json).
    -t, --timeout=<timeout>              The connection timeout of the request in seconds (default: 30).
    -b, --body                           Print only the response body.
    -v, --verbose                        Verbose output. Print the whole request as well as the response.

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

func (c *Client) doRequest(method, uri string, params []byte, hook Hook) (resp *http.Response, err error) {
	u := &url.URL{}
	if u, err = url.Parse(uri); err != nil {
		return
	}

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
	req, err := http.NewRequest(method, u.String(), body)
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", defaultContentTypeJSON)
	req.Header.Set("User-Agent", userAgent)
	sign := gdauth.Signature{
		Method:          gdauth.HMACSHA1V1,
		AccessKeyID:     c.accessKeyID,
		AccessKeySecret: c.accessKeySecret,
	}
	sign.SignReq(req)

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

	configPath = getArgString(arguments, "--config", configPath)
	accessKeyID := getArgString(arguments, "--accesskeyid", "")
	accessKeySecret := getArgString(arguments, "--accesskeysecret", "")
	verbose := getArgBoolean(arguments, "--verbose", false)
	onlyBody := getArgBoolean(arguments, "--body", false)
	timeout := getArgSecond(arguments, "--timeout", defaultTimeout)
	method := getArgString(arguments, "METHOD", http.MethodGet)
	uri := getArgString(arguments, "URL", "")
	params := []byte{}
	if !isatty.IsTerminal(os.Stdin.Fd()) {
		if params, err = ioutil.ReadAll(os.Stdin); err != nil {
			exitWithError(err)
		}
	}

	auths := map[string]configAuth{}
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

	args = &Args{
		accessKeyID:     accessKeyID,
		accessKeySecret: accessKeySecret,
		auths:           auths,
		timeout:         timeout,
		method:          method,
		uri:             uri,
		params:          params,
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
	c := NewClient(args.accessKeyID, args.accessKeySecret, args.timeout)

	resp, err := c.doRequest(
		args.method, args.uri, args.params, dumpConfig,
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
	body, _ := ioutil.ReadAll(resp.Body)
	prettyBody, err := prettyJSON(body)
	if err != nil {
		fmt.Println(string(body))
		return
	}
	fmt.Println(string(prettyBody))
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
