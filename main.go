package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/user"
	"path"
	"strings"
	"time"

	"github.com/mattn/go-isatty"
	"github.com/mozillazg/gdauth"
)

const version = "0.1.0"
const contentTypeJSON = "application/json; charset=utf-8"
const userAgent = "gdhttp/" + version
const configPath = ".gdhttp/config.json"

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

// HTTPDump config for dump http request and response
type HTTPDump struct {
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
	req.Header.Set("Content-Type", contentTypeJSON)
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

func parseArgs() (args *Args, httpDump *HTTPDump, err error) {
	defaultConfigP, err := getDefaultConfigFile()
	if err != nil {
		exitWithError(err)
	}

	verbose := flag.Bool("v", false, "Verbose output. Print the whole request as well as the response.")
	onlyBody := flag.Bool("b", false, "Print only the response body.")
	accessKeyID := flag.String("accessKeyID", "", "Access key id.")
	accessKeySecret := flag.String("accessKeySecret", "", "Access key secret.")
	timeout := flag.Int64("timeout", 30, "The connection timeout of the request in seconds.")
	configP := flag.String("c", defaultConfigP, "Configuration file")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr,
			`Usage: %s [-accessKeyID ACCESSKEYID] [-accessKeySecret ACCESSKEYSECRET]
              [-b] [-c CONFIGFILE] [-timeout TIMEOUT] [-v]
              [METHOD] URL
`, os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	method := http.MethodGet
	uri := ""
	params := []byte{}
	cmdArgs := flag.Args()
	if len(cmdArgs) == 1 {
		uri = cmdArgs[0]
	} else if len(cmdArgs) == 2 {
		method = strings.ToUpper(cmdArgs[0])
		uri = cmdArgs[1]
	}
	if uri == "" {
		flag.Usage()
		os.Exit(1)
	}

	if !isatty.IsTerminal(os.Stdin.Fd()) {
		if params, err = ioutil.ReadAll(os.Stdin); err != nil {
			exitWithError(err)
		}
	}

	auths := map[string]configAuth{}
	config, err := parseConfig(*configP)
	if err != nil {
		exitWithError(err)
	} else {
		u, err := url.Parse(uri)
		if err != nil {
			exitWithError(err)
		}
		if value, ok := config.Auths[u.Host]; ok {
			accessKeyID = &value.AccessKeyID
			accessKeySecret = &value.AccessKeySecret
		}
	}
	auths = config.Auths

	args = &Args{
		accessKeyID:     *accessKeyID,
		accessKeySecret: *accessKeySecret,
		auths:           auths,
		timeout:         time.Duration(*timeout) * time.Second,
		method:          method,
		uri:             uri,
		params:          params,
	}
	httpDump = &HTTPDump{
		verbose:  *verbose,
		onlyBody: *onlyBody,
	}
	return
}

func main() {
	args, httpDump, err := parseArgs()
	if err != nil {
		exitWithError(err)
	}
	c := NewClient(args.accessKeyID, args.accessKeySecret, args.timeout)

	resp, err := c.doRequest(
		args.method, args.uri, args.params, httpDump,
	)
	if err != nil {
		exitWithError(err)
	}
	defer resp.Body.Close()
}

func (dump *HTTPDump) before(req *http.Request) {
	if dump.verbose {
		b, _ := httputil.DumpRequest(req, true)
		fmt.Print(string(b))
	}
}

func (dump *HTTPDump) after(resp *http.Response) {
	if !dump.onlyBody {
		b, _ := httputil.DumpResponse(resp, false)
		fmt.Print(string(b))
	}
	jsonBody, _ := ioutil.ReadAll(resp.Body)
	prettyBody, _ := prettyJSON(jsonBody)
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

	p = path.Join(usr.HomeDir, configPath)
	return
}
