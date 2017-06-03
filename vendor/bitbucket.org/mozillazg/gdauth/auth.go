package gdauth

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"hash"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

var internalHeaderPrefix = "x-gd-"
var internalAuthPrefix = "GeneDock"

// HMACSHA1V1 ...
const HMACSHA1V1 = "hmac-sha1-v1"

// Signature ...
type Signature struct {
	Method          string // 签名方法
	AccessKeyID     string // access key id
	AccessKeySecret string // access key secret
}

// SignReq 给 req 增加签名相关的设置
func (sign *Signature) SignReq(req *http.Request) {
	reqMethod := req.Method
	contentType := req.Header.Get("Content-Type")
	contentMD5 := req.Header.Get("Content-MD5")
	resource := sign.convertURLToString(req.URL)
	headersStr := sign.convertHeadersToString(req.Header)
	date := time.Now().UTC().Format(http.TimeFormat)

	s := sign.sign(reqMethod, contentType, contentMD5,
		resource, headersStr, date)
	req.Header.Set("Date", date)
	sign.setAuthHeader(req, s)
}

func (sign *Signature) setAuthHeader(req *http.Request, signStr string) {
	req.Header.Set("Authorization",
		fmt.Sprintf("%s %s:%s", internalAuthPrefix,
			sign.AccessKeyID, signStr))
}

func (sign *Signature) sign(
	reqMethod, contentType, contentMD5,
	resource, headersStr, date string) (s string) {
	msgSlice := []string{}
	if len(headersStr) > 0 {
		msgSlice = []string{
			reqMethod, contentMD5, contentType,
			date, headersStr, resource,
		}
	} else {
		msgSlice = []string{
			reqMethod, contentMD5, contentType,
			date, resource,
		}
	}
	msg := strings.Join(msgSlice, "\n")
	digest := sign.newHMACDigest(msg)
	s = base64.StdEncoding.EncodeToString(digest)
	return
}

func (sign *Signature) newHMACDigest(msg string) (digest []byte) {
	var hashFunc func() hash.Hash
	switch sign.Method {
	case HMACSHA1V1:
		hashFunc = sha1.New
	default:
		hashFunc = sha1.New
	}
	h := hmac.New(hashFunc, []byte(sign.AccessKeySecret))
	h.Write([]byte(msg))
	digest = h.Sum(nil)
	return
}

func (sign *Signature) convertURLToString(u *url.URL) (uri string) {
	uri = u.Path
	sortedQuery := url.Values{}
	for key, values := range u.Query() {
		for _, value := range values {
			sortedQuery.Add(key, value)
		}
	}
	if len(sortedQuery) > 0 {
		uri = fmt.Sprintf("%s?%s", uri, sortedQuery.Encode())
	}
	return
}

func (sign *Signature) convertHeadersToString(reqHeaders http.Header) (s string) {
	headers := getInternalHeaders(reqHeaders)
	sortedItems := sortMapByKey(headers)
	sSlice := []string{}
	for _, item := range sortedItems {
		sSlice = append(sSlice, fmt.Sprintf("%s:%s", item[0], item[1]))
	}
	s = strings.Join(sSlice, "\n")
	return
}

// getInternalHeaders 获取 request headers 中自定义的 headers
func getInternalHeaders(headers http.Header) (internalHeaders map[string]string) {
	for key, values := range headers {
		if strings.HasPrefix(strings.ToLower(key), internalHeaderPrefix) {
			internalHeaders[key] = strings.Join(values, ",")
		}
	}
	return
}

func sortMapByKey(m map[string]string) (sortedItems [][2]string) {
	keys := []string{}
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		sortedItems = append(sortedItems, [2]string{key, m[key]})
	}
	return
}
