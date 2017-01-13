package ali_http

//go:generate stringer -type=API

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"github.com/cocotyty/summer"
	"github.com/satori/go.uuid"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	ContentType string = "application/x-www-form-urlencoded"
)

type API int

const (
	OpenSearch API = iota
)

func init() {
	summer.Put(&AliHTTP{})
}

type AliHTTP struct {
	AccessKeyId string `sm:"#.ali.appKey"`
	AppSecret   string `sm:"#.ali.appSecret"`
}

func (client *AliHTTP) Post(api API, url string, params url.Values) (resp *http.Response, err error) {
	return client.curl("POST", api, url, params)

}

func (client *AliHTTP) Get(api API, url string, params url.Values) (resp *http.Response, err error) {
	return client.curl("GET", api, url, params)
}

func (client *AliHTTP) curl(method string, api API, url string, params url.Values) (resp *http.Response, err error) {
	err = client.header(params)
	if err != nil {
		return
	}
	err = client.format(params, api)
	if err != nil {
		return
	}
	err = client.sign(method, params)
	if err != nil {
		return
	}
	switch method {
	case "GET":
		return http.Get(url + "?" + params.Encode())
	case "POST":
		return http.Post(url, ContentType, strings.NewReader(params.Encode()))
	default:
		return http.Post(url, ContentType, strings.NewReader(params.Encode()))
	}
}

func (client *AliHTTP) header(params url.Values) (err error) {
	params.Add("AccessKeyId", client.AccessKeyId)
	params.Add("SignatureMethod", "HMAC-SHA1")
	params.Add("Timestamp", time.Now().UTC().Format("2006-01-02T15:04:05Z"))
	params.Add("SignatureVersion", "1.0")
	params.Add("SignatureNonce", uuid.NewV4().String())
	return nil
}

func (client *AliHTTP) format(params url.Values, api API) (err error) {
	switch api {
	case OpenSearch:
		params.Add("Version", "v2")
	}
	return nil
}

func (client *AliHTTP) sign(method string, params url.Values) (err error) {
	queryString := method + "&%2F&" + url.QueryEscape(params.Encode())
	mac := hmac.New(sha1.New, []byte(client.AppSecret + "&"))
	mac.Write([]byte(queryString))
	signature := mac.Sum(nil)
	params.Add("Signature", base64.StdEncoding.EncodeToString(signature))
	return nil
}
