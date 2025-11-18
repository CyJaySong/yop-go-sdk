// Package client
// Copyright: Copyright (c) 2020<br>
// Company: 易宝支付(YeePay)<br>
// @author    : yunmei.wu
// @time      : 2023/3/16 3:22 PM
package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
	"github.com/yop-platform/yop-go-sdk/yop/auth"
	"github.com/yop-platform/yop-go-sdk/yop/constants"
	"github.com/yop-platform/yop-go-sdk/yop/request"
	"github.com/yop-platform/yop-go-sdk/yop/response"
	"github.com/yop-platform/yop-go-sdk/yop/utils"
)

var DefaultClient = YopClient{&http.Client{Transport: http.DefaultTransport}}

type YopClient struct {
	*http.Client
}

func init() {
	log.SetLevel(log.InfoLevel)
}

// MultiPartUploadFileByUrl 根据URL使用表单方式上传文件
func (yopClient *YopClient) MultiPartUploadFileByUrl(yopRequest *request.YopRequest, fieldName, filename, sourceUrl string) (*response.YopResponse, error) {
	initRequest(yopRequest)
	var signer = auth.RsaSigner{}
	err := signer.SignRequest(*yopRequest)
	if nil != err {
		return nil, err
	}
	if yopRequest.Timeout == 0 {
		yopRequest.Timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), yopRequest.Timeout)
	defer cancel()
	downloadHttpReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, sourceUrl, nil)
	downloadResp, err := http.DefaultClient.Do(downloadHttpReq)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) { _ = Body.Close() }(downloadResp.Body)
	if downloadResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download file failed: %d", downloadResp.StatusCode)
	}
	if filename == "" {
		// 尝试从 Content-Disposition 获取文件名
		if disposition := downloadResp.Header.Get("Content-Disposition"); disposition != "" {
			if strings.Contains(disposition, "filename=") {
				start := strings.Index(disposition, "filename=") + 9
				filename = strings.Trim(disposition[start:], "\"'")
			}
		}

		// 如果没有从响应头获取到文件名，则从 URL 获取
		if filename == "" {
			URL, _ := url.Parse(sourceUrl)
			filename = filepath.Base(URL.Path)
			if filename == "." || filename == "/" {
				// 根据 Content-Type 设置默认扩展名
				contentType := downloadResp.Header.Get("Content-Type")
				switch {
				case strings.Contains(contentType, "text/plain"):
					filename = "file.txt"
				case strings.Contains(contentType, "application/pdf"):
					filename = "file.pdf"
				case strings.Contains(contentType, "application/zip"):
					filename = "file.zip"
				case strings.Contains(contentType, "image/jpeg"):
					filename = "image.jpg"
				case strings.Contains(contentType, "image/gif"):
					filename = "image.gif"
				case strings.Contains(contentType, "image/png"):
					filename = "image.png"
				case strings.Contains(contentType, "audio/ogg"):
					filename = "audio.ogg"
				case strings.Contains(contentType, "audio/mpeg"):
					filename = "audio.mp3"
				case strings.Contains(contentType, "video/mp4"):
					filename = "video.mp4"
				case strings.Contains(contentType, "video/webm"):
					filename = "video.webm"
				default:
					filename = "file"
				}
			}
		}
	}

	pipeReader, pipeWriter := io.Pipe()
	multipartWriter := multipart.NewWriter(pipeWriter)
	go func(multipartWriter *multipart.Writer, pw *io.PipeWriter) {
		defer func() { _ = multipartWriter.Close() }()
		for k, v := range yopRequest.Params {
			for i := range v {
				if err = multipartWriter.WriteField(k, url.QueryEscape(v[i])); err != nil {
					_ = pw.CloseWithError(err)
					return
				}
			}
		}
		// 设置表单字段
		fileWriter, _ := multipartWriter.CreateFormFile(fieldName, filename)
		// 将下载内容直接复制到表单字段
		if _, copyErr := io.Copy(fileWriter, downloadResp.Body); copyErr != nil {
			_ = pw.CloseWithError(fmt.Errorf("copy file failed: %w", copyErr))
			return
		}
		_ = pw.Close()
	}(multipartWriter, pipeWriter)

	//build http request

	var uri = yopRequest.ServerRoot + yopRequest.ApiUri
	httpRequest, err := http.NewRequestWithContext(ctx, "POST", uri, pipeReader)
	if nil != err {
		return nil, err
	}
	httpRequest.Header.Set("Content-Type", multipartWriter.FormDataContentType())
	for k, v := range yopRequest.Headers {
		httpRequest.Header.Set(k, v)
	}

	httpResp, err := yopClient.Client.Do(httpRequest)
	if nil != err {
		return nil, err
	}
	defer func(Body io.ReadCloser) { _ = Body.Close() }(httpResp.Body)
	body, err := io.ReadAll(httpResp.Body)
	if nil != err {
		return nil, err
	}
	var yopResponse = response.YopResponse{Content: body}
	metaData := response.YopResponseMetadata{}
	metaData.YopSign = httpResp.Header.Get("X-Yop-Sign")
	metaData.YopRequestId = httpResp.Header.Get("X-Yop-Request-Id")
	yopResponse.Metadata = &metaData
	respHandleCtx := response.RespHandleContext{YopSigner: &signer, YopResponse: &yopResponse, YopRequest: *yopRequest}
	for i := range response.ANALYZER_CHAIN {
		err = response.ANALYZER_CHAIN[i].Analyze(respHandleCtx, httpResp)
		if nil != err {
			return nil, err
		}
	}
	return &yopResponse, nil
}

// MultiPartUploadFileByBytes 根据Bytes使用表单方式上传文件
func (yopClient *YopClient) MultiPartUploadFileByBytes(yopRequest *request.YopRequest, fieldName, filename string, byte []byte) (*response.YopResponse, error) {
	initRequest(yopRequest)
	var signer = auth.RsaSigner{}
	err := signer.SignRequest(*yopRequest)
	if nil != err {
		return nil, err
	}

	multipartBuffer := &bytes.Buffer{}
	multipartWriter := multipart.NewWriter(multipartBuffer)
	for k, v := range yopRequest.Params {
		for i := range v {
			if err = multipartWriter.WriteField(k, url.QueryEscape(v[i])); err != nil {
				_ = multipartWriter.Close()
				return nil, err
			}
		}
	}
	fileWriter, _ := multipartWriter.CreateFormFile(fieldName, filename)
	if _, err = fileWriter.Write(byte); err != nil {
		_ = multipartWriter.Close()
		return nil, err
	}
	_ = multipartWriter.Close()

	//build http request
	if yopRequest.Timeout == 0 {
		yopRequest.Timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), yopRequest.Timeout)
	defer cancel()

	var uri = yopRequest.ServerRoot + yopRequest.ApiUri
	httpRequest, err := http.NewRequestWithContext(ctx, "POST", uri, multipartBuffer)
	if nil != err {
		return nil, err
	}
	httpRequest.Header.Set("Content-Type", multipartWriter.FormDataContentType())
	for k, v := range yopRequest.Headers {
		httpRequest.Header.Set(k, v)
	}

	httpResp, err := yopClient.Client.Do(httpRequest)
	if nil != err {
		return nil, err
	}
	defer func(Body io.ReadCloser) { _ = Body.Close() }(httpResp.Body)
	body, err := io.ReadAll(httpResp.Body)
	if nil != err {
		return nil, err
	}
	var yopResponse = response.YopResponse{Content: body}
	metaData := response.YopResponseMetadata{}
	metaData.YopSign = httpResp.Header.Get("X-Yop-Sign")
	metaData.YopRequestId = httpResp.Header.Get("X-Yop-Request-Id")
	yopResponse.Metadata = &metaData
	respHandleCtx := response.RespHandleContext{YopSigner: &signer, YopResponse: &yopResponse, YopRequest: *yopRequest}
	for i := range response.ANALYZER_CHAIN {
		err = response.ANALYZER_CHAIN[i].Analyze(respHandleCtx, httpResp)
		if nil != err {
			return nil, err
		}
	}
	return &yopResponse, nil
}

// Request 普通请求
func (yopClient *YopClient) Request(request *request.YopRequest) (*response.YopResponse, error) {
	initRequest(request)
	var signer = auth.RsaSigner{}
	err := signer.SignRequest(*request)
	if nil != err {
		return nil, err
	}

	httpRequest, err := buildHttpRequest(*request)
	if nil != err {
		return nil, err
	}
	httpResp, err := yopClient.Client.Do(&httpRequest)
	if nil != err {
		return nil, err
	}
	defer httpResp.Body.Close()
	body, err := ioutil.ReadAll(httpResp.Body)
	if nil != err {
		return nil, err
	}
	var yopResponse = response.YopResponse{Content: body}
	metaData := response.YopResponseMetadata{}
	metaData.YopSign = httpResp.Header.Get("X-Yop-Sign")
	metaData.YopRequestId = httpResp.Header.Get("X-Yop-Request-Id")
	yopResponse.Metadata = &metaData
	context := response.RespHandleContext{YopSigner: &signer, YopResponse: &yopResponse, YopRequest: *request}
	for i := range response.ANALYZER_CHAIN {
		err = response.ANALYZER_CHAIN[i].Analyze(context, httpResp)
		if nil != err {
			return nil, err
		}
	}
	return &yopResponse, nil
}
func initRequest(yopRequest *request.YopRequest) {
	yopRequest.RequestId = uuid.NewV4().String()
	log.Println("requestId:" + yopRequest.RequestId)
	if 0 == len(yopRequest.ServerRoot) {
		yopRequest.HandleServerRoot()
	}
	if 0 == len(yopRequest.PlatformPubKey.Value) {
		yopRequest.PlatformPubKey.Value = request.YOP_PLATFORM_PUBLIC_KEY
		yopRequest.PlatformPubKey.CertType = request.RSA2048
	}
	addStandardHeaders(yopRequest)
}
func addStandardHeaders(yopRequest *request.YopRequest) {
	yopRequest.Headers = map[string]string{}
	yopRequest.Headers[constants.YOP_REQUEST_ID] = yopRequest.RequestId
	yopRequest.Headers[constants.YOP_APPKEY_HEADER_KEY] = yopRequest.AppId
	yopRequest.Headers[constants.USER_AGENT_HEADER_KEY] = buildUserAgent()
}

func buildUserAgent() string {
	return "go" + "/" + constants.SDK_VERSION + "/" + runtime.GOOS + "/" + runtime.Version()
}

func buildHttpRequest(yopRequest request.YopRequest) (http.Request, error) {
	if yopRequest.Timeout == 0 {
		yopRequest.Timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), yopRequest.Timeout)
	defer cancel()

	var uri = yopRequest.ServerRoot + yopRequest.ApiUri
	isMultiPart, err := checkForMultiPart(yopRequest)
	if nil != err {
		return http.Request{}, err
	}
	var result http.Request
	if isMultiPart {
		bodyBuf := &bytes.Buffer{}
		bodyWriter := multipart.NewWriter(bodyBuf)

		for k, v := range yopRequest.Params {
			for i := range v {
				bodyWriter.WriteField(k, url.QueryEscape(v[i]))
			}
		}

		for k, v := range yopRequest.Files {
			fileWriter, _ := bodyWriter.CreateFormFile(k, v.Name())
			io.Copy(fileWriter, v)
		}
		bodyWriter.Close()

		if err != nil {
			return http.Request{}, err
		}
		req, err := http.NewRequestWithContext(ctx, "POST", uri, bodyBuf)
		if nil != err {
			return http.Request{}, err
		}
		req.Header.Set("Content-Type", bodyWriter.FormDataContentType())
		result = *req
	} else {
		var encodedParam = utils.EncodeParameters(yopRequest.Params, false)
		var requestHasPayload = 0 < len(yopRequest.Content)
		var requestIsPost = 0 == strings.Compare(constants.POST_HTTP_METHOD, yopRequest.HttpMethod)
		var putParamsInUri = !requestIsPost || requestHasPayload
		if 0 < len(encodedParam) && putParamsInUri {
			uri += "?" + encodedParam
		}
		var body io.Reader = nil
		if 0 == strings.Compare(constants.POST_HTTP_METHOD, yopRequest.HttpMethod) {
			if 0 < len(yopRequest.Content) {
				body = bytes.NewBuffer([]byte(yopRequest.Content))
			} else {
				formValues := url.Values{}
				for k, v := range yopRequest.Params {
					for i := range v {
						formValues.Set(k, url.QueryEscape(v[i]))
					}
				}
				formDataStr := formValues.Encode()
				body = bytes.NewBuffer([]byte(formDataStr))
			}
		}
		httpRequest, err := http.NewRequestWithContext(ctx, yopRequest.HttpMethod, uri, body)
		if err != nil {
			return http.Request{}, err
		}
		result = *httpRequest
		result.Header.Set(constants.CONTENT_TYPE, getContentType(yopRequest))
	}
	for k, v := range yopRequest.Headers {
		result.Header.Set(k, v)
	}
	return result, err
}

func checkForMultiPart(yopRequest request.YopRequest) (bool, error) {
	var result = nil != yopRequest.Files && 0 < len(yopRequest.Files)
	if result && 0 != strings.Compare(constants.POST_HTTP_METHOD, yopRequest.HttpMethod) {
		var errorMsg = "ContentType:multipart/form-data only support Post Request"
		log.Fatal(errorMsg)
		return false, errors.New(errorMsg)
	}
	return result, nil
}

func getContentType(yopRequest request.YopRequest) string {
	if 0 == strings.Compare("POST", yopRequest.HttpMethod) && 0 < len(yopRequest.Content) {
		return constants.YOP_HTTP_CONTENT_TYPE_JSON
	}
	if 0 < len(yopRequest.Params) {
		return constants.YOP_HTTP_CONTENT_TYPE_FORM
	}
	return constants.YOP_HTTP_CONTENT_TYPE_FORM
}
