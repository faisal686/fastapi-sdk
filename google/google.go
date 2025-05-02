package google

import (
	"context"
	"errors"
	"fmt"
	"github.com/gogf/gf/v2/encoding/gjson"
	"github.com/gogf/gf/v2/net/gclient"
	"github.com/smoggyiniti/fastapi-sdk/logger"
	"github.com/smoggyiniti/fastapi-sdk/model"
	"github.com/smoggyiniti/fastapi-sdk/sdkerr"
)

type Client struct {
	model               string
	key                 string
	baseURL             string
	path                string
	proxyURL            string
	isSupportSystemRole *bool
	header              map[string]string
	isGcp               bool
}

func NewClient(ctx context.Context, model, key, baseURL, path string, isSupportSystemRole *bool, proxyURL ...string) *Client {

	logger.Infof(ctx, "NewClient Google model: %s, key: %s", model, key)

	client := &Client{
		model:               model,
		key:                 key,
		baseURL:             "https://generativelanguage.googleapis.com/v1beta",
		path:                "/models/" + model,
		isSupportSystemRole: isSupportSystemRole,
	}

	if baseURL != "" {
		logger.Infof(ctx, "NewClient Google model: %s, baseURL: %s", model, baseURL)
		client.baseURL = baseURL
	}

	if path != "" {
		logger.Infof(ctx, "NewClient Google model: %s, path: %s", model, path)
		client.path = path
	}

	if len(proxyURL) > 0 && proxyURL[0] != "" {
		logger.Infof(ctx, "NewClient Google model: %s, proxyURL: %s", model, proxyURL[0])
		client.proxyURL = proxyURL[0]
	}

	return client
}

func NewGcpClient(ctx context.Context, model, key, baseURL, path string, isSupportSystemRole *bool, proxyURL ...string) *Client {

	logger.Infof(ctx, "NewGcpClient Google model: %s, key: %s", model, key)

	client := &Client{
		model:               model,
		key:                 key,
		baseURL:             "https://us-east5-aiplatform.googleapis.com/v1",
		path:                "/projects/%s/locations/us-east5/publishers/google/models/%s",
		isSupportSystemRole: isSupportSystemRole,
		isGcp:               true,
	}

	if baseURL != "" {
		logger.Infof(ctx, "NewGcpClient Google model: %s, baseURL: %s", model, baseURL)
		client.baseURL = baseURL
	}

	if path != "" {
		logger.Infof(ctx, "NewGcpClient Google model: %s, path: %s", model, path)
		client.path = path
	}

	if len(proxyURL) > 0 && proxyURL[0] != "" {
		logger.Infof(ctx, "NewGcpClient Google model: %s, proxyURL: %s", model, proxyURL[0])
		client.proxyURL = proxyURL[0]
	}

	client.header = make(map[string]string)
	client.header["Authorization"] = "Bearer " + key

	return client
}

func (c *Client) requestErrorHandler(ctx context.Context, response *gclient.Response) (err error) {
	return sdkerr.NewRequestError(500, errors.New(fmt.Sprintf("error, status code: %d, response: %s", response.StatusCode, response.ReadAllString())))
}

func (c *Client) apiErrorHandler(response *model.GoogleChatCompletionRes) error {
	return sdkerr.NewApiError(500, response.Error.Code, gjson.MustEncodeString(response), "api_error", "")
}
