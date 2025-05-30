package sdk

import (
	"context"
	"github.com/smoggyiniti/fastapi-sdk/ai360"
	"github.com/smoggyiniti/fastapi-sdk/aliyun"
	"github.com/smoggyiniti/fastapi-sdk/anthropic"
	"github.com/smoggyiniti/fastapi-sdk/baidu"
	"github.com/smoggyiniti/fastapi-sdk/consts"
	"github.com/smoggyiniti/fastapi-sdk/deepseek"
	"github.com/smoggyiniti/fastapi-sdk/google"
	"github.com/smoggyiniti/fastapi-sdk/logger"
	"github.com/smoggyiniti/fastapi-sdk/model"
	"github.com/smoggyiniti/fastapi-sdk/openai"
	"github.com/smoggyiniti/fastapi-sdk/volcengine"
	"github.com/smoggyiniti/fastapi-sdk/xfyun"
	"github.com/smoggyiniti/fastapi-sdk/zhipuai"
)

type Client interface {
	ChatCompletion(ctx context.Context, request model.ChatCompletionRequest) (res model.ChatCompletionResponse, err error)
	ChatCompletionStream(ctx context.Context, request model.ChatCompletionRequest) (responseChan chan *model.ChatCompletionResponse, err error)
	Image(ctx context.Context, request model.ImageRequest) (res model.ImageResponse, err error)
	Speech(ctx context.Context, request model.SpeechRequest) (res model.SpeechResponse, err error)
	Transcription(ctx context.Context, request model.AudioRequest) (res model.AudioResponse, err error)
	Embeddings(ctx context.Context, request model.EmbeddingRequest) (res model.EmbeddingResponse, err error)
	Moderations(ctx context.Context, request model.ModerationRequest) (res model.ModerationResponse, err error)
}

func NewClient(ctx context.Context, corp, model, key, baseURL, path string, isSupportSystemRole *bool, proxyURL ...string) Client {

	logger.Infof(ctx, "NewClient corp: %s, model: %s, key: %s", corp, model, key)

	switch corp {
	case consts.CORP_OPENAI:
		return openai.NewClient(ctx, model, key, baseURL, path, isSupportSystemRole, proxyURL...)
	case consts.CORP_AZURE:
		return openai.NewAzureClient(ctx, model, key, baseURL, path, isSupportSystemRole, proxyURL...)
	case consts.CORP_BAIDU:
		return baidu.NewClient(ctx, model, key, baseURL, path, isSupportSystemRole, proxyURL...)
	case consts.CORP_XFYUN:
		return xfyun.NewClient(ctx, model, key, baseURL, path, isSupportSystemRole, proxyURL...)
	case consts.CORP_ALIYUN:
		return aliyun.NewClient(ctx, model, key, baseURL, path, isSupportSystemRole, proxyURL...)
	case consts.CORP_ZHIPUAI:
		return zhipuai.NewClient(ctx, model, key, baseURL, path, isSupportSystemRole, proxyURL...)
	case consts.CORP_GOOGLE:
		return google.NewClient(ctx, model, key, baseURL, path, isSupportSystemRole, proxyURL...)
	case consts.CORP_GCP_GEMINI:
		return google.NewGcpClient(ctx, model, key, baseURL, path, isSupportSystemRole, proxyURL...)
	case consts.CORP_DEEPSEEK:
		return deepseek.NewClient(ctx, model, key, baseURL, path, isSupportSystemRole, proxyURL...)
	case consts.CORP_DEEPSEEK_BAIDU:
		return deepseek.NewClientBaidu(ctx, model, key, baseURL, path, isSupportSystemRole, proxyURL...)
	case consts.CORP_360AI:
		return ai360.NewClient(ctx, model, key, baseURL, path, isSupportSystemRole, proxyURL...)
	case consts.CORP_ANTHROPIC:
		return anthropic.NewClient(ctx, model, key, baseURL, path, isSupportSystemRole, proxyURL...)
	case consts.CORP_GCP_CLAUDE:
		return anthropic.NewGcpClient(ctx, model, key, baseURL, path, isSupportSystemRole, proxyURL...)
	case consts.CORP_AWS_CLAUDE:
		return anthropic.NewAwsClient(ctx, model, key, baseURL, path, isSupportSystemRole, proxyURL...)
	case consts.CORP_VOLC_ENGINE:
		return volcengine.NewClient(ctx, model, key, baseURL, path, isSupportSystemRole, proxyURL...)
	}

	return openai.NewClient(ctx, model, key, baseURL, path, isSupportSystemRole, proxyURL...)
}
