package xfyun

import (
	"context"
	"github.com/gogf/gf/v2/os/gtime"
	"github.com/gogf/gf/v2/text/gstr"
	"github.com/gogf/gf/v2/util/gconv"
	"github.com/gogf/gf/v2/util/grand"
	"github.com/smoggyiniti/fastapi-sdk/consts"
	"github.com/smoggyiniti/fastapi-sdk/logger"
	"github.com/smoggyiniti/fastapi-sdk/model"
	"github.com/smoggyiniti/fastapi-sdk/util"
)

func (c *Client) Image(ctx context.Context, request model.ImageRequest) (res model.ImageResponse, err error) {

	logger.Infof(ctx, "Image Xfyun model: %s start", request.Model)

	now := gtime.TimestampMilli()
	defer func() {
		res.TotalTime = gtime.TimestampMilli() - now
		logger.Infof(ctx, "Image Xfyun model: %s totalTime: %d ms", request.Model, gtime.TimestampMilli()-now)
	}()

	width := 512
	height := 512

	if request.Size != "" {

		size := gstr.Split(request.Size, `×`)

		if len(size) != 2 {
			size = gstr.Split(request.Size, `x`)
		}

		if len(size) != 2 {
			size = gstr.Split(request.Size, `X`)
		}

		if len(size) != 2 {
			size = gstr.Split(request.Size, `*`)
		}

		if len(size) != 2 {
			size = gstr.Split(request.Size, `:`)
		}

		if len(size) == 2 {
			width = gconv.Int(size[0])
			height = gconv.Int(size[1])
		}
	}

	imageReq := model.XfyunChatCompletionReq{
		Header: model.Header{
			AppId: c.appId,
			Uid:   grand.Digits(10),
		},
		Parameter: model.Parameter{
			Chat: &model.Chat{
				Domain: "general",
				Width:  width,
				Height: height,
			},
		},
		Payload: model.Payload{
			Message: &model.Message{
				Text: []model.ChatCompletionMessage{{
					Role:    consts.ROLE_USER,
					Content: request.Prompt,
				}},
			},
		},
	}

	imageRes := new(model.XfyunChatCompletionRes)
	if _, err = util.HttpPost(ctx, c.getHttpUrl(ctx), nil, imageReq, &imageRes, c.proxyURL); err != nil {
		logger.Errorf(ctx, "Image Xfyun model: %s, error: %v", request.Model, err)
		return res, err
	}

	res = model.ImageResponse{
		Created: gtime.Timestamp(),
		Data: []model.ImageResponseDataInner{{
			B64JSON: imageRes.Payload.Choices.Text[0].Content,
		}},
	}

	return res, nil
}
