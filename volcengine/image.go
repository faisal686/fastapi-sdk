package volcengine

import (
	"context"
	"github.com/gogf/gf/v2/os/gtime"
	"github.com/smoggyiniti/fastapi-sdk/logger"
	"github.com/smoggyiniti/fastapi-sdk/model"
	"github.com/iimeta/go-openai"
)

func (c *Client) Image(ctx context.Context, request model.ImageRequest) (res model.ImageResponse, err error) {

	logger.Infof(ctx, "Image VolcEngine model: %s start", request.Model)

	now := gtime.TimestampMilli()
	defer func() {
		res.TotalTime = gtime.TimestampMilli() - now
		logger.Infof(ctx, "Image VolcEngine model: %s totalTime: %d ms", request.Model, gtime.TimestampMilli()-now)
	}()

	response, err := c.client.CreateImage(ctx, openai.ImageRequest{
		Prompt:         request.Prompt,
		Model:          request.Model,
		N:              request.N,
		Quality:        request.Quality,
		Size:           request.Size,
		Style:          request.Style,
		ResponseFormat: request.ResponseFormat,
		User:           request.User,
	})
	if err != nil {
		logger.Errorf(ctx, "Image VolcEngine model: %s, error: %v", request.Model, err)
		return res, err
	}

	data := make([]model.ImageResponseDataInner, 0)
	for _, d := range response.Data {
		data = append(data, model.ImageResponseDataInner{
			URL:           d.URL,
			B64JSON:       d.B64JSON,
			RevisedPrompt: d.RevisedPrompt,
		})
	}

	res = model.ImageResponse{
		Created: response.Created,
		Data:    data,
	}

	return res, nil
}
