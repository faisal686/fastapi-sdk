package anthropic

import (
	"context"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
	"github.com/gogf/gf/v2/encoding/gjson"
	"github.com/gogf/gf/v2/os/grpool"
	"github.com/gogf/gf/v2/os/gtime"
	"github.com/gogf/gf/v2/util/gconv"
	"github.com/smoggyiniti/fastapi-sdk/common"
	"github.com/smoggyiniti/fastapi-sdk/consts"
	"github.com/smoggyiniti/fastapi-sdk/logger"
	"github.com/smoggyiniti/fastapi-sdk/model"
	"github.com/smoggyiniti/fastapi-sdk/util"
	"github.com/iimeta/go-openai"
	"io"
)

func (c *Client) ChatCompletion(ctx context.Context, request model.ChatCompletionRequest) (res model.ChatCompletionResponse, err error) {

	logger.Infof(ctx, "ChatCompletion Anthropic model: %s start", request.Model)

	now := gtime.TimestampMilli()
	defer func() {
		res.TotalTime = gtime.TimestampMilli() - now
		logger.Infof(ctx, "ChatCompletion Anthropic model: %s totalTime: %d ms", request.Model, res.TotalTime)
	}()

	var messages []model.ChatCompletionMessage
	if c.isSupportSystemRole != nil {
		messages = common.HandleMessages(request.Messages, *c.isSupportSystemRole)
	} else {
		messages = common.HandleMessages(request.Messages, true)
	}

	chatCompletionReq := model.AnthropicChatCompletionReq{
		Model:         request.Model,
		Messages:      messages,
		MaxTokens:     request.MaxTokens,
		StopSequences: request.Stop,
		Stream:        request.Stream,
		Temperature:   request.Temperature,
		ToolChoice:    request.ToolChoice,
		TopK:          request.TopK,
		TopP:          request.TopP,
		Tools:         request.Tools,
	}

	if chatCompletionReq.Messages[0].Role == consts.ROLE_SYSTEM {
		chatCompletionReq.System = chatCompletionReq.Messages[0].Content
		chatCompletionReq.Messages = chatCompletionReq.Messages[1:]
	}

	if request.User != "" {
		chatCompletionReq.Metadata = &model.Metadata{
			UserId: request.User,
		}
	}

	if chatCompletionReq.MaxTokens == 0 {
		chatCompletionReq.MaxTokens = 4096
	}

	for _, message := range messages {

		if contents, ok := message.Content.([]interface{}); ok {

			for _, value := range contents {

				if content, ok := value.(map[string]interface{}); ok {

					if content["type"] == "image_url" {

						if imageUrl, ok := content["image_url"].(map[string]interface{}); ok {

							mimeType, data := common.GetMime(gconv.String(imageUrl["url"]))

							content["source"] = model.Source{
								Type:      "base64",
								MediaType: mimeType,
								Data:      data,
							}

							content["type"] = "image"
							delete(content, "image_url")
						}
					}
				}
			}
		}
	}

	if c.isGcp {
		chatCompletionReq.Model = ""
		chatCompletionReq.AnthropicVersion = "vertex-2023-10-16"
	}

	chatCompletionRes := new(model.AnthropicChatCompletionRes)

	if c.isAws {

		chatCompletionReq.AnthropicVersion = "bedrock-2023-05-31"
		chatCompletionReq.Metadata = nil

		invokeModelInput := &bedrockruntime.InvokeModelInput{
			ModelId:     aws.String(chatCompletionReq.Model),
			Accept:      aws.String("application/json"),
			ContentType: aws.String("application/json"),
		}

		if modelId, ok := AwsModelIDMap[chatCompletionReq.Model]; ok {
			invokeModelInput.ModelId = aws.String(modelId)
		}

		chatCompletionReq.Model = ""

		if invokeModelInput.Body, err = gjson.Marshal(chatCompletionReq); err != nil {
			logger.Errorf(ctx, "ChatCompletion Anthropic model: %s, chatCompletionReq: %s, gjson.Marshal error: %v", c.model, gjson.MustEncodeString(chatCompletionReq), err)
			return res, err
		}

		invokeModelOutput, err := c.awsClient.InvokeModel(ctx, invokeModelInput)
		if err != nil {
			logger.Errorf(ctx, "ChatCompletion Anthropic model: %s, invokeModelInput: %s, awsClient.InvokeModel error: %v", c.model, gjson.MustEncodeString(invokeModelInput), err)
			return res, err
		}

		if err = gjson.Unmarshal(invokeModelOutput.Body, &chatCompletionRes); err != nil {
			logger.Errorf(ctx, "ChatCompletion Anthropic model: %s, invokeModelOutput.Body: %s, gjson.Unmarshal error: %v", c.model, invokeModelOutput.Body, err)
			return res, err
		}

	} else {
		if chatCompletionRes.ResponseBytes, err = util.HttpPost(ctx, c.baseURL+c.path, c.header, chatCompletionReq, &chatCompletionRes, c.proxyURL); err != nil {
			logger.Errorf(ctx, "ChatCompletion Anthropic model: %s, error: %v", request.Model, err)
			return res, err
		}
	}

	if chatCompletionRes.Error != nil && chatCompletionRes.Error.Type != "" {
		logger.Errorf(ctx, "ChatCompletion Anthropic model: %s, chatCompletionRes: %s", request.Model, gjson.MustEncodeString(chatCompletionRes))

		err = c.apiErrorHandler(chatCompletionRes)
		logger.Errorf(ctx, "ChatCompletion Anthropic model: %s, error: %v", request.Model, err)

		return res, err
	}

	res = model.ChatCompletionResponse{
		ID:      consts.COMPLETION_ID_PREFIX + chatCompletionRes.Id,
		Object:  consts.COMPLETION_OBJECT,
		Created: gtime.Timestamp(),
		Model:   request.Model,
		Usage: &model.Usage{
			PromptTokens:             chatCompletionRes.Usage.InputTokens,
			CompletionTokens:         chatCompletionRes.Usage.OutputTokens,
			TotalTokens:              chatCompletionRes.Usage.InputTokens + chatCompletionRes.Usage.OutputTokens,
			CacheCreationInputTokens: chatCompletionRes.Usage.CacheCreationInputTokens,
			CacheReadInputTokens:     chatCompletionRes.Usage.CacheReadInputTokens,
		},
	}

	for _, content := range chatCompletionRes.Content {
		if content.Type == consts.DELTA_TYPE_INPUT_JSON {
			res.Choices = append(res.Choices, model.ChatCompletionChoice{
				Delta: &model.ChatCompletionStreamChoiceDelta{
					Role: consts.ROLE_ASSISTANT,
					ToolCalls: []openai.ToolCall{{
						Function: openai.FunctionCall{
							Arguments: content.PartialJson,
						},
					}},
				},
			})
		} else {
			res.Choices = append(res.Choices, model.ChatCompletionChoice{
				Message: &model.ChatCompletionMessage{
					Role:    chatCompletionRes.Role,
					Content: content.Text,
				},
				FinishReason: "stop",
			})
		}
	}

	return res, nil
}

func (c *Client) ChatCompletionStream(ctx context.Context, request model.ChatCompletionRequest) (responseChan chan *model.ChatCompletionResponse, err error) {

	logger.Infof(ctx, "ChatCompletionStream Anthropic model: %s start", request.Model)

	now := gtime.TimestampMilli()
	defer func() {
		if err != nil {
			logger.Infof(ctx, "ChatCompletionStream Anthropic model: %s totalTime: %d ms", request.Model, gtime.TimestampMilli()-now)
		}
	}()

	var messages []model.ChatCompletionMessage
	if c.isSupportSystemRole != nil {
		messages = common.HandleMessages(request.Messages, *c.isSupportSystemRole)
	} else {
		messages = common.HandleMessages(request.Messages, true)
	}

	chatCompletionReq := model.AnthropicChatCompletionReq{
		Model:         request.Model,
		Messages:      messages,
		MaxTokens:     request.MaxTokens,
		StopSequences: request.Stop,
		Stream:        request.Stream,
		Temperature:   request.Temperature,
		ToolChoice:    request.ToolChoice,
		TopK:          request.TopK,
		TopP:          request.TopP,
		Tools:         request.Tools,
	}

	if chatCompletionReq.Messages[0].Role == consts.ROLE_SYSTEM {
		chatCompletionReq.System = chatCompletionReq.Messages[0].Content
		chatCompletionReq.Messages = chatCompletionReq.Messages[1:]
	}

	if request.User != "" {
		chatCompletionReq.Metadata = &model.Metadata{
			UserId: request.User,
		}
	}

	if chatCompletionReq.MaxTokens == 0 {
		chatCompletionReq.MaxTokens = 4096
	}

	for _, message := range messages {

		if contents, ok := message.Content.([]interface{}); ok {

			for _, value := range contents {

				if content, ok := value.(map[string]interface{}); ok {

					if content["type"] == "image_url" {

						if imageUrl, ok := content["image_url"].(map[string]interface{}); ok {

							mimeType, data := common.GetMime(gconv.String(imageUrl["url"]))

							content["source"] = model.Source{
								Type:      "base64",
								MediaType: mimeType,
								Data:      data,
							}

							content["type"] = "image"
							delete(content, "image_url")
						}
					}
				}
			}
		}
	}

	if c.isGcp {
		chatCompletionReq.Model = ""
		chatCompletionReq.AnthropicVersion = "vertex-2023-10-16"
	}

	if c.isAws {

		chatCompletionReq.AnthropicVersion = "bedrock-2023-05-31"
		chatCompletionReq.Stream = false

		invokeModelStreamInput := &bedrockruntime.InvokeModelWithResponseStreamInput{
			ModelId:     aws.String(chatCompletionReq.Model),
			Accept:      aws.String("application/json"),
			ContentType: aws.String("application/json"),
		}

		if modelId, ok := AwsModelIDMap[chatCompletionReq.Model]; ok {
			invokeModelStreamInput.ModelId = aws.String(modelId)
		}

		chatCompletionReq.Model = ""

		if invokeModelStreamInput.Body, err = gjson.Marshal(chatCompletionReq); err != nil {
			logger.Error(ctx, err)
			return responseChan, err
		}

		invokeModelStreamOutput, err := c.awsClient.InvokeModelWithResponseStream(ctx, invokeModelStreamInput)
		if err != nil {
			logger.Error(ctx, err)
			return responseChan, err
		}

		stream := invokeModelStreamOutput.GetStream()

		duration := gtime.TimestampMilli()

		responseChan = make(chan *model.ChatCompletionResponse)

		if err = grpool.AddWithRecover(ctx, func(ctx context.Context) {

			defer func() {
				if err := stream.Close(); err != nil {
					logger.Errorf(ctx, "ChatCompletionStream Anthropic model: %s, stream.Close error: %v", request.Model, err)
				}

				end := gtime.TimestampMilli()
				logger.Infof(ctx, "ChatCompletionStream Anthropic model: %s connTime: %d ms, duration: %d ms, totalTime: %d ms", request.Model, duration-now, end-duration, end-now)
			}()

			var id string

			for {

				event, ok := <-stream.Events()
				if !ok {

					if !errors.Is(err, context.Canceled) {
						logger.Errorf(ctx, "ChatCompletionStream Anthropic model: %s, error: %v", request.Model, err)
					}

					end := gtime.TimestampMilli()
					responseChan <- &model.ChatCompletionResponse{
						ConnTime:  duration - now,
						Duration:  end - duration,
						TotalTime: end - now,
						Error:     err,
					}

					return
				}

				chatCompletionRes := new(model.AnthropicChatCompletionRes)
				switch v := event.(type) {
				case *types.ResponseStreamMemberChunk:
					if err := gjson.Unmarshal(v.Value.Bytes, &chatCompletionRes); err != nil {
						logger.Errorf(ctx, "ChatCompletionStream Anthropic model: %s, v.Value.Bytes: %s, error: %v", request.Model, v.Value.Bytes, err)

						end := gtime.TimestampMilli()
						responseChan <- &model.ChatCompletionResponse{
							ConnTime:  duration - now,
							Duration:  end - duration,
							TotalTime: end - now,
							Error:     errors.New(fmt.Sprintf("v.Value.Bytes: %s, error: %v", v.Value.Bytes, err)),
						}

						return
					}
				case *types.UnknownUnionMember:

					end := gtime.TimestampMilli()
					responseChan <- &model.ChatCompletionResponse{
						ConnTime:  duration - now,
						Duration:  end - duration,
						TotalTime: end - now,
						Error:     errors.New("unknown tag:" + v.Tag),
					}

					return
				default:

					end := gtime.TimestampMilli()
					responseChan <- &model.ChatCompletionResponse{
						ConnTime:  duration - now,
						Duration:  end - duration,
						TotalTime: end - now,
						Error:     errors.New("unknown type"),
					}

					return
				}

				if chatCompletionRes.Error != nil && chatCompletionRes.Error.Type != "" {
					logger.Errorf(ctx, "ChatCompletionStream Anthropic model: %s, chatCompletionRes: %s", request.Model, gjson.MustEncodeString(chatCompletionRes))

					err = c.apiErrorHandler(chatCompletionRes)
					logger.Errorf(ctx, "ChatCompletionStream Anthropic model: %s, error: %v", request.Model, err)

					end := gtime.TimestampMilli()
					responseChan <- &model.ChatCompletionResponse{
						ConnTime:  duration - now,
						Duration:  end - duration,
						TotalTime: end - now,
						Error:     err,
					}

					return
				}

				if chatCompletionRes.Message.Id != "" {
					id = chatCompletionRes.Message.Id
				}

				response := &model.ChatCompletionResponse{
					ID:       consts.COMPLETION_ID_PREFIX + id,
					Object:   consts.COMPLETION_STREAM_OBJECT,
					Created:  gtime.Timestamp(),
					Model:    request.Model,
					ConnTime: duration - now,
				}

				if chatCompletionRes.Usage != nil {
					response.Usage = &model.Usage{
						PromptTokens:             chatCompletionRes.Usage.InputTokens,
						CompletionTokens:         chatCompletionRes.Usage.OutputTokens,
						TotalTokens:              chatCompletionRes.Usage.InputTokens + chatCompletionRes.Usage.OutputTokens,
						CacheCreationInputTokens: chatCompletionRes.Usage.CacheCreationInputTokens,
						CacheReadInputTokens:     chatCompletionRes.Usage.CacheReadInputTokens,
					}
				}

				if chatCompletionRes.Message.Usage != nil {
					response.Usage = &model.Usage{
						PromptTokens:             chatCompletionRes.Message.Usage.InputTokens,
						CacheCreationInputTokens: chatCompletionRes.Message.Usage.CacheCreationInputTokens,
						CacheReadInputTokens:     chatCompletionRes.Message.Usage.CacheReadInputTokens,
					}
				}

				if chatCompletionRes.Delta.StopReason != "" {
					response.Choices = append(response.Choices, model.ChatCompletionChoice{
						FinishReason: openai.FinishReasonStop,
					})
				} else {
					if chatCompletionRes.Delta.Type == consts.DELTA_TYPE_INPUT_JSON {
						response.Choices = append(response.Choices, model.ChatCompletionChoice{
							Delta: &model.ChatCompletionStreamChoiceDelta{
								Role: consts.ROLE_ASSISTANT,
								ToolCalls: []openai.ToolCall{{
									Function: openai.FunctionCall{
										Arguments: chatCompletionRes.Delta.PartialJson,
									},
								}},
							},
						})
					} else {
						response.Choices = append(response.Choices, model.ChatCompletionChoice{
							Delta: &model.ChatCompletionStreamChoiceDelta{
								Role:    consts.ROLE_ASSISTANT,
								Content: chatCompletionRes.Delta.Text,
							},
						})
					}
				}

				if errors.Is(err, io.EOF) || response.Choices[0].FinishReason != "" {
					logger.Infof(ctx, "ChatCompletionStream Anthropic model: %s finished", request.Model)

					if len(response.Choices) == 0 {
						response.Choices = append(response.Choices, model.ChatCompletionChoice{
							Delta:        new(model.ChatCompletionStreamChoiceDelta),
							FinishReason: openai.FinishReasonStop,
						})
					}

					end := gtime.TimestampMilli()
					response.Duration = end - duration
					response.TotalTime = end - now
					responseChan <- response

					responseChan <- &model.ChatCompletionResponse{
						ConnTime:  duration - now,
						Duration:  end - duration,
						TotalTime: end - now,
						Error:     io.EOF,
					}

					return
				}

				end := gtime.TimestampMilli()
				response.Duration = end - duration
				response.TotalTime = end - now

				responseChan <- response
			}
		}, nil); err != nil {
			logger.Errorf(ctx, "ChatCompletionStream Anthropic model: %s, error: %v", request.Model, err)
			return responseChan, err
		}

	} else {

		stream, err := util.SSEClient(ctx, c.baseURL+c.path, c.header, chatCompletionReq, c.proxyURL, c.requestErrorHandler)
		if err != nil {
			logger.Errorf(ctx, "ChatCompletionStream Anthropic model: %s, error: %v", request.Model, err)
			return responseChan, err
		}

		duration := gtime.TimestampMilli()

		responseChan = make(chan *model.ChatCompletionResponse)

		if err = grpool.AddWithRecover(ctx, func(ctx context.Context) {

			defer func() {
				if err := stream.Close(); err != nil {
					logger.Errorf(ctx, "ChatCompletionStream Anthropic model: %s, stream.Close error: %v", request.Model, err)
				}

				end := gtime.TimestampMilli()
				logger.Infof(ctx, "ChatCompletionStream Anthropic model: %s connTime: %d ms, duration: %d ms, totalTime: %d ms", request.Model, duration-now, end-duration, end-now)
			}()

			var id string
			var promptTokens int

			for {

				streamResponse, err := stream.Recv()
				if err != nil && !errors.Is(err, io.EOF) {

					if !errors.Is(err, context.Canceled) {
						logger.Errorf(ctx, "ChatCompletionStream Anthropic model: %s, error: %v", request.Model, err)
					}

					end := gtime.TimestampMilli()
					responseChan <- &model.ChatCompletionResponse{
						ConnTime:  duration - now,
						Duration:  end - duration,
						TotalTime: end - now,
						Error:     err,
					}

					return
				}

				chatCompletionRes := new(model.AnthropicChatCompletionRes)
				if err := gjson.Unmarshal(streamResponse, &chatCompletionRes); err != nil {
					logger.Errorf(ctx, "ChatCompletionStream Anthropic model: %s, streamResponse: %s, error: %v", request.Model, streamResponse, err)

					end := gtime.TimestampMilli()
					responseChan <- &model.ChatCompletionResponse{
						ConnTime:  duration - now,
						Duration:  end - duration,
						TotalTime: end - now,
						Error:     errors.New(fmt.Sprintf("streamResponse: %s, error: %v", streamResponse, err)),
					}

					return
				}

				if chatCompletionRes.Error != nil && chatCompletionRes.Error.Type != "" {
					logger.Errorf(ctx, "ChatCompletionStream Anthropic model: %s, chatCompletionRes: %s", request.Model, gjson.MustEncodeString(chatCompletionRes))

					err = c.apiErrorHandler(chatCompletionRes)
					logger.Errorf(ctx, "ChatCompletionStream Anthropic model: %s, error: %v", request.Model, err)

					end := gtime.TimestampMilli()
					responseChan <- &model.ChatCompletionResponse{
						ConnTime:  duration - now,
						Duration:  end - duration,
						TotalTime: end - now,
						Error:     err,
					}

					return
				}

				if chatCompletionRes.Message.Id != "" {
					id = chatCompletionRes.Message.Id
				}

				response := &model.ChatCompletionResponse{
					ID:       consts.COMPLETION_ID_PREFIX + id,
					Object:   consts.COMPLETION_STREAM_OBJECT,
					Created:  gtime.Timestamp(),
					Model:    request.Model,
					ConnTime: duration - now,
				}

				if chatCompletionRes.Usage != nil {
					if chatCompletionRes.Usage.InputTokens != 0 {
						promptTokens = chatCompletionRes.Usage.InputTokens
					}
					response.Usage = &model.Usage{
						PromptTokens:             promptTokens,
						CompletionTokens:         chatCompletionRes.Usage.OutputTokens,
						TotalTokens:              promptTokens + chatCompletionRes.Usage.OutputTokens,
						CacheCreationInputTokens: chatCompletionRes.Usage.CacheCreationInputTokens,
						CacheReadInputTokens:     chatCompletionRes.Usage.CacheReadInputTokens,
					}
				}

				if chatCompletionRes.Message.Usage != nil {
					promptTokens = chatCompletionRes.Message.Usage.InputTokens
					response.Usage = &model.Usage{
						PromptTokens:             promptTokens,
						CacheCreationInputTokens: chatCompletionRes.Message.Usage.CacheCreationInputTokens,
						CacheReadInputTokens:     chatCompletionRes.Message.Usage.CacheReadInputTokens,
					}
				}

				if chatCompletionRes.Delta.StopReason != "" {
					response.Choices = append(response.Choices, model.ChatCompletionChoice{
						FinishReason: openai.FinishReasonStop,
					})
				} else {
					if chatCompletionRes.Delta.Type == consts.DELTA_TYPE_INPUT_JSON {
						response.Choices = append(response.Choices, model.ChatCompletionChoice{
							Delta: &model.ChatCompletionStreamChoiceDelta{
								Role: consts.ROLE_ASSISTANT,
								ToolCalls: []openai.ToolCall{{
									Function: openai.FunctionCall{
										Arguments: chatCompletionRes.Delta.PartialJson,
									},
								}},
							},
						})
					} else {
						response.Choices = append(response.Choices, model.ChatCompletionChoice{
							Delta: &model.ChatCompletionStreamChoiceDelta{
								Role:    consts.ROLE_ASSISTANT,
								Content: chatCompletionRes.Delta.Text,
							},
						})
					}
				}

				if errors.Is(err, io.EOF) || response.Choices[0].FinishReason != "" {
					logger.Infof(ctx, "ChatCompletionStream Anthropic model: %s finished", request.Model)

					if len(response.Choices) == 0 {
						response.Choices = append(response.Choices, model.ChatCompletionChoice{
							Delta:        new(model.ChatCompletionStreamChoiceDelta),
							FinishReason: openai.FinishReasonStop,
						})
					}

					end := gtime.TimestampMilli()
					response.Duration = end - duration
					response.TotalTime = end - now
					responseChan <- response

					responseChan <- &model.ChatCompletionResponse{
						ConnTime:  duration - now,
						Duration:  end - duration,
						TotalTime: end - now,
						Error:     io.EOF,
					}

					return
				}

				end := gtime.TimestampMilli()
				response.Duration = end - duration
				response.TotalTime = end - now

				responseChan <- response
			}
		}, nil); err != nil {
			logger.Errorf(ctx, "ChatCompletionStream Anthropic model: %s, error: %v", request.Model, err)
			return responseChan, err
		}
	}

	return responseChan, nil
}
