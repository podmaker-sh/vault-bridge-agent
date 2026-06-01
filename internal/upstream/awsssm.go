package upstream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// AWSSSMDriver — AWS Systems Manager Parameter Store via the v2
// SDK. PodMaker paths become parameter names with a leading
// slash (SSM convention). Values round-trip as JSON.
type AWSSSMDriver struct {
	Client *ssm.Client
	Prefix string // optional path prefix
}

func NewAWSSSM(region, accessKey, secretKey, sessionToken, prefix string) *AWSSSMDriver {
	provider := credentials.NewStaticCredentialsProvider(accessKey, secretKey, sessionToken)
	cfg := aws.Config{Region: region, Credentials: aws.NewCredentialsCache(provider)}
	return &AWSSSMDriver{
		Client: ssm.NewFromConfig(cfg),
		Prefix: strings.Trim(prefix, "/"),
	}
}

func (a *AWSSSMDriver) Slug() string { return "aws-ssm" }

func (a *AWSSSMDriver) Ping(ctx context.Context) error {
	_, err := a.Client.DescribeParameters(ctx, &ssm.DescribeParametersInput{MaxResults: aws.Int32(1)})
	return err
}

func (a *AWSSSMDriver) name(path string) string {
	clean := "/" + strings.TrimLeft(path, "/")
	if a.Prefix != "" {
		clean = "/" + a.Prefix + clean
	}
	return clean
}

func (a *AWSSSMDriver) Read(ctx context.Context, path string) (map[string]any, bool, error) {
	resp, err := a.Client.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(a.name(path)),
		WithDecryption: aws.Bool(true),
	})
	if err != nil {
		var notFound *types.ParameterNotFound
		if errors.As(err, &notFound) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("aws-ssm read %s: %w", path, err)
	}
	raw := aws.ToString(resp.Parameter.Value)
	if raw == "" {
		return map[string]any{}, true, nil
	}
	out := map[string]any{}
	if jerr := json.Unmarshal([]byte(raw), &out); jerr != nil {
		return map[string]any{"value": raw}, true, nil
	}
	return out, true, nil
}

func (a *AWSSSMDriver) Write(ctx context.Context, path string, data map[string]any) error {
	payload, _ := json.Marshal(data)
	_, err := a.Client.PutParameter(ctx, &ssm.PutParameterInput{
		Name:      aws.String(a.name(path)),
		Type:      types.ParameterTypeSecureString,
		Value:     aws.String(string(payload)),
		Overwrite: aws.Bool(true),
	})
	if err != nil {
		return fmt.Errorf("aws-ssm write %s: %w", path, err)
	}
	return nil
}

func (a *AWSSSMDriver) Delete(ctx context.Context, path string) error {
	_, err := a.Client.DeleteParameter(ctx, &ssm.DeleteParameterInput{
		Name: aws.String(a.name(path)),
	})
	if err != nil {
		var notFound *types.ParameterNotFound
		if errors.As(err, &notFound) || strings.Contains(err.Error(), "ParameterNotFound") {
			return nil
		}
		return fmt.Errorf("aws-ssm delete %s: %w", path, err)
	}
	return nil
}
