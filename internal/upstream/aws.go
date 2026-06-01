package upstream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
)

// AWSSecretsManagerDriver — uses the official AWS SDK v2 against
// Secrets Manager. Forward slashes are legal in SecretId so the
// PodMaker path round-trips verbatim.
type AWSSecretsManagerDriver struct {
	Client *secretsmanager.Client
}

func NewAWSSecretsManager(region, accessKey, secretKey, sessionToken string) *AWSSecretsManagerDriver {
	provider := credentials.NewStaticCredentialsProvider(accessKey, secretKey, sessionToken)
	cfg := aws.Config{
		Region:      region,
		Credentials: aws.NewCredentialsCache(provider),
	}
	return &AWSSecretsManagerDriver{Client: secretsmanager.NewFromConfig(cfg)}
}

func (a *AWSSecretsManagerDriver) Slug() string { return "aws-sm" }

func (a *AWSSecretsManagerDriver) Ping(ctx context.Context) error {
	_, err := a.Client.ListSecrets(ctx, &secretsmanager.ListSecretsInput{MaxResults: aws.Int32(1)})
	return err
}

func (a *AWSSecretsManagerDriver) Read(ctx context.Context, path string) (map[string]any, bool, error) {
	resp, err := a.Client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String(path)})
	if err != nil {
		var notFound *types.ResourceNotFoundException
		if errors.As(err, &notFound) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("aws-sm read %s: %w", path, err)
	}
	raw := aws.ToString(resp.SecretString)
	if raw == "" {
		return map[string]any{}, true, nil
	}
	out := map[string]any{}
	if jerr := json.Unmarshal([]byte(raw), &out); jerr != nil {
		return map[string]any{"value": raw}, true, nil
	}
	return out, true, nil
}

func (a *AWSSecretsManagerDriver) Write(ctx context.Context, path string, data map[string]any) error {
	payload, _ := json.Marshal(data)
	_, err := a.Client.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{
		SecretId:     aws.String(path),
		SecretString: aws.String(string(payload)),
	})
	if err == nil {
		return nil
	}
	var notFound *types.ResourceNotFoundException
	if errors.As(err, &notFound) || strings.Contains(err.Error(), "ResourceNotFoundException") {
		_, createErr := a.Client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
			Name:         aws.String(path),
			SecretString: aws.String(string(payload)),
		})
		if createErr != nil {
			return fmt.Errorf("aws-sm create %s: %w", path, createErr)
		}
		return nil
	}
	return fmt.Errorf("aws-sm write %s: %w", path, err)
}

func (a *AWSSecretsManagerDriver) Delete(ctx context.Context, path string) error {
	_, err := a.Client.DeleteSecret(ctx, &secretsmanager.DeleteSecretInput{
		SecretId:                   aws.String(path),
		ForceDeleteWithoutRecovery: aws.Bool(true),
	})
	if err == nil {
		return nil
	}
	var notFound *types.ResourceNotFoundException
	if errors.As(err, &notFound) || strings.Contains(err.Error(), "ResourceNotFoundException") {
		return nil
	}
	return fmt.Errorf("aws-sm delete %s: %w", path, err)
}
