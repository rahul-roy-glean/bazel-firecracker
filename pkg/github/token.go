package github

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"time"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/golang-jwt/jwt/v5"
)

// TokenClient generates GitHub App tokens for runner registration
type TokenClient struct {
	appID      string
	privateKey *rsa.PrivateKey
	httpClient *http.Client
}

// NewTokenClient creates a new GitHub token client
func NewTokenClient(ctx context.Context, appID, secretName, gcpProject string) (*TokenClient, error) {
	// Fetch private key from Secret Manager
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create secret manager client: %w", err)
	}
	defer client.Close()

	secretPath := fmt.Sprintf("projects/%s/secrets/%s/versions/latest", gcpProject, secretName)
	result, err := client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: secretPath,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to access secret: %w", err)
	}

	// Parse private key
	block, _ := pem.Decode(result.Payload.Data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8 format
		keyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		var ok bool
		key, ok = keyInterface.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is not RSA")
		}
	}

	return &TokenClient{
		appID:      appID,
		privateKey: key,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// generateJWT creates a JWT for GitHub App authentication
func (c *TokenClient) generateJWT() (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iat": now.Add(-60 * time.Second).Unix(),
		"exp": now.Add(10 * time.Minute).Unix(),
		"iss": c.appID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(c.privateKey)
}

// GetInstallationToken gets an installation access token
func (c *TokenClient) GetInstallationToken(ctx context.Context) (string, error) {
	jwt, err := c.generateJWT()
	if err != nil {
		return "", fmt.Errorf("failed to generate JWT: %w", err)
	}

	// Get installation ID
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/app/installations", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to get installations: %w", err)
	}
	defer resp.Body.Close()

	var installations []struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&installations); err != nil {
		return "", fmt.Errorf("failed to decode installations: %w", err)
	}
	if len(installations) == 0 {
		return "", fmt.Errorf("no installations found")
	}

	// Get installation token
	tokenURL := fmt.Sprintf("https://api.github.com/app/installations/%d/access_tokens", installations[0].ID)
	req, _ = http.NewRequestWithContext(ctx, "POST", tokenURL, nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err = c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to create installation token: %w", err)
	}
	defer resp.Body.Close()

	var tokenResp struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to decode token response: %w", err)
	}

	return tokenResp.Token, nil
}

// GetRunnerRegistrationToken gets a runner registration token for a repository
func (c *TokenClient) GetRunnerRegistrationToken(ctx context.Context, repo string) (string, error) {
	installToken, err := c.GetInstallationToken(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get installation token: %w", err)
	}

	url := fmt.Sprintf("https://api.github.com/repos/%s/actions/runners/registration-token", repo)
	req, _ := http.NewRequestWithContext(ctx, "POST", url, nil)
	req.Header.Set("Authorization", "token "+installToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to get runner token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to get runner token: %s - %s", resp.Status, string(body))
	}

	var tokenResp struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to decode runner token: %w", err)
	}

	return tokenResp.Token, nil
}

