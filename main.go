package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

func main() {
	clientCredentials, err := GetClientCredentialsFromOAuthJson()
	if err != nil {
		fmt.Println("Error getting client credentials:", err)
		return
	}
	RefreshTokensMap, err := getRefreshTokensMap()
	if err != nil {
		fmt.Println("Error getting refresh tokens map:", err)
		return
	}
	ok := false
	clientCredentials.RefreshToken, ok = RefreshTokensMap["franlegon.backup5@gmail.com"]
	if !ok {
		fmt.Println("Refresh token not found in RefreshTokensMap")
		return
	}
	accessToken, err := clientCredentials.GetAccessToken()
	if err != nil {
		fmt.Println("Error getting access token:", err)
		return
	}
	fmt.Println("Access token:", accessToken)
	fmt.Println("Access token value:", accessToken.AccessToken)
	fmt.Println("Expires in:", accessToken.ExpiresIn)
}

type WebOAuthClientJson struct {
	Web clientCredentials `json:"web"`
}
type clientCredentials struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	TokenUri     string `json:"token_uri"`
	RefreshToken string
	AccessToken  AccessToken
}

type AccessToken struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

func GetClientCredentialsFromOAuthJson() (clientCredentials, error) {
	var c clientCredentials
	file, err := os.Open("Credentials_OAuthClient.json")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return c, err
	}
	defer file.Close()

	var webOAuthClientJson WebOAuthClientJson
	if err := json.NewDecoder(file).Decode(&webOAuthClientJson); err != nil {
		fmt.Println("Error decoding JSON:", err)
		return c, err
	}

	return webOAuthClientJson.Web, nil
}

func (c *clientCredentials) GetAccessToken() (AccessToken, error) {
	if c.AccessToken.AccessToken != "" {
		return c.AccessToken, nil
	}
	if c.RefreshToken == "" {
		return c.AccessToken, fmt.Errorf("refreshToken is empty")
	}

	data := map[string]string{
		"refresh_token": c.RefreshToken,
		"client_id":     c.ClientID,
		"client_secret": c.ClientSecret,
		"grant_type":    "refresh_token",
	}
	jsonData, _ := json.Marshal(data)

	resp, err := http.Post(c.TokenUri, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return c.AccessToken, err
	}

	var tokenResp AccessToken
	json.NewDecoder(resp.Body).Decode(&tokenResp)

	c.AccessToken = tokenResp

	return c.AccessToken, nil
}

func getRefreshTokensMap() (map[string]string, error) {
	file, err := os.Open("Credentials_UsersRefreshTokens.json")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var refreshTokensMap map[string]string
	if err := json.NewDecoder(file).Decode(&refreshTokensMap); err != nil {
		return nil, err
	}

	return refreshTokensMap, nil
}
