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
	clientCredentials.AccessTokens = make(map[string]AccessToken)
	_, err = clientCredentials.GetRefreshTokensMap()
	if err != nil {
		fmt.Println("Error getting refresh tokens map:", err)
		return
	}
	/*
		accessToken, err := clientCredentials.GetAccessToken("franlegon.backup5@gmail.com")
		if err != nil {
			fmt.Println("Error getting access token:", err)
			return
		}
		fmt.Println("Access token:", accessToken)
		fmt.Println("Access token value:", accessToken.AccessToken)
		fmt.Println("Expires in:", accessToken.ExpiresIn)
	*/
}

type WebOAuthClientJson struct {
	Web clientCredentials `json:"web"`
}
type clientCredentials struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	TokenUri     string `json:"token_uri"`
	//RefreshToken string
	//AccessToken  AccessToken
	RefreshTokens map[string]string
	AccessTokens  map[string]AccessToken
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

func (c *clientCredentials) GetAccessToken(user string) (AccessToken, error) {
	if c.AccessTokens[user].AccessToken != "" {
		return c.AccessTokens[user], nil
	}
	if c.RefreshTokens[user] == "" {
		return c.AccessTokens[user], fmt.Errorf("refreshToken is empty for user %s", user)
	}

	data := map[string]string{
		"refresh_token": c.RefreshTokens[user],
		"client_id":     c.ClientID,
		"client_secret": c.ClientSecret,
		"grant_type":    "refresh_token",
	}
	jsonData, _ := json.Marshal(data)

	resp, err := http.Post(c.TokenUri, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return c.AccessTokens[user], err
	}

	var tokenResp AccessToken
	json.NewDecoder(resp.Body).Decode(&tokenResp)

	c.AccessTokens[user] = tokenResp

	return c.AccessTokens[user], nil
}

func (c *clientCredentials) GetRefreshTokensMap() (map[string]string, error) {
	file, err := os.Open("Credentials_UsersRefreshTokens.json")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var refreshTokensMap map[string]string
	if err := json.NewDecoder(file).Decode(&refreshTokensMap); err != nil {
		return nil, err
	}

	c.RefreshTokens = refreshTokensMap

	return c.RefreshTokens, nil
}
