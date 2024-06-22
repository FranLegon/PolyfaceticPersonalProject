package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	decryptFile("Credentials_OAuthClient.json.enc")
	defer os.Remove("Credentials_OAuthClient.json")
	decryptFile("Credentials_UsersRefreshTokens.json.enc")
	defer os.Remove("Credentials_UsersRefreshTokens.json")
	clientCredentials, err := GetClientCredentialsFromOAuthJson()
	if err != nil {
		fmt.Println("Error getting client credentials:", err)
		return
	}

	////
	fmt.Println("Client ID:", clientCredentials.ClientID)

	accessToken, err := clientCredentials.GetAccessToken("franlegon.backup5@gmail.com")
	if err != nil {
		fmt.Println("Error getting access token:", err)
		return
	}

	files, err := listFiles(accessToken.AccessToken)
	if err != nil {
		fmt.Println("Error listing files:", err)
		return
	}
	fmt.Println("Files:")
	for _, f := range files.Files {
		fmt.Println(f)

	}

}

type EncryptionKey struct {
	KeyBase64 string `json:"keyBase64"`
	IvBase64  string `json:"ivBase64"`
}

func decryptFile(filename string) error {
	// Read the encryption key JSON file
	keyData, err := os.ReadFile("Credentials_EncriptionKey.json")
	if err != nil {
		return err
	}

	// Unmarshal the JSON data into the EncryptionKey struct
	var encKey EncryptionKey
	err = json.Unmarshal(keyData, &encKey)
	if err != nil {
		return err
	}

	// Decode the base64 encoded key and IV
	key, err := base64.StdEncoding.DecodeString(encKey.KeyBase64)
	if err != nil {
		return err
	}
	iv, err := base64.StdEncoding.DecodeString(encKey.IvBase64)
	if err != nil {
		return err
	}

	// Decryption process
	ciphertext, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	if len(ciphertext) < aes.BlockSize {
		return fmt.Errorf("ciphertext too short")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	// remove padding
	padding := ciphertext[len(ciphertext)-1] // Get the last byte, which indicates padding length
	padLen := int(padding)                   // Convert to int for slicing

	if padLen > aes.BlockSize || padLen == 0 {
		return fmt.Errorf("invalid padding")
	}
	for _, padByte := range ciphertext[len(ciphertext)-padLen:] {
		if padByte != padding {
			return fmt.Errorf("invalid padding byte")
		}
	}
	ciphertext = ciphertext[:len(ciphertext)-padLen]

	// Write the decrypted file
	decryptedFilename := strings.TrimSuffix(filename, ".enc")
	err = os.WriteFile(decryptedFilename, ciphertext, 0644)
	if err != nil {
		return err
	}

	return nil
}

type AccessToken struct {
	AccessToken string `json:"access_token"`
	Duration    int    `json:"expires_in"`
	RetrievedAt time.Time
}

func (t *AccessToken) ExpirationTime() time.Time {
	return t.RetrievedAt.Add(time.Duration(t.Duration) * time.Second)
}
func (t *AccessToken) IsExpired() bool {
	return time.Now().After(t.ExpirationTime())
}
func (t *AccessToken) ExpiresIn() time.Duration {
	return time.Until(t.ExpirationTime())
}

type WebOAuthClientJson struct {
	Web clientCredentials `json:"web"`
}
type clientCredentials struct {
	ClientID      string `json:"client_id"`
	ClientSecret  string `json:"client_secret"`
	TokenUri      string `json:"token_uri"`
	RefreshTokens map[string]string
	AccessTokens  map[string]AccessToken
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

	webOAuthClientJson.Web.AccessTokens = make(map[string]AccessToken)
	_, err = webOAuthClientJson.Web.GetRefreshTokensMap()
	if err != nil {
		fmt.Println("Error getting refresh tokens map:", err)
		return webOAuthClientJson.Web, err
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

	tokenResp.RetrievedAt = time.Now()
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

type files struct {
	Files         []file `json:"files"`
	NextPageToken string `json:"nextPageToken,omitempty"`
}
type file struct {
	Name     string `json:"name"`
	Id       string `json:"id"`
	Kind     string `json:"kind"`
	MimeType string `json:"mimeType"`
	Size     string `json:"size"`
	Owners   []struct {
		DisplayName  string `json:"displayName"`
		EmailAddress string `json:"emailAddress"`
	} `json:"owners"`
}

func listFiles(accessToken string) (files, error) {
	var allFiles files
	url := "https://www.googleapis.com/drive/v3/files" + "?fields=nextPageToken,files(id,name,kind,mimeType,owners,size)"
	for {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return allFiles, err
		}
		req.Header.Set("Authorization", "Bearer "+accessToken)

		// Add query parameters if nextPageToken exists
		q := req.URL.Query()
		if allFiles.NextPageToken != "" {
			q.Add("pageToken", allFiles.NextPageToken)
		}
		req.URL.RawQuery = q.Encode()

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return allFiles, err
		}
		defer resp.Body.Close()

		var pageFiles files
		if err := json.NewDecoder(resp.Body).Decode(&pageFiles); err != nil {
			return allFiles, err
		}

		// Append the files from the current page to the allFiles
		allFiles.Files = append(allFiles.Files, pageFiles.Files...)

		// Break the loop if there is no nextPageToken
		if pageFiles.NextPageToken == "" {
			break
		} else {
			allFiles.NextPageToken = pageFiles.NextPageToken
		}
	}

	return allFiles, nil
}
