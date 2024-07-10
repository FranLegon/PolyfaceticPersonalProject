package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.ngrok.com/ngrok"
	"golang.ngrok.com/ngrok/config"
	_ "modernc.org/sqlite"
)

// #region main (testing)

func main() {
	if err := DecryptFile("Credentials_UsersRefreshTokens.json.enc"); err != nil {
		log.Fatal(err)
	}

	// Get the client credentials from the OAuth JSON file
	ClientCredentials, err := GetClientCredentialsFromOAuthJson()
	if err != nil {
		fmt.Println("Error getting client credentials:", err)
		return
	}

	// Get the access token for the user
	accessToken1, err := ClientCredentials.GetAccessToken("franlegon.backup1@gmail.com")
	if err != nil {
		fmt.Println("Error getting access token:", err)
		return
	}
	accessToken5, err := ClientCredentials.GetAccessToken("franlegon.backup5@gmail.com")
	if err != nil {
		fmt.Println("Error getting access token:", err)
		return
	}

	// List the files in the user's Google Drive
	files, err := ListFiles(accessToken1.AccessToken)
	if err != nil {
		fmt.Println("Error listing files:", err)
		return
	}
	testFile := files.Files[0]
	fmt.Println("testFile:")
	fmt.Println(testFile)

	/*
		// Transfer ownership of the first file to the second user
		fmt.Println("Access Token 1:", accessToken1.AccessToken)
		err = TransferOwnership(testFile.Id, accessToken1.AccessToken, "franlegon.backup5@gmail.com")
		if err != nil {
			fmt.Println("Error transferring ownership:", err)
			return
		}
		fmt.Println("Ownership transferred successfully")
	*/

	fileReader, err := testFile.StreamDownload(accessToken1.AccessToken)
	if err != nil {
		fmt.Println("Error streaming download:", err)
		return
	}
	defer fileReader.Close()
	fileReaderCopy, err := testFile.StreamDownload(accessToken1.AccessToken)
	if err != nil {
		fmt.Println("Error streaming download:", err)
		return
	}
	defer fileReaderCopy.Close()

	hash, err := CalculateSHA256Hash(fileReaderCopy)
	if err != nil {
		fmt.Println("Error calculating SHA256 hash:", err)
		return
	}
	uploadedFile, err := UploadFileAsStream(accessToken5.AccessToken, fileReader, testFile.Name, hash)
	if err != nil {
		fmt.Println("Error uploading file:", err)
		return
	}
	fmt.Println("Uploaded File:")
	fmt.Println(uploadedFile)

}

func main5() {
	//DecryptFile("Credentials_UsersRefreshTokens.json.enc")
	//return

	db, err := GetSQLiteConnection()
	if err != nil {
		fmt.Println("Error getting SQLite connection:", err)
		return
	}
	defer db.Close()
	//defer EncryptFile("sqlite.db")
	//defer os.Remove("sqlite.db")
	if err = CreateSQLiteTables(db); err != nil {
		fmt.Println("Error creating SQLite tables:", err)
		return
	}

	GoogleCredentials, err := GetClientCredentialsFromOAuthJson()
	if err != nil {
		fmt.Println("Error getting client credentials:", err)
		return
	}
	accessToken, err := GoogleCredentials.GetAccessToken("franlegon.backup5@gmail.com")
	if err != nil {
		fmt.Println("Error getting access token:", err)
		return
	}
	fmt.Println("Access Token:", accessToken.AccessToken)
	files, err := ListFiles(accessToken.AccessToken)
	if err != nil {
		fmt.Println("Error listing files:", err)
		return
	}

	err = InsertOrUpdateInSQLiteTable(files)
	if err != nil {
		fmt.Println("Error inserting files into SQLite:", err)
		return
	}

	mediaItems, err := ListMediaItems(accessToken.AccessToken)
	if err != nil {
		fmt.Println("Error listing media items:", err)
		return
	}

	err = InsertOrUpdateInSQLiteTable(mediaItems)
	if err != nil {
		fmt.Println("Error inserting media items into SQLite:", err)
		return
	}
}

func main4() {
	//EncryptFile("Credentials_UsersRefreshTokens.json")
	//return
	GoogleCredentials, err := GetClientCredentialsFromOAuthJson()
	if err != nil {
		fmt.Println("Error getting client credentials:", err)
		return
	}
	accessToken1, err := GoogleCredentials.GetAccessToken("franlegon.backup1@gmail.com")
	if err != nil {
		fmt.Println("Error getting access token:", err)
		return
	}
	accessToken5, err := GoogleCredentials.GetAccessToken("franlegon.backup5@gmail.com")
	if err != nil {
		fmt.Println("Error getting access token:", err)
		return
	}
	sharedAlbums, err := GetSharedAlbums(accessToken1.AccessToken)
	if err != nil {
		fmt.Println("Error getting shared albums:", err)
		return
	}
	fmt.Println("Shared Albums:")
	for _, album := range sharedAlbums {
		fmt.Println(album)
	}

	sharedAlbum1 := sharedAlbums[0].Id
	fmt.Printf("Shared Album id: %s\n", sharedAlbum1)
	fmt.Printf("Shared Album name: %s\n", sharedAlbums[0].Title)

	albumMediaItems, err := GetAlbumMediaItems(accessToken1.AccessToken, sharedAlbum1)
	if err != nil {
		fmt.Println("Error getting album media items:", err)
		return
	}
	fmt.Println("albumMediaItems.MediaItems[0]:")
	fmt.Println(albumMediaItems.MediaItems[0])

	//mediaItemIds := albumMediaItems.GetMediaItemIds()

	/*
		album2, err := CreateAlbum(accessToken.AccessToken, "My Shared Album (TESTING)")
		if err != nil {
			fmt.Println("Error creating shared album:", err)
			return
		}
		fmt.Printf("Created shared album id: %s\n", album2)

		shareInfo, err := ShareAlbum(accessToken.AccessToken, album2)
		if err != nil {
			fmt.Println("Error sharing album:", err)
			return
		}
		fmt.Println("ShareInfo:")
		fmt.Println(shareInfo)
	*/

	/*
		err = AddMediaItemsToAlbum(accessToken.AccessToken, album2, mediaItemIds)
		if err != nil {
			fmt.Println("Error adding media items to album:", err)
			return
		}
			fmt.Println("Media items added to album successfully")
	*/

	ioReader, err := albumMediaItems.MediaItems[0].StreamDownload(accessToken1.AccessToken)
	if err != nil {
		fmt.Println("Error streaming download:", err)
		return
	}
	defer ioReader.Close()

	uploadedMediaItem, err := UploadMediaItemAsStream(accessToken5.AccessToken, ioReader, albumMediaItems.MediaItems[0].Filename+" testing")
	if err != nil {
		fmt.Println("Error uploading media item:", err)
		return
	}
	fmt.Println("Uploaded Media Item:")
	fmt.Println(uploadedMediaItem)
}

func main2() {

	ClientCredentials, err := GetClientCredentialsFromOAuthJson()
	if err != nil {
		fmt.Println("Error getting client credentials:", err)
		return
	}

	////
	fmt.Println("Client ID:", ClientCredentials.ClientID)

	accessToken, err := ClientCredentials.GetAccessToken("franlegon.backup5@gmail.com")
	if err != nil {
		fmt.Println("Error getting access token:", err)
		return
	}

	//files, err := ListFiles(accessToken.AccessToken)
	//if err != nil {
	//	fmt.Println("Error listing files:", err)
	//	return
	//}
	//fmt.Println("Files:")
	//for _, f := range files.Files {
	//	fmt.Println(f)
	//}
	fmt.Println("--------------------------------------------------------------------")
	quota, err := GetStorageQuota(accessToken.AccessToken)
	if err != nil {
		fmt.Println("Error getting quota:", err)
		return
	}
	fmt.Println("Quota:/n", quota)
	fmt.Println("--------------------------------------------------------------------")
	fmt.Println("Quota in GigaBytes:/n", quota.SeeInGigaBytes())
	fmt.Println("--------------------------------------------------------------------")
}

func main3() {
	WhatsappCredentials, err := GetWhatsappCredentials()
	if err != nil {
		fmt.Println("Error getting whatsapp credentials:", err)
		return
	}
	err = SendWhatsappMessage(WhatsappCredentials.AccessToken, "Hello from Go!", WhatsappCredentials.To)
	if err != nil {
		fmt.Println("Error sending message:", err)
		return
	}
}

// #endregion main (testing)

// #region Encryption
type EncryptionKey struct {
	KeyBase64 string `json:"keyBase64"`
	IvBase64  string `json:"ivBase64"`
}

func GetEncryptionKey() ([]byte, []byte, error) {
	// Read the encryption key JSON file
	keyData, err := os.ReadFile("Credentials_EncriptionKey.json")
	if err != nil {
		return nil, nil, err
	}

	// Unmarshal the JSON data into the EncryptionKey struct
	var encKey EncryptionKey
	err = json.Unmarshal(keyData, &encKey)
	if err != nil {
		return nil, nil, err
	}

	// Decode the base64 encoded key and IV
	key, err := base64.StdEncoding.DecodeString(encKey.KeyBase64)
	if err != nil {
		return nil, nil, err
	}
	iv, err := base64.StdEncoding.DecodeString(encKey.IvBase64)
	if err != nil {
		return nil, nil, err
	}

	return key, iv, nil
}

func DecryptFile(filename string) error {
	// Get key
	key, iv, err := GetEncryptionKey()
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

func EncryptFile(filename string) error {
	// 1. Get Encryption Key and IV
	key, iv, err := GetEncryptionKey()
	if err != nil {
		return err
	}

	// 2. Open the Source File for Reading
	srcFile, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	// 3. Create the Destination File for Writing
	encFilename := filename + ".enc"
	dstFile, err := os.Create(encFilename)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	// 4. Initialize AES Cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	// 5. Initialize CBC Mode for Encryption
	mode := cipher.NewCBCEncrypter(block, iv)

	// 6. Stream the File
	buf := make([]byte, mode.BlockSize()*1024) // Adjust the buffer size as needed
	for {
		n, err := srcFile.Read(buf)
		if err != nil && err != io.EOF {
			return err
		}
		if n == 0 {
			break
		}

		// Apply PKCS#7 padding if this is the last chunk
		// Apply PKCS#7 padding if this is the last chunk
		if n < len(buf) || err == io.EOF {
			padding := mode.BlockSize() - n%mode.BlockSize()
			padText := bytes.Repeat([]byte{byte(padding)}, padding)
			buf = append(buf[:n], padText...)
			mode.CryptBlocks(buf, buf)
			dstFile.Write(buf)
			break
		}

		// Encrypt and write the chunk
		mode.CryptBlocks(buf, buf)
		if _, err := dstFile.Write(buf); err != nil {
			return err
		}
	}

	return nil
}

// #endregion Encryption

// #region Google

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
	Web ClientCredentials `json:"web"`
}
type ClientCredentials struct {
	ClientID      string `json:"client_id"`
	ClientSecret  string `json:"client_secret"`
	TokenUri      string `json:"token_uri"`
	RefreshTokens map[string]string
	AccessTokens  map[string]AccessToken
}

func GetClientCredentialsFromOAuthJson() (ClientCredentials, error) {

	err := DecryptFile("Credentials_OAuthClient.json.enc")
	if err != nil {
		fmt.Println("Error decrypting file:", err)
		return ClientCredentials{}, err
	}
	defer os.Remove("Credentials_OAuthClient.json")

	var c ClientCredentials
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

func (c *ClientCredentials) GetAccessToken(user string) (AccessToken, error) {
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

	if tokenResp.AccessToken == "" {
		return c.AccessTokens[user], fmt.Errorf("access token is empty for user %s. Refresh token might be expired.", user)
	}

	return c.AccessTokens[user], nil
}

func (c *ClientCredentials) GetRefreshTokensMap() (map[string]string, error) {

	err := DecryptFile("Credentials_UsersRefreshTokens.json.enc")
	if err != nil {
		return nil, err
	}
	defer os.Remove("Credentials_UsersRefreshTokens.json")

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

// #region Drive

type Files struct {
	Files         []File `json:"files"`
	NextPageToken string `json:"nextPageToken,omitempty"`
}
type File struct {
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

func ListFiles(accessToken string) (Files, error) {
	var allFiles Files
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

		var pageFiles Files
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

func TransferOwnership(fileID string, accessToken string, newOwnerEmail string) error {
	url := "https://www.googleapis.com/drive/v3/files/" + fileID + "/permissions"
	req, err := http.NewRequest("POST", url, strings.NewReader(`{
		"role": "owner",
		"type": "user",
		"emailAddress": "`+newOwnerEmail+`",
		"transferOwnership": true
	}`))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("transfer ownership failed: %s", resp.Status)
	}

	return nil
}

type StorageQuota struct {
	Limit             int64
	UsageInDrive      int64
	Usage             int64
	UsageInDriveTrash int64
	Free              int64
}

func GetStorageQuota(accessToken string) (StorageQuota, error) {
	var quota StorageQuota
	url := "https://www.googleapis.com/drive/v3/about?fields=storageQuota"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return quota, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return quota, err
	}
	defer resp.Body.Close()
	//////VMT
	//bodyBytes, _ := io.ReadAll(resp.Body)
	//fmt.Println(string(bodyBytes))
	//////VMT
	var quotaAsStrings struct {
		StorageQuota struct {
			Limit             string `json:"limit"`
			UsageInDrive      string `json:"usageInDrive"`
			Usage             string `json:"usage"`
			UsageInDriveTrash string `json:"usageInDriveTrash"`
		} `json:"storageQuota"`
	}
	err = json.NewDecoder(resp.Body).Decode(&quotaAsStrings)
	if err != nil {
		return quota, err
	}
	quota.Limit, err = strconv.ParseInt(quotaAsStrings.StorageQuota.Limit, 10, 64)
	if err != nil {
		return quota, err
	}
	quota.UsageInDrive, err = strconv.ParseInt(quotaAsStrings.StorageQuota.UsageInDrive, 10, 64)
	if err != nil {
		return quota, err
	}
	quota.Usage, err = strconv.ParseInt(quotaAsStrings.StorageQuota.Usage, 10, 64)
	if err != nil {
		return quota, err
	}
	quota.UsageInDriveTrash, err = strconv.ParseInt(quotaAsStrings.StorageQuota.UsageInDriveTrash, 10, 64)
	if err != nil {
		return quota, err
	}
	quota.Free = quota.Limit - quota.Usage

	return quota, nil
}

func (quota StorageQuota) SeeInGigaBytes() string {
	return fmt.Sprintf("Limit: %.2f GB, UsageInDrive: %.2f GB, Usage: %.2f GB, UsageInDriveTrash: %.2f GB, Free: %.2f GB",
		float64(quota.Limit)/(1<<30), float64(quota.UsageInDrive)/(1<<30), float64(quota.Usage)/(1<<30), float64(quota.UsageInDriveTrash)/(1<<30), float64(quota.Free)/(1<<30))
}

func (f File) StreamDownload(accessToken string) (io.ReadCloser, error) {
	req, err := http.NewRequest("GET", "https://www.googleapis.com/drive/v3/files/"+f.Id+"?alt=media", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	// The caller is responsible for closing the response body
	fmt.Println("Remenber to close the response body")
	return resp.Body, nil
}

func (f File) Download(accessToken string, filepath string) error {
	ioReader, err := f.StreamDownload(accessToken)
	if err != nil {
		return err
	}
	defer ioReader.Close()

	file, err := os.Create(filepath + f.Name)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = io.Copy(file, ioReader)
	if err != nil {
		return err
	}

	return nil
}

func SimpleUploadFileAsStream(accessToken string, ioReader io.Reader, filename string) (File, error) {
	url := "https://www.googleapis.com/upload/drive/v3/files?uploadType=media"
	req, err := http.NewRequest("POST", url, ioReader)
	if err != nil {
		return File{}, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Content-Length", "0") // Required for POST requests

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return File{}, err
	}
	defer resp.Body.Close()

	var file File
	if err := json.NewDecoder(resp.Body).Decode(&file); err != nil {
		return File{}, err
	}

	return file, nil
}

// Multipart Upload
func UploadFileAsStream(accessToken string, ioReader io.Reader, filename string, hash string) (File, error) {
	url := "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart"

	var requestBody bytes.Buffer
	multipartWriter := multipart.NewWriter(&requestBody)

	// Part 1: JSON Metadata
	metadataPart, err := multipartWriter.CreatePart(textproto.MIMEHeader{
		"Content-Type": []string{"application/json; charset=UTF-8"},
	})
	if err != nil {
		return File{}, err
	}
	//hash, err := CalculateSHA256Hash(ioReader)
	//if err != nil {
	//	return File{}, err
	//}
	metadata := map[string]interface{}{
		"name":        filename,
		"description": hash,
		"appProperties": map[string]string{
			"SHA256": hash,
		},
	}
	if err := json.NewEncoder(metadataPart).Encode(metadata); err != nil {
		return File{}, err
	}

	// Part 2: File Content
	filePart, err := multipartWriter.CreateFormFile("file", filename)
	if err != nil {
		return File{}, err
	}
	if _, err := io.Copy(filePart, ioReader); err != nil {
		return File{}, err
	}

	// Finalize the multipart message
	if err := multipartWriter.Close(); err != nil {
		return File{}, err
	}

	req, err := http.NewRequest("POST", url, &requestBody)
	if err != nil {
		return File{}, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", multipartWriter.FormDataContentType())

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return File{}, err
	}
	defer resp.Body.Close()

	var file File
	if err := json.NewDecoder(resp.Body).Decode(&file); err != nil {
		return File{}, err
	}

	return file, nil
}

// #endregion Drive

// #region Photos
type MediaItem struct {
	Id            string `json:"id"`
	Description   string `json:"description"`
	ProductUrl    string `json:"productUrl"`
	BaseUrl       string `json:"baseUrl"`
	MimeType      string `json:"mimeType"`
	Filename      string `json:"filename"`
	FileSize      int64
	MediaMetadata struct {
		CreationTime string `json:"creationTime"`
		Width        string `json:"width"`
		Height       string `json:"height"`
	} `json:"mediaMetadata"`
	ContributorInfo struct {
		ProfilePictureBaseUrl string `json:"profilePictureBaseUrl"`
		DisplayName           string `json:"displayName"`
	} `json:"contributorInfo"`
}
type MediaItems struct {
	MediaItems    []MediaItem `json:"mediaItems"`
	NextPageToken string      `json:"nextPageToken,omitempty"`
}

func ListMediaItems(accessToken string) (MediaItems, error) {
	var allMediaItems MediaItems
	url := "https://photoslibrary.googleapis.com/v1/mediaItems" + "?fields=nextPageToken,mediaItems(id,description,productUrl,baseUrl,mimeType,filename,mediaMetadata(creationTime,width,height))"
	for {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return allMediaItems, err
		}
		req.Header.Set("Authorization", "Bearer "+accessToken)

		// Add query parameters if nextPageToken exists
		q := req.URL.Query()
		if allMediaItems.NextPageToken != "" {
			q.Add("pageToken", allMediaItems.NextPageToken)
		}
		req.URL.RawQuery = q.Encode()

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return allMediaItems, err
		}
		defer resp.Body.Close()

		////VMT
		//bodyBytes, _ := io.ReadAll(resp.Body)
		//fmt.Println(string(bodyBytes))
		////VMT

		var pageMediaItems MediaItems
		if err := json.NewDecoder(resp.Body).Decode(&pageMediaItems); err != nil {
			return allMediaItems, err
		}

		// Append the files from the current page to the allFiles
		allMediaItems.MediaItems = append(allMediaItems.MediaItems, pageMediaItems.MediaItems...)

		// Break the loop if there is no nextPageToken
		if pageMediaItems.NextPageToken == "" {
			break
		} else {
			allMediaItems.NextPageToken = pageMediaItems.NextPageToken
			//VMT for testing break
		}
	}

	return allMediaItems, nil
}

func (m *MediaItem) GetFileSize(accessToken string) (int64, error) {
	baseUrl := m.BaseUrl + "=d"
	req, err := http.NewRequest("HEAD", baseUrl, nil)
	if err != nil {
		return 0, err
	}

	req.Header.Add("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	// Check if Content-Length header is present
	contentLength := resp.Header.Get("Content-Length")
	if contentLength == "" {
		return 0, errors.New("Content-Length header is missing")
	}

	// Convert Content-Length to int64
	size, err := strconv.ParseInt(contentLength, 10, 64)
	if err != nil {
		return 0, err
	}

	// Update the FileSize field in the original MediaItem struct
	m.FileSize = size
	return size, nil
}

func (m MediaItem) StreamDownload(accessToken string) (io.ReadCloser, error) {
	var baseUrl string
	if strings.HasPrefix(m.MimeType, "image/") {
		baseUrl = m.BaseUrl + "=d"
	} else if strings.HasPrefix(m.MimeType, "video/") {
		baseUrl = m.BaseUrl + "=dv"
	} else {
		return nil, errors.New("unsupported media type")
	}
	req, err := http.NewRequest("GET", baseUrl, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	// The caller is responsible for closing the response body
	fmt.Println("Remenber to close the response body")
	return resp.Body, nil
}

func (m MediaItem) Download(accessToken string, filepath string, filename string) error {
	ioReader, err := m.StreamDownload(accessToken)
	if err != nil {
		return err
	} else if ioReader == nil {
		return errors.New("failed to stream download")
	}
	defer ioReader.Close()

	file, err := os.Create(filepath + filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = io.Copy(file, ioReader)
	if err != nil {
		return err
	}

	return nil
}

func (m MediaItems) GetMediaItemIds() []string {
	var ids []string
	for _, item := range m.MediaItems {
		ids = append(ids, item.Id)
	}
	return ids
}

type SharedAlbum struct {
	Id              string `json:"id"`
	Title           string `json:"title"`
	MediaItemsCount int    `json:"mediaItemsCount"`
	ProductUrl      string `json:"productUrl"`
}

func GetSharedAlbums(accessToken string) ([]SharedAlbum, error) {
	var sharedAlbums []SharedAlbum
	url := "https://photoslibrary.googleapis.com/v1/sharedAlbums"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return sharedAlbums, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return sharedAlbums, err
	}
	defer resp.Body.Close()

	////VMT
	//bodyBytes, _ := io.ReadAll(resp.Body)
	//fmt.Println(string(bodyBytes))
	////VMT

	type SharedAlbum_WithStringMediaItemsCount struct {
		Id              string `json:"id"`
		Title           string `json:"title"`
		MediaItemsCount string `json:"mediaItemsCount"`
		ProductUrl      string `json:"productUrl"`
	}

	var albums_WithStringMediaItemsCount struct {
		SharedAlbums []SharedAlbum_WithStringMediaItemsCount `json:"sharedAlbums"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&albums_WithStringMediaItemsCount); err != nil {
		return sharedAlbums, err
	}

	var albums []SharedAlbum
	for _, album := range albums_WithStringMediaItemsCount.SharedAlbums {
		fmt.Print(album.MediaItemsCount) //VMT
		if album.MediaItemsCount == "" {
			album.MediaItemsCount = "0"
		}

		mediaItemsCount_AsInt, err := strconv.Atoi(album.MediaItemsCount)
		if err != nil {
			return sharedAlbums, err
		}
		albums = append(albums, SharedAlbum{Id: album.Id, Title: album.Title, MediaItemsCount: mediaItemsCount_AsInt, ProductUrl: album.ProductUrl})
	}

	return albums, nil
}

func GetAlbumMediaItems(accessToken string, albumId string) (MediaItems, error) {
	var allMediaItems MediaItems
	url := "https://photoslibrary.googleapis.com/v1/mediaItems:search"

	// Initialize requestBody outside the loop
	requestBody := map[string]interface{}{
		"albumId":  albumId,
		"pageSize": 50, // Optional: Adjust pageSize as needed
	}

	for {
		// Update requestBody with nextPageToken if it exists
		if allMediaItems.NextPageToken != "" {
			requestBody["pageToken"] = allMediaItems.NextPageToken
		}

		requestBodyBytes, err := json.Marshal(requestBody)
		if err != nil {
			return allMediaItems, err
		}

		req, err := http.NewRequest("POST", url, bytes.NewBuffer(requestBodyBytes))
		if err != nil {
			return allMediaItems, err
		}
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return allMediaItems, err
		}
		defer resp.Body.Close()

		var pageMediaItems MediaItems
		if err := json.NewDecoder(resp.Body).Decode(&pageMediaItems); err != nil {
			return allMediaItems, err
		}

		allMediaItems.MediaItems = append(allMediaItems.MediaItems, pageMediaItems.MediaItems...)

		// Update the nextPageToken for the next iteration
		allMediaItems.NextPageToken = pageMediaItems.NextPageToken

		// Break the loop if there is no nextPageToken
		if pageMediaItems.NextPageToken == "" {
			break
		} else {
			break //VMT for testing
		}
	}

	return allMediaItems, nil
}

func CreateAlbum(accessToken string, title string) (string, error) {
	url := "https://photoslibrary.googleapis.com/v1/albums"
	jsonPayload := fmt.Sprintf(`{
		"album": {
			"title": "%s"
		}
	}`, title)

	req, err := http.NewRequest("POST", url, strings.NewReader(jsonPayload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	////VMT
	//bodyBytes, _ := io.ReadAll(resp.Body)
	//fmt.Println(string(bodyBytes))
	////VMT

	var album struct {
		Id string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&album); err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("failed to create album: %s", resp.Status)
	}

	return album.Id, nil
}

func AddMediaItemsToAlbum(accessToken string, albumId string, mediaItemIds []string) error {
	const batchSize = 50
	for i := 0; i < len(mediaItemIds); i += batchSize {
		end := i + batchSize
		if end > len(mediaItemIds) {
			end = len(mediaItemIds)
		}
		batch := mediaItemIds[i:end]

		url := "https://photoslibrary.googleapis.com/v1/albums/" + albumId + ":batchAddMediaItems"
		jsonPayload := fmt.Sprintf(`{
			"mediaItemIds": [%s]
		}`, "\""+strings.Join(batch, "\",\"")+"\"")

		fmt.Print(jsonPayload) //VMT

		req, err := http.NewRequest("POST", url, strings.NewReader(jsonPayload))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		////VMT
		bodyBytes, _ := io.ReadAll(resp.Body)
		fmt.Println(string(bodyBytes))
		////VMT

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
			return fmt.Errorf("failed to add media items to album in batch %d-%d: %s", i, end-1, resp.Status)
		}
	}
	return nil
}

func RemoveMediaItemsFromAlbum(accessToken string, albumId string, mediaItemIds []string) error {
	const batchSize = 50
	for i := 0; i < len(mediaItemIds); i += batchSize {
		end := i + batchSize
		if end > len(mediaItemIds) {
			end = len(mediaItemIds)
		}
		batch := mediaItemIds[i:end]

		url := "https://photoslibrary.googleapis.com/v1/albums/" + albumId + ":batchRemoveMediaItems"
		jsonPayload := fmt.Sprintf(`{
			"mediaItemIds": [%s]
		}`, "\""+strings.Join(batch, "\",\"")+"\"")

		req, err := http.NewRequest("POST", url, strings.NewReader(jsonPayload))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
			return fmt.Errorf("failed to remove media items from album in batch %d-%d: %s", i, end-1, resp.Status)
		}
	}
	return nil
}

type ShareInfo struct {
	SharedAlbumOptions struct {
		IsCollaborative bool `json:"isCollaborative"`
		IsCommentable   bool `json:"isCommentable"`
	} `json:"sharedAlbumOptions"`
	ShareableUrl string `json:"shareableUrl"`
	ShareToken   string `json:"shareToken"`
	IsJoined     bool   `json:"isJoined"`
	IsOwned      bool   `json:"isOwned"`
	IsJoinable   bool   `json:"isJoinable"`
}

func ShareAlbum(accessToken string, albumId string) (ShareInfo, error) {
	var ShareInfo ShareInfo
	url := "https://photoslibrary.googleapis.com/v1/albums/" + albumId + ":share"
	req, err := http.NewRequest("POST", url, strings.NewReader(`{
			"sharedAlbumOptions": {
				"isCollaborative": true,
				"isCommentable": true
			}
		}`))
	if err != nil {
		return ShareInfo, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ShareInfo, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return ShareInfo, fmt.Errorf("failed to share album: %s", resp.Status)
	}

	if err := json.NewDecoder(resp.Body).Decode(&ShareInfo); err != nil {
		return ShareInfo, err
	}

	return ShareInfo, nil
}

func JoinSharedAlbum(accessToken string, shareToken string) error {
	url := "https://photoslibrary.googleapis.com/v1/sharedAlbums:join"
	req, err := http.NewRequest("POST", url, strings.NewReader(`{
		"shareToken": "`+shareToken+`"
	}`))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed to join shared album: %s", resp.Status)
	}

	return nil
}

func UploadMediaItem(accessToken string, filepath string, filename string) (MediaItem, error) {
	// 1. Open the file for reading
	file, err := os.Open(filepath + filename)
	if err != nil {
		return MediaItem{}, err
	}
	defer file.Close()

	// 2. Create the request
	url := "https://photoslibrary.googleapis.com/v1/uploads"
	req, err := http.NewRequest("POST", url, file)
	if err != nil {
		return MediaItem{}, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Goog-Upload-File-Name", filename)

	// 3. Execute the request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return MediaItem{}, err
	}
	defer resp.Body.Close()

	// 4. Read the response body
	uploadToken, err := io.ReadAll(resp.Body)
	if err != nil {
		return MediaItem{}, err
	}

	// 5. Create the media item
	url = "https://photoslibrary.googleapis.com/v1/mediaItems:batchCreate"
	jsonPayload := fmt.Sprintf(`{
		"newMediaItems": [
			{
				"description": "%s",
				"simpleMediaItem": {
					"uploadToken": "%s"
				}
			}
		]
	}`, filename, uploadToken)

	req, err = http.NewRequest("POST", url, strings.NewReader(jsonPayload))
	if err != nil {
		return MediaItem{}, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return MediaItem{}, err
	}
	defer resp.Body.Close()

	// 6. Decode the response
	var mediaItem struct {
		NewMediaItemResults []MediaItem `json:"newMediaItemResults"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&mediaItem); err != nil {
		return MediaItem{}, err
	}

	return mediaItem.NewMediaItemResults[0], nil
}

func UploadMediaItemAsStream(accessToken string, ioReader io.Reader, filename string) (MediaItem, error) {
	// 1. Create the request
	url := "https://photoslibrary.googleapis.com/v1/uploads"
	req, err := http.NewRequest("POST", url, ioReader)
	if err != nil {
		return MediaItem{}, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Goog-Upload-File-Name", filename)

	// 2. Execute the request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return MediaItem{}, err
	}
	defer resp.Body.Close()

	// 3. Read the response body
	uploadToken, err := io.ReadAll(resp.Body)
	if err != nil {
		return MediaItem{}, err
	}

	// 4. Create the media item
	url = "https://photoslibrary.googleapis.com/v1/mediaItems:batchCreate"
	jsonPayload := fmt.Sprintf(`{
		"newMediaItems": [
			{
				"description": "%s",
				"simpleMediaItem": {
					"uploadToken": "%s"
				}
			}
		]
	}`, filename, uploadToken)

	req, err = http.NewRequest("POST", url, strings.NewReader(jsonPayload))
	if err != nil {
		return MediaItem{}, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return MediaItem{}, err
	}
	defer resp.Body.Close()

	// 5. Decode the response
	////VMT
	//bodyBytes, _ := io.ReadAll(resp.Body)
	//fmt.Println(string(bodyBytes))
	////VMT

	type MediaItemResult struct {
		UploadToken string `json:"uploadToken"`
		Status      struct {
			Message string `json:"message"`
		} `json:"status"`
		MediaItem MediaItem `json:"mediaItem"`
	}

	type Response struct {
		NewMediaItemResults []MediaItemResult `json:"newMediaItemResults"`
	}

	// Assuming resp.Body is the body of the HTTP response
	var response Response
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		// Handle error
		return MediaItem{}, err
	}

	return response.NewMediaItemResults[0].MediaItem, nil
}

// #endregion Photos

// #endregion Google

// #region Whatsapp
type WhatsappCredentials struct {
	AccessToken string `json:"admin-system-user-access-token"`
	To          int    `json:"to-whatsapp-number"`
}

func GetWhatsappCredentials() (WhatsappCredentials, error) {

	var WhatsappCredentials WhatsappCredentials

	if err := DecryptFile("Credentials_Whatsapp.json.enc"); err != nil {
		fmt.Println("Error decrypting file:", err)
		return WhatsappCredentials, err
	}
	defer os.Remove("Credentials_Whatsapp.json")

	file, err := os.Open("Credentials_Whatsapp.json")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return WhatsappCredentials, err
	}
	defer file.Close()

	if err := json.NewDecoder(file).Decode(&WhatsappCredentials); err != nil {
		fmt.Println("Error decoding JSON:", err)
		return WhatsappCredentials, err
	}

	return WhatsappCredentials, nil
}

func SendWhatsappMessage(accessToken string, message string, to int) error {
	url := "https://graph.facebook.com/v19.0/387981631054756/messages"
	body := fmt.Sprintf(`{
		"messaging_product": "whatsapp",
		"to": "%d",
		"type": "text",
		"text": {
			"preview_url": false,
			"body": "%s"
		}
	}`, to, message)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(body)))
	if err != nil {
		return err
	}

	req.Header.Add("Authorization", "Bearer "+accessToken)
	req.Header.Add("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %v", err)
		}
		bodyMessage := string(bodyBytes)
		return fmt.Errorf("failed to send WhatsApp message, status code: %d, message: %s", resp.StatusCode, bodyMessage)
	}

	return nil
}

// #endregion Whatsapp

// #region ngrok
type NgrokCredentials struct {
	AuthToken      string `json:"authToken"`
	WithForwardsTo string `json:"withForwardsTo"`
	WithDomain     string `json:"withDomain"`
}

func GetNgrokCredentials() (NgrokCredentials, error) {

	var c NgrokCredentials

	if err := DecryptFile("Credentials_Ngrok.json.enc"); err != nil {
		fmt.Println("Error decrypting file:", err)
		return NgrokCredentials{}, err
	}
	defer os.Remove("Credentials_Ngrok.json")

	file, err := os.Open("Credentials_Ngrok.json")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return c, err
	}
	defer file.Close()

	if err := json.NewDecoder(file).Decode(&c); err != nil {
		fmt.Println("Error decoding JSON:", err)
		return c, err
	}

	return c, nil
}

func NgrokHandler() {
	ngrokCredentials, err := GetNgrokCredentials()
	if err != nil {
		fmt.Println("Error getting ngrok credentials:", err)
		return
	}
	ngrokAuth := ngrok.WithAuthtoken(ngrokCredentials.AuthToken)
	tunnel := config.HTTPEndpoint(
		config.WithForwardsTo(ngrokCredentials.WithForwardsTo),
		config.WithDomain(ngrokCredentials.WithDomain),
		config.WithScheme(config.SchemeHTTPS),
		/*
			config.WithAllowCIDRString("0.0.0.0/0"),
			config.WithAllowUserAgent("Mozilla/5.0.*"),
			// config.WithBasicAuth("ngrok", "online1line"),
			config.WithCircuitBreaker(0.5),
			config.WithCompression(),
			config.WithDenyCIDRString("10.1.1.1/32"),
			config.WithDenyUserAgent("EvilCorp.*"),
			// config.WithDomain("<somedomain>.ngrok.io"),
			config.WithMetadata("example secure connection metadata from golang"),
			// config.WithMutualTLSCA(<cert>),
			// config.WithOAuth("google",
			// 	config.WithAllowOAuthEmail("<user>@<domain>"),
			// 	config.WithAllowOAuthDomain("<domain>"),
			// 	config.WithOAuthScope("<scope>"),
			// ),
			// config.WithOIDC("<url>", "<id>", "<secret>",
			// 	config.WithAllowOIDCEmail("<user>@<domain>"),
			// 	config.WithAllowOIDCDomain("<domain>"),
			// 	config.WithOIDCScope("<scope>"),
			// ),
			config.WithProxyProto(config.ProxyProtoNone),
			config.WithRemoveRequestHeader("X-Req-Nope"),
			config.WithRemoveResponseHeader("X-Res-Nope"),
			config.WithRequestHeader("X-Req-Yup", "true"),
			config.WithResponseHeader("X-Res-Yup", "true"),
			config.WithScheme(config.SchemeHTTPS),
			// config.WithWebsocketTCPConversion(),
			// config.WithWebhookVerification("twilio", "asdf"),
		*/
	)
	ln, err := ngrok.Listen(context.Background(), tunnel, ngrokAuth)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Ingress established at:", ln.URL())
	http.HandleFunc("/", Handler)
	log.Fatal(http.Serve(ln, nil))
}

func Handler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Hello from ngrok-go!"))
}

// #endregion ngrok

// #region SQLite

func GetSQLiteConnection() (*sql.DB, error) {

	// Check if the file exists
	if _, err := os.Stat("sqlite.db.enc"); err == nil {
		if err := DecryptFile("sqlite.db.enc"); err != nil {
			fmt.Println("Error decrypting file:", err)
			return nil, err
		}
		fmt.Println("Remember to: \n defer EncryptFile(\"sqlite.db\") \n defer os.Remove(\"sqlite.db\")")
	}

	db, err := sql.Open("sqlite", "sqlite.db")
	if err != nil {
		fmt.Println("Error opening SQLite connection:", err)
		return nil, err
	}
	return db, nil
}

func CreateSQLiteTables(db *sql.DB) error {
	tables := []string{"GoogleDriveFiles", "GooglePhotosMediaItems"}

	for _, table := range tables {
		var tableCreationQuery string
		switch table {
		case "GoogleDriveFiles":
			tableCreationQuery = `CREATE TABLE IF NOT EXISTS GoogleDriveFiles (
				id TEXT PRIMARY KEY,
				name TEXT,
				mimeType TEXT,
				size INTEGER,
				ownerDisplayName TEXT,
				ownerEmailAddress TEXT
			)`
		case "GooglePhotosMediaItems":
			tableCreationQuery = `CREATE TABLE IF NOT EXISTS GooglePhotosMediaItems (
				id TEXT PRIMARY KEY,
				description TEXT,
				productUrl TEXT,
				baseUrl TEXT,
				mimeType TEXT,
				filename TEXT,
				fileSize INTEGER,
				creationTime TEXT,
				width TEXT,
				height TEXT
			)`
		default:
			return errors.New("invalid SQL table name")
		}

		_, err := db.Exec(tableCreationQuery)
		if err != nil {
			fmt.Println("Error creating table:", err)
			return err
		}
	}
	return nil
}

func (MediaItems MediaItems) GetValuesSlicesForSqlInsert() [][]interface{} {
	var values [][]interface{}
	for _, m := range MediaItems.MediaItems {
		values = append(values, []interface{}{m.Id, m.Description, m.ProductUrl, m.BaseUrl, m.MimeType, m.Filename, m.FileSize, m.MediaMetadata.CreationTime, m.MediaMetadata.Width, m.MediaMetadata.Height})
	}
	return values
}

func (Files Files) GetValuesSlicesForSqlInsert() [][]interface{} {
	var values [][]interface{}
	for _, f := range Files.Files {
		values = append(values, []interface{}{f.Id, f.Name, f.MimeType, f.Size, f.Owners[0].DisplayName, f.Owners[0].EmailAddress})
	}
	return values
}

type SqlValuesGenerator interface {
	GetValuesSlicesForSqlInsert() [][]interface{}
}

func InsertOrUpdateInSQLiteTable(data SqlValuesGenerator) error {
	var tableName string
	var columns []string
	switch data.(type) {
	case MediaItems:
		tableName = "GooglePhotosMediaItems"
		columns = []string{"id", "description", "productUrl", "baseUrl", "mimeType", "filename", "fileSize", "creationTime", "width", "height"}
	case Files:
		tableName = "GoogleDriveFiles"
		columns = []string{"id", "name", "mimeType", "size", "ownerDisplayName", "ownerEmailAddress"}
	default:
		panic("invalid data type in InsertOrUpdateInSQLiteTable")
	}

	// Generate placeholders for INSERT VALUES
	insertPlaceholders := strings.Repeat("?, ", len(columns)-1) + "?"

	// Generate placeholders for ON CONFLICT DO UPDATE SET
	conflictColumns := columns[1:] // Exclude 'id' for the ON CONFLICT part
	updatePlaceholders := make([]string, len(conflictColumns))
	for i, col := range conflictColumns {
		updatePlaceholders[i] = fmt.Sprintf("%s = ?", col)
	}
	updatePlaceholderStr := strings.Join(updatePlaceholders, ", ")

	// Construct the full SQL statement
	sqlStatement := fmt.Sprintf(`INSERT INTO %s (%s) VALUES (%s)
		ON CONFLICT(id) DO UPDATE SET %s`, tableName, strings.Join(columns, ", "), insertPlaceholders, updatePlaceholderStr)

	db, err := GetSQLiteConnection()
	if err != nil {
		return err
	}
	defer db.Close()

	rows := data.GetValuesSlicesForSqlInsert()

	for _, row := range rows {
		_, err := db.Exec(sqlStatement, append(row, row[1:]...)...)
		if err != nil {
			fmt.Println("Error inserting row: ", row)
			return err
		}
	}

	return nil
}

// #endregion SQLite

// #region Others
func CalculateSHA256Hash(ioReader io.Reader) (string, error) {
	hasher := sha256.New()
	if _, err := io.Copy(hasher, ioReader); err != nil {
		return "", err
	}
	hashBytes := hasher.Sum(nil)
	hashString := hex.EncodeToString(hashBytes)
	return hashString, nil
}

// #endregion Others
