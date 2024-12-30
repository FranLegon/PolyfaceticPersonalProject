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

const (
	mainAccount = "franlegon.backup10@gmail.com"
)

var backupAccounts = []string{"franlegon.backup11@gmail.com"}

// #region main (testing)

func main() {
	//decript ngrok creds json file
	//if err := DecryptFile("Credentials_OAuthClient.json.enc"); err != nil {
	//	log.Fatal(err)
	//}

	GoogleCredentials, err := GetClientCredentialsFromOAuthJson()
	if err != nil {
		fmt.Println("Error getting client credentials:", err)
		return
	}
	accessTokenMain, err := GoogleCredentials.GetAccessToken(mainAccount)
	if err != nil {
		fmt.Println("Error getting access token:", err)
		return
	}

	if err := FillSQLiteTableFromGoogleDrive(accessTokenMain.AccessToken); err != nil {
		fmt.Println("Error filling SQLite table:", err)
		return
	}

	/*
		if err := ShareAllFoldersFromMainAccountToAllBackupAccounts(); err != nil {
			log.Fatal(err)
		}
	*/

	if err := TransferAllFilesFromMainAccountToABackupAccount(); err != nil {
		log.Fatal(err)
	}

}

// #endregion main (testing)

// #region main process
func ShareAllFoldersFromMainAccountToAllBackupAccounts() error {
	GoogleCredentials, err := GetClientCredentialsFromOAuthJson()
	if err != nil {
		fmt.Println("Error getting client credentials:", err)
		return err
	}
	accessTokenMain, err := GoogleCredentials.GetAccessToken(mainAccount)
	if err != nil {
		fmt.Println("Error getting access token:", err)
		return err
	}
	// Query ids of folders to share from sqlite
	db, err := GetSQLiteConnection()
	if err != nil {
		fmt.Println("Error getting SQLite connection:", err)
		return err
	}
	defer db.Close()
	query := fmt.Sprintf("SELECT id FROM [main].[GoogleDriveFiles] WHERE [mimeType] = 'application/vnd.google-apps.folder' AND [ownerEmailAddress] = '%s'", mainAccount)
	rows, err := db.Query(query)
	if err != nil {
		fmt.Println("Error querying folders:", err)
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var folderID string
		if err := rows.Scan(&folderID); err != nil {
			fmt.Println("Error scanning folder id:", err)
			return err
		}
		for _, backupAccount := range backupAccounts {
			err = ShareFileOrFolder(folderID, accessTokenMain.AccessToken, backupAccount, "writer")
			if err != nil {
				fmt.Println("Error sharing folder:", err)
				return err
			}
		}
	}
	fmt.Println("All folders from main shared successfully with all backup accounts.")
	return nil
}

func TransferAllFilesFromMainAccountToABackupAccount() error {
	GoogleCredentials, err := GetClientCredentialsFromOAuthJson()
	if err != nil {
		fmt.Println("Error getting client credentials:", err)
		return err
	}
	accessTokenMain, err := GoogleCredentials.GetAccessToken(mainAccount)
	if err != nil {
		fmt.Println("Error getting access token:", err)
		return err
	}

	// Query ids of files to transfer from sqlite
	db, err := GetSQLiteConnection()
	if err != nil {
		fmt.Println("Error getting SQLite connection:", err)
		return err
	}
	defer db.Close()
	query := fmt.Sprintf("SELECT id, name, mimeType, description, ownerEmailAddress, parents FROM [main].[GoogleDriveFiles] WHERE [mimeType] != 'application/vnd.google-apps.folder' AND [ownerEmailAddress] = '%s'", mainAccount)
	rows, err := db.Query(query)
	if err != nil {
		fmt.Println("Error querying files:", err)
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var file File
		var parents string
		file.Owners = make([]struct {
			DisplayName  string `json:"displayName"`
			EmailAddress string `json:"emailAddress"`
		}, 1)
		if err := rows.Scan(&file.Id, &file.Name, &file.MimeType, &file.Description, &file.Owners[0].EmailAddress, &parents); err != nil {
			fmt.Println("Error scanning file metadata:", err)
			return err
		}
		file.Parents = strings.Split(parents, ",")
		// query permisions of file
		permissions, err := QuerySharedWithAndRole(file.Id, accessTokenMain.AccessToken)
		if err != nil {
			fmt.Println("Error querying permissions:", err)
			return err
		}

		// check if file is owned by main account, if it isnt, continue with next file
		if len(file.Owners) == 0 {
			fmt.Printf("File %s has no owners. Skipping file.\n", file.Name)
			return errors.New("file has no owners")
		} else if file.Owners[0].EmailAddress != mainAccount {
			fmt.Printf("File %s is owned by %s, not main account (%s). Skipping file.\n", file.Owners[0].EmailAddress, file.Name, mainAccount)
			continue
		}

		err = TransferFile(accessTokenMain.AccessToken, file, backupAccounts[0], permissions)
		if err != nil {
			fmt.Println("Error transferring file:", err)
			return err
		}
	}
	fmt.Println("All files from main transferred successfully to backup account.")
	return nil
}

// #endregion main process

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
	Name        string `json:"name"`
	Id          string `json:"id"`
	Kind        string `json:"kind"`
	MimeType    string `json:"mimeType"`
	Size        string `json:"size"`
	Description string `json:"description"`
	Owners      []struct {
		DisplayName  string `json:"displayName"`
		EmailAddress string `json:"emailAddress"`
	} `json:"owners"`
	Parents []string `json:"parents"`
}

func ListFiles(accessToken string) (Files, error) {
	var allFiles Files
	url := "https://www.googleapis.com/drive/v3/files" + "?fields=nextPageToken,files(id,name,kind,mimeType,owners,size,description,parents)"
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
	//fmt.Println("Remenber to close the response body")
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

func UploadFileAsStream(accessToken string, ioReader io.Reader, filename string, description string) (File, error) {
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
	metadata := map[string]interface{}{
		"name":        filename,
		"description": description,
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

func (file File) UploadFileAsStream(accessToken string) (File, error) {
	fileReader, err := file.StreamDownload(accessToken)
	if err != nil {
		return File{}, err
	}
	defer fileReader.Close()

	return UploadFileAsStream(accessToken, fileReader, file.Name, file.Description)
}

func DeleteFile(fileID string, accessToken string) error {
	url := "https://www.googleapis.com/drive/v3/files/" + fileID
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("delete file failed: %s", resp.Status)
	}

	return nil
}

func TransferFile(actualOwnerAccessToken string, file File, newOwnerEmail string, permissions []Permission) error {
	ClientCredentials, err := GetClientCredentialsFromOAuthJson()
	if err != nil {
		return err
	}
	newOwnerAccess, err := ClientCredentials.GetAccessToken(newOwnerEmail)
	if err != nil {
		return err
	}
	newOwnerAccessToken := newOwnerAccess.AccessToken
	fileReader, err := file.StreamDownload(actualOwnerAccessToken)
	if err != nil {
		fmt.Println("Error streaming download:", err)
		return err
	}
	defer fileReader.Close()
	newFile, err := UploadFileAsStream(newOwnerAccessToken, fileReader, file.Name, file.Description)
	if err != nil {
		fmt.Println("Error uploading file:", err)
		return err
	}
	if err = DeleteFile(file.Id, actualOwnerAccessToken); err != nil {
		fmt.Printf("Error deleting file with id %s: %v\n", file.Id, err)
		return err
	}

	for _, parentID := range file.Parents {
		err = ShareFileOrFolder(parentID, actualOwnerAccessToken, newOwnerEmail, "writer")
		if err != nil {
			fmt.Printf("Error sharing folder with id %s (from parents \"%s\"): %v\n", parentID, file.Parents, err)
			return err
		}
	}
	if err = MoveFileToFolder(newOwnerAccessToken, newFile.Id, file.Parents); err != nil {
		fmt.Println("Error moving file to folder:", err)
		return err
	}

	for _, permission := range permissions {
		if permission.Role == "owner" {
			permission.Role = "writer"
		}
		if permission.EmailAddress == newOwnerEmail {
			continue
		}
		err = ShareFileOrFolder(newFile.Id, newOwnerAccessToken, permission.EmailAddress, permission.Role)
		if err != nil {
			fmt.Printf("Error sharing file with id %s: %v", newFile.Id, err)
			return err
		}
	}

	fmt.Printf("✔️ \"%s\" transferred successfully to %s", file.Name, newOwnerEmail)
	return nil
}

func ShareFileOrFolder(fileID string, accessToken string, email string, role string) error {
	url := "https://www.googleapis.com/drive/v3/files/" + fileID + "/permissions"
	req, err := http.NewRequest("POST", url, strings.NewReader(`{
		"role": "`+role+`",
		"type": "user",
		"emailAddress": "`+email+`"
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
		return fmt.Errorf("share file failed: %s", resp.Status)
	}

	return nil
}

func MoveFileToFolder(accessToken string, fileID string, folderIDs []string) error {
	url := "https://www.googleapis.com/drive/v3/files/" + fileID + "?addParents=" + strings.Join(folderIDs, ",") + "&removeParents=root"
	req, err := http.NewRequest("PATCH", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("MoveFileToFolder(%s, %s, %v)\nfailed: %s", accessToken, fileID, folderIDs, resp.Status)
	}

	return nil
}

type Permission struct {
	FileId           string
	ID               string `json:"id"`
	Type             string `json:"type"`
	Role             string `json:"role"`
	EmailAddress     string `json:"emailAddress,omitempty"`
	PermisionDetails struct {
		PermissionType string `json:"permissionType"`
		Role           string `json:"role"`
		Inherited      bool   `json:"inherited"`
	} `json:"permissionDetails"`
	Inherited bool
}

func QuerySharedWithAndRole(fileID string, accessToken string) ([]Permission, error) {
	url := "https://www.googleapis.com/drive/v3/files/" + fileID + "/permissions?fields=permissions(id,type,role,emailAddress,permissionDetails)"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var permissions struct {
		Permissions []Permission `json:"permissions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&permissions); err != nil {
		return nil, err
	}

	for i := range permissions.Permissions {
		permissions.Permissions[i].FileId = fileID
	}

	return permissions.Permissions, nil
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
	//fmt.Println("Remenber to close the response body")
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
	tables := []string{"GoogleDriveFiles", "GooglePhotosMediaItems", "GoogleDriveSharedWith"}

	for _, table := range tables {
		var tableCreationQuery string
		switch table {
		case "GoogleDriveFiles":
			tableCreationQuery = `CREATE TABLE IF NOT EXISTS GoogleDriveFiles (
				id TEXT PRIMARY KEY,
				name TEXT,
				mimeType TEXT,
				size INTEGER,
				description TEXT,
				ownerDisplayName TEXT,
				ownerEmailAddress TEXT,
				parents TEXT
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
		case "GoogleDriveSharedWith":
			tableCreationQuery = `CREATE TABLE IF NOT EXISTS GoogleDriveSharedWith (
                id TEXT PRIMARY KEY,
				fileId TEXT,
                sharedWithEmailAddress TEXT,
				role TEXT,
				inherited BOOLEAN,
                FOREIGN KEY (fileId) REFERENCES GoogleDriveFiles(id)
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

func (Files Files) GetValuesSlicesForSqlInsert() [][]interface{} {
	var values [][]interface{}
	for _, f := range Files.Files {
		values = append(values, []interface{}{f.Id, f.Name, f.MimeType, f.Size, f.Description, f.Owners[0].DisplayName, f.Owners[0].EmailAddress, strings.Join(f.Parents, ",")})
	}
	return values
}

func (MediaItems MediaItems) GetValuesSlicesForSqlInsert() [][]interface{} {
	var values [][]interface{}
	for _, m := range MediaItems.MediaItems {
		values = append(values, []interface{}{m.Id, m.Description, m.ProductUrl, m.BaseUrl, m.MimeType, m.Filename, m.FileSize, m.MediaMetadata.CreationTime, m.MediaMetadata.Width, m.MediaMetadata.Height})
	}
	return values
}

type Permissions struct {
	Permissions []Permission
}

func (Permissions Permissions) GetValuesSlicesForSqlInsert() [][]interface{} {
	var values [][]interface{}
	for _, p := range Permissions.Permissions {
		values = append(values, []interface{}{p.FileId + " - " + p.EmailAddress, p.FileId, p.EmailAddress, p.Role, p.Inherited})
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
		columns = []string{"id", "name", "mimeType", "size", "description", "ownerDisplayName", "ownerEmailAddress", "parents"}
	case Permissions:
		tableName = "GoogleDriveSharedWith"
		columns = []string{"id", "fileId", "sharedWithEmailAddress", "role", "inherited"}
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

func FillSQLiteTableFromGoogleDrive(accessToken string) error {
	//if db does not exist, create it and create tables in it
	db, err := GetSQLiteConnection()
	if err != nil {
		return err
	}
	defer db.Close()

	if err = CreateSQLiteTables(db); err != nil {
		return err
	}

	files, err := ListFiles(accessToken)
	if err != nil {
		return err
	}
	if err = InsertOrUpdateInSQLiteTable(files); err != nil {
		return err
	}

	for _, file := range files.Files {
		permissions, err := QuerySharedWithAndRole(file.Id, accessToken)
		if err != nil {
			return err
		}
		perms := Permissions{Permissions: permissions}
		if err = InsertOrUpdateInSQLiteTable(perms); err != nil {
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
