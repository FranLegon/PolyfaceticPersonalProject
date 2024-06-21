package main

import (
	"context"
	"os"

	"golang.org/x/oauth2/google"
	"google.golang.org/api/drive/v3"
	"google.golang.org/api/option"
	//"github.com/gphotosuploader/google-photos-api-client-go/v2"
)

func main() {}

func getService() (*drive.Service, error) {
	data, err := os.ReadFile("Credentials.json")
	if err != nil {
		return nil, err
	}
	conf, err := google.JWTConfigFromJSON(data, drive.DriveScope)
	if err != nil {
		return nil, err
	}
	client := conf.Client(context.Background())
	service, err := drive.NewService(context.Background(), option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}
	return service, nil
}
