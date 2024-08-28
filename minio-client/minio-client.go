package minio_client

import (
	"fmt"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"os"
)

var MinioBucket = "testgo"
var MinioFolder = "images/"

func GetMinioEndpoint() string {
	host := "127.0.0.1"
	if os.Getenv("MINIO_HOST") != "" {
		host = os.Getenv("MINIO_HOST")
	}
	port := "9000"
	url := fmt.Sprintf("%s:%s", host, port)
	return url
}

func GetMinioClient() (*minio.Client, error) {
	endpoint := GetMinioEndpoint()
	accessKeyID := "root"
	secretAccessKey := "g35y13tagrgh"

	minioClient, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKeyID, secretAccessKey, ""),
		Secure: false,
	})
	if err != nil {
		fmt.Println(err)
		return minioClient, err
	}
	return minioClient, err
}
