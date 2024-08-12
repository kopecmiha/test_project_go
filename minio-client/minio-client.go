package minio_client

import (
	"fmt"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

var MinioEndpoint = "127.0.0.1:9000"
var MinioBucket = "testgo"
var MinioFolder = "images/"

func GetMinioClient() (*minio.Client, error) {
	endpoint := MinioEndpoint
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
