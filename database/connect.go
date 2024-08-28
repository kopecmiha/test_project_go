package database

import (
	"fmt"
	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"log"
	"os"
)

func getDns() string {
	host := "localhost"
	if os.Getenv("DB_HOST") != "" {
		host = os.Getenv("DB_HOST")
	}
	user := "postgres"
	if os.Getenv("DB_USER") != "" {
		user = os.Getenv("DB_USER")
	}
	password := "123"
	if os.Getenv("DB_PASSWORD") != "" {
		password = os.Getenv("DB_PASSWORD")
	}
	dbName := "gormgo"
	if os.Getenv("DB_NAME") != "" {
		dbName = os.Getenv("DB_NAME")
	}
	dsn := fmt.Sprintf("host=%s user=%s dbname=%s password=%s sslmode=disable", host, user, dbName, password)
	return dsn
}

func InitDbConnect() *gorm.DB {
	dsn := getDns()
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Println("Error connect to database", err)
		return nil
	}
	return db
}

type UserDB struct {
	gorm.Model
	ID       uint   `gorm:"unique;primaryKey;autoIncrement"`
	Email    string `gorm:"unique;not null;type:varchar(100)"`
	Username string `gorm:"type:varchar(100)"`
	Password string `gorm:"not null;type:varchar(100)"`
}

type FileDB struct {
	UUID     string `gorm:"unique;primaryKey;type:uuid"`
	UserId   uint
	Filepath string `gorm:"type:varchar(255)"`
}

func (file FileDB) TableName() string {
	return "files"
}

func (file *FileDB) BeforeCreate(tx *gorm.DB) (err error) {
	// UUID version 4
	file.UUID = uuid.NewString()
	return
}
