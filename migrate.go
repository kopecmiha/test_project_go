package main

import (
	"log"
	"myproj/database"
)

func Migration() {
	db := database.InitDbConnect()
	if db == nil {
		log.Println("Migration failed, can't connect")
		return
	}
	db.AutoMigrate(&database.UserDB{}, &database.FileDB{})
	log.Println("Migration success")
}
