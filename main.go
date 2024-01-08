package main

import (
	"log"
	"os"
	"strings"

	"gorm.io/gorm"

	apiserver "github.com/bachdang2k/security-golang/internal/apiServer"
	"github.com/bachdang2k/security-golang/internal/utils"
	"github.com/joho/godotenv"
)

var databaseConnection *gorm.DB

func initialize() {
	if err := godotenv.Load(); err != nil {
		log.Println("Not loading Config from .env")
	}

	databaseConfig := utils.DatabaseConfig{
		Host:     os.Getenv("PG_HOST"),
		Username: os.Getenv("PG_USER"),
		Password: os.Getenv("PG_PASSWORD"),
		Port:     os.Getenv("PG_PORT"),
		Database: os.Getenv("PG_DB"),
	}

	if strings.ToTitle(os.Getenv("PG_SSL")) == "True" {
		databaseConfig.SSL = true
		databaseConfig.Certificate = os.Getenv("PG_CERT")
	} else {
		databaseConfig.SSL = false
	}

	var err error
	databaseConnection, err = utils.GetMainDatabaseConnections(databaseConfig)
	if err != nil {
		log.Fatal("Failed to Connect to the  Database", err)
	}

	asciiArt := `

███████ ██████  ███████ ███████ ██████  ██    ██      █████  ██    ██ ████████ ██   ██ 
██      ██   ██ ██      ██      ██   ██  ██  ██      ██   ██ ██    ██    ██    ██   ██ 
███████ ██████  █████   █████   ██   ██   ████       ███████ ██    ██    ██    ███████ 
     ██ ██      ██      ██      ██   ██    ██        ██   ██ ██    ██    ██    ██   ██ 
███████ ██      ███████ ███████ ██████     ██        ██   ██  ██████     ██    ██   ██ 
                                                                                       
																																		   																			
	`
	log.Println(asciiArt)
}

func main() {
	initialize()
	apiServer := apiserver.NewAPIServer(os.Getenv("SERVER_ADDRESS"), os.Getenv("SERVER_PORT"), databaseConnection)
	apiServer.Run()
}
