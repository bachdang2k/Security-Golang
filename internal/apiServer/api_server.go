package apiserver

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/bachdang2k/security-golang/internal/middlewares"
	"gorm.io/gorm"

	"github.com/bachdang2k/security-golang/internal/services"
)

type APIServer struct {
	port       string
	serverName string
	db         *gorm.DB
}

func NewAPIServer(serverName string, port string, db *gorm.DB) *APIServer {
	return &APIServer{serverName: serverName, port: port, db: db}
}

func (ap *APIServer) Run() {
	ap.cleanUp()
	ap.setupRoutes()
	// Listen to incoming connections
	log.Println("Starting SpeedyAuth listening for requests on port " + os.Getenv("SERVER_PORT"))
	err := http.ListenAndServe(fmt.Sprintf("%s:%s", ap.serverName, ap.port), middlewares.LogRequest(http.DefaultServeMux))

	// Exit if fail to start service
	if err != nil {
		log.Fatal("Failed to start Service ")
	}
}

func (ap *APIServer) setupRoutes() {
	ap.registerGlobalFunctions()
	ap.registerAdminFunctions()
	ap.registerUSerFunctions()
}

func (ap *APIServer) registerGlobalFunctions() {

}

func (ap *APIServer) registerUSerFunctions() {

}

// register admin functions
func (ap *APIServer) registerAdminFunctions() {

}

// Cleanup
func (ap *APIServer) cleanUp() {
	authService := services.NewAuthService(ap.db)
	// Deletes expired tokens after 30 days
	err := authService.DeleteExpiredTokens(30)
	if err != nil {
		log.Fatal("There was a problem cleaning up ")
	}
}
