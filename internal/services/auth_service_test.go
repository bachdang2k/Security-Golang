package services

import (
	"log"
	"os"
	"testing"

	"github.com/bachdang2k/security-golang/internal/utils"
	_ "github.com/lib/pq"
	"gorm.io/gorm"
)

var db *gorm.DB

func setUp() {
	var err error
	db, err = utils.GetMainDatabaseConnections(utils.DatabaseConfig{
		Host:     os.Getenv("PG_HOST"),
		Username: os.Getenv("PG_USER"),
		Password: os.Getenv("PG_PASSWORD"),
		Database: os.Getenv("PG_DB"),
		Port:     os.Getenv("PG_PORT"),
	})
	if err != nil {
		log.Fatal("Failed to connect to database")
		return
	}
	// userService := NewUserService(db)
	// _, err = userService.Register(models.UserRegistrationRequest{
	// 	Username:     "john.doe",
	// 	Password:     "password_2030333",
	// 	EmailAddress: "johndoe@localhost",
	// 	FirstName:    "john",
	// 	LastName:     "doe",
	// 	CellNumber:   "0731482947",
	// })

}
func TestMain(m *testing.M) {
	setUp()
	code := m.Run()
	os.Exit(code)
}
func TestLoginByUsernamePassword(t *testing.T) {
	authService := NewAuthService(db)
	_, err := authService.LoginByUsernamePassword("john.doe", "password", "", "")
	if err != nil {
		t.Error("Failed to authenticate")
	}
}
