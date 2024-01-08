package controllers

import (
	"gorm.io/gorm"

	"github.com/bachdang2k/security-golang/internal/services"
	"github.com/go-playground/validator/v10"
)

type AuthController struct {
	// Registered Services
	db          *gorm.DB
	userService services.UserService
	authService services.AuthService
	validate    *validator.Validate
}

func NewAuthController(db *gorm.DB) *AuthController {
	return &AuthController{
		db:          db,
		userService: *services.NewUserService(db),
		authService: *services.NewAuthService(db),
		validate:    validator.New(),
	}
}
