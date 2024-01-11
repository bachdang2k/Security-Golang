package controllers

import (
	"errors"
	"log"
	"net/http"

	"github.com/bachdang2k/security-golang/internal/models"
	"github.com/bachdang2k/security-golang/internal/utils"
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

func (controller *AuthController) Login(w http.ResponseWriter, r *http.Request) {
	request := models.AuthenticationRequest{}
	if err := utils.GetJsonInput(&request, r); err != nil {
		utils.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := controller.validate.Struct(request); err != nil {
		log.Println(err)
		utils.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	response, err := controller.authService.LoginByUsernamePassword(request.Username, request.Password, "", "")
	if err != nil {
		if errors.Is(err, services.ErrInvalidUsername) || errors.Is(err, services.ErrInvalidPassword) || errors.Is(err, services.ErrAccountNotActive) {
			utils.JSONError(w, err.Error(), http.StatusUnauthorized)
		} else {
			utils.JSONError(w, services.ErrServer.Error(), http.StatusInternalServerError)
		}
		return
	}
	utils.JSONResponse(w, response)
}

// PasswordLessLogin Login Handler To Authenticate user without password
func (controller *AuthController) PasswordLessLogin(w http.ResponseWriter, r *http.Request) {
	request := models.PasswordLessAuthRequest{}
	err := utils.GetJsonInput(&request, r)
	if err != nil {
		utils.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	err = controller.validate.Struct(request)
	if err != nil {
		log.Println(err)
		utils.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	var response *models.PasswordLessAuthResponse
	response, err = controller.authService.PasswordLessLogin(request.Username, request.SendMethod, "", "")
	if err != nil {
		if errors.Is(err, services.ErrInvalidUsername) || errors.Is(err, services.ErrInvalidPassword) || errors.Is(err, services.ErrAccountNotActive) {
			utils.JSONError(w, err.Error(), http.StatusUnauthorized)
		} else {
			utils.JSONError(w, services.ErrServer.Error(), http.StatusInternalServerError)
		}
		return
	}
	utils.JSONResponse(w, response)
}

// CompletePasswordLogin Completes passwordLess login
func (controller *AuthController) CompletePasswordLogin(w http.ResponseWriter, r *http.Request) {
	request := models.CompletePasswordLessRequest{}
	if err := utils.GetJsonInput(&request, r); err != nil {
		utils.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := controller.validate.Struct(request); err != nil {
		log.Println(err)
		utils.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	//var response *models.AuthenticationResponse
	response, err := controller.authService.CompletePasswordLessLogin(request.Code, request.RequestId)
	if err != nil {
		if errors.Is(err, services.ErrInvalidCode) {
			utils.JSONError(w, err.Error(), http.StatusUnauthorized)
		} else {
			utils.JSONError(w, services.ErrServer.Error(), http.StatusInternalServerError)
		}
		return
	}
	utils.JSONResponse(w, response)
}

// RefreshToken Function To Refresh Token
func (controller *AuthController) RefreshToken(w http.ResponseWriter, r *http.Request) {
	request := models.TokenRefreshRequest{}
	if err := utils.GetJsonInput(&request, r); err != nil {
		utils.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	response, err := controller.authService.GenerateRefreshToken(request.RefreshToken, r.RemoteAddr, r.UserAgent())
	if err != nil {
		if errors.Is(err, services.ErrInvalidToken) {
			utils.JSONError(w, err.Error(), http.StatusUnauthorized)
		} else {
			utils.JSONError(w, services.ErrServer.Error(), http.StatusUnauthorized)
		}
		return
	}
	utils.JSONResponse(w, response)
}

// PasswordResetRequest Reset Password Request
func (controller *AuthController) PasswordResetRequest(w http.ResponseWriter, r *http.Request) {

}

// VerifyAndChangePassword Verify and update the password
func (controller *AuthController) VerifyAndChangePassword(w http.ResponseWriter, r *http.Request) {

}

// Register Function register User
func (controller *AuthController) Register(w http.ResponseWriter, r *http.Request) {

}

// ValidateTwoFactor Validates Two Factor authCtrl function is only called when two factor is required
func (controller *AuthController) ValidateTwoFactor(w http.ResponseWriter, r *http.Request) {

}

func (controller *AuthController) Health(w http.ResponseWriter, r *http.Request) {
	utils.JSONResponse(w, "OKAY")
}
