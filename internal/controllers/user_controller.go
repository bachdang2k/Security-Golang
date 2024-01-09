package controllers

import (
	"log"
	"net/http"

	"github.com/bachdang2k/security-golang/internal/models"
	"github.com/bachdang2k/security-golang/internal/services"
	"github.com/bachdang2k/security-golang/internal/utils"
	"github.com/go-playground/validator/v10"
	"gorm.io/gorm"
)

type UserController struct {
	db          *gorm.DB
	userService services.UserService
	authService services.AuthService
	validate    *validator.Validate
}

func NewUserController(db *gorm.DB) *UserController {
	return &UserController{
		db:          db,
		userService: *services.NewUserService(db),
		authService: *services.NewAuthService(db),
		validate:    validator.New(),
	}
}

// Index Welcome USer
func (controller *UserController) Index(w http.ResponseWriter, r *http.Request) {
	userId := utils.GetUserIdFromHttpContext(r)
	userDetails := controller.userService.Get(userId)
	utils.JSONResponse(w, userDetails)
}

func (controller *UserController) Update(w http.ResponseWriter, r *http.Request) {
	request := models.UserUpdateRequest{}
	if err := utils.GetJsonInput(&request, r); err != nil {
		utils.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := controller.validate.Struct(request); err != nil {
		log.Println(err)
		utils.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	userId := utils.GetUserIdFromHttpContext(r)
	response := models.SuccessResponse{}
	if err := controller.userService.Update(uint(userId), request); err != nil {
		utils.JSONError(w, "Failed to Update ", http.StatusBadRequest)
		return
	}
	response.Success = true
	utils.JSONResponse(w, response)
}

func (controller *UserController) Logout(w http.ResponseWriter, r *http.Request) {
	request := models.TokenRefreshRequest{}
	if err := utils.GetJsonInput(&request, r); err != nil {
		utils.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	response := models.SuccessResponse{}
	userId := utils.GetUserIdFromHttpContext(r)
	success, err := controller.userService.DeleteToken(uint(userId), request.RefreshToken)
	if err != nil {
		response.Success = false
		utils.JSONError(w, "Failed to register", http.StatusBadRequest)
		return
	}
	response.Success = success
	utils.JSONResponse(w, response)
}

func (controller *UserController) EnableTwoFactor(w http.ResponseWriter, r *http.Request) {
	request := models.EnableTwoFactorRequest{}
	if err := utils.GetJsonInput(&request, r); err != nil {
		utils.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	userId := utils.GetUserIdFromHttpContext(r)
	if request.Type == "TOTP" {
		totpResponse, err := controller.userService.Enable2FactorTOTP(uint(userId))
		if err != nil {
			utils.JSONError(w, "Failed to Enable Two Factor (TOTP)", http.StatusBadRequest)
			return
		}
		utils.JSONResponse(w, totpResponse)
		return
	} else {
		err := controller.userService.Enable2Factor(uint(userId), request.Type)
		if err != nil {
			utils.JSONError(w, "Failed to Enabled Two Factor EMAIL OR SMS ", http.StatusBadRequest)
			return
		}
	}
	response := models.SuccessResponse{Success: true}
	utils.JSONResponse(w, response)
}

func (controller *UserController) VerifyPassCode(w http.ResponseWriter, r *http.Request) {
	request := models.VerifyPassCodeRequest{}
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

	userId := utils.GetUserIdFromHttpContext(r)
	response := models.SuccessResponse{}
	if controller.authService.VerifyPassCode(uint(userId), request.Code) {
		response.Success = true
	} else {
		response.Success = false
	}
	utils.JSONResponse(w, response)
}
