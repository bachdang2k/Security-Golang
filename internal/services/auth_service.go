package services

import (
	"database/sql"
	"log"
	"os"
	"time"

	"github.com/bachdang2k/security-golang/internal/models"
	"github.com/bachdang2k/security-golang/internal/utils"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type AuthService struct {
	db           *gorm.DB
	userService  *UserService
	emailService *EmailService
	tokenTime    time.Duration
}

func NewAuthService(db *gorm.DB) *AuthService {
	tokenTime, _ := time.ParseDuration(os.Getenv("TOKEN_EXPIRY_TIME"))
	return &AuthService{
		db:           db,
		userService:  NewUserService(db),
		emailService: NewEmailService(true),
		tokenTime:    tokenTime,
	}
}

// Login function to authenticate user by username and password
func (authSrv *AuthService) LoginByUsernamePassword(username, password, ipAddress, userAgent string) (*models.AuthenticationResponse, error) {
	var (
		userId       int
		passwordHash string
		err          error
	)

	row := authSrv.db.Model(&models.User{}).Select("id", "password").Where("username = ?", username).Row()
	//row := authSrv.db.QueryRow("SELECT id, password FROM users WHERE username = $1  LIMIT 1 ", username)
	row.Scan(&userId, &passwordHash)
	if userId == 0 {
		return nil, ErrInvalidUsername
	}
	userDetails := authSrv.userService.Get(userId)
	if !userDetails.Active {
		return nil, ErrAccountNotActive
	}

	// Validates password
	if err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
		return nil, ErrInvalidPassword
	}
	return authSrv.generateAuthResponse(*userDetails, ipAddress, userAgent)
}

func (service *AuthService) generateAuthResponse(userDetails models.User, ipAddress, userAgent string) (*models.AuthenticationResponse, error) {
	if userDetails.TwoFactorEnabled {
		if userDetails.TwoFactorMethod != "TOTP" {
			return service.twoFactorRequest(userDetails, ipAddress, userAgent)
		}

		// Otherwise its TOTP then
		authResult := &models.AuthenticationResponse{}
		// Generate a short token which expires after 5minutes
		shortToken, _ := utils.GenerateJwtToken(int(userDetails.Model.ID), userDetails.Roles, 5*time.Minute)
		authResult.TwoFactorEnabled = true
		authResult.Token = shortToken
		authResult.TwoFactorMethod = userDetails.TwoFactorMethod
		return authResult, nil
	}

	// Get user roles
	roles, err := service.userService.GetRoles(int(userDetails.Model.ID))
	userDetails.Roles = roles
	if err != nil {
		log.Println(err)
		return nil, err
	}
	return service.generateTokenDetails(userDetails, ipAddress, userAgent)
}

func (service *AuthService) twoFactorRequest(userDetails models.User, ipAddress string, userAgent string) (*models.AuthenticationResponse, error) {

	// Expire after 5minutes
	expires := time.Duration(300 * time.Second)
	requestId := utils.GenerateOpaqueToken(60)

	var entity = models.TwoFactorRequest{
		UserId:     userDetails.ID,
		RequestId:  requestId,
		IpAddress:  ipAddress,
		Code:       utils.GenerateRandomDigits(6),
		UserAgent:  userAgent,
		SendType:   "EMAIL",
		ExpireTime: sql.NullTime{Time: time.Now().Add(expires), Valid: true},
	}

	if err := service.insert2FactorRequest(entity, userDetails); err != nil {
		return nil, err
	}

	authResult := &models.AuthenticationResponse{}
	authResult.TwoFactorEnabled = true
	authResult.Token = requestId
	authResult.TwoFactorMethod = userDetails.TwoFactorMethod
	return authResult, nil
}

func (service *AuthService) insert2FactorRequest(entity models.TwoFactorRequest, userDetail models.User) error {

	return utils.Transaction(service.db, func(db *gorm.DB) error {
		if err := service.db.Create(&entity).Error; err != nil {
			log.Println("loi xay ra ", err)
			return ErrTwoFactorRequest
		}

		if err := service.emailService.SendTwoFactorRequest(entity.Code, userDetail); err != nil {
			log.Println("Sending Email error", err)
			return ErrSendingMail
		}

		return nil
	})
}

func (service *AuthService) generateTokenDetails(userDetails models.User, ipAddress string, userAgent string) (*models.AuthenticationResponse, error) {

	authResult := &models.AuthenticationResponse{}
	tokenExpiry := time.Duration(service.tokenTime)

	token, err := utils.GenerateJwtToken(int(userDetails.ID), userDetails.Roles, tokenExpiry)
	if err != nil {
		log.Println(err)
		return nil, ErrAccessToken
	}
	refreshToken := utils.GenerateOpaqueToken(45)
	var entity = models.UserRefreshToken{
		UserId:     userDetails.ID,
		Token:      token,
		IpAddress:  ipAddress,
		UserAgent:  userAgent,
		ExpireTime: sql.NullTime{Time: time.Now().Add(tokenExpiry), Valid: true},
	}

	if err := service.db.Create(&entity).Error; err != nil {
		log.Println(err)
		return nil, ErrTokenGeneration
	}

	authResult.RefreshToken = refreshToken
	authResult.Token = token
	authResult.Roles = userDetails.Roles
	authResult.Expires = int(tokenExpiry.Seconds())
	authResult.TwoFactorEnabled = userDetails.TwoFactorEnabled
	return authResult, nil
}

// Validate the two factor authentication request and complete the authentication request
func (service *AuthService) ValidateTwoFactor(code, requestId, ipAddress, userAgent string) (*models.AuthenticationResponse, error) {

	var userId uint
	err := service.db.Model(&models.TwoFactorRequest{}).Select("id").Where("code = ? AND request_id = ? AND Expire_Time > NOW()", code, requestId).First(&userId).Error

	if userId == 0 || err != nil {
		log.Println("Invalid Code ", err)
		return nil, ErrTwoFactorCode
	}

	if err := service.db.Model(&models.TwoFactorRequest{}).Exec("DELETE FROM two_factor_requests WHERE code = ? AND request_id = ?", code, requestId).Error; err != nil {
		log.Println(err)
		return nil, ErrTwoFactorCode
	}

	userDetail := service.userService.Get(int(userId))
	return service.generateTokenDetails(*userDetail, ipAddress, userAgent)

}

// Delete expired tokens
func (service *AuthService) DeleteExpiredTokens(days int) error {

	ch := make(chan error, 3)

	go func() {
		err := service.db.Exec("DELETE FROM user_refresh_tokens WHERE (DATE_PART('day', AGE(NOW()::date ,expiry_time::date))) >= ?", days).Error
		if err != nil {
			ch <- nil
		}
	}()

	go func() {
		// Deletes Two factor requests
		err := service.db.Exec("DELETE FROM two_factor_requests WHERE (DATE_PART('day', AGE(NOW()::date ,expiry_time::date))) >= ?", days).Error
		if err != nil {
			ch <- nil
		}
	}()

	go func() {
		// Delete Reset Password Requests
		err := service.db.Exec("DELETE FROM reset_password_requests WHERE (DATE_PART('day', AGE(NOW()::date ,expiry_time::date))) >= ?", days).Error
		if err != nil {
			ch <- nil
		}
	}()

	// Deletes User Refresh tokens
	for i := 0; i < 3; i++ {
		if receice := <-ch; receice != nil {
			return receice
		}
	}

	return nil
}
