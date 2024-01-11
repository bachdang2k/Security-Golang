package services

import (
	"database/sql"
	"errors"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/bachdang2k/security-golang/internal/models"
	"github.com/bachdang2k/security-golang/internal/utils"
	"github.com/pquerna/otp/totp"
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

// LoginByUsernamePassword Login function to authenticate user by username and password
func (service *AuthService) LoginByUsernamePassword(username, password, ipAddress, userAgent string) (*models.AuthenticationResponse, error) {
	var (
		userId       int
		passwordHash string
		err          error
	)

	row := service.db.Model(&models.User{}).Select("id", "password").Where("username = ?", username).Row()
	//row := authSrv.db.QueryRow("SELECT id, password FROM users WHERE username = $1  LIMIT 1 ", username)
	row.Scan(&userId, &passwordHash)
	if userId == 0 {
		return nil, ErrInvalidUsername
	}
	userDetails := service.userService.Get(userId)
	if !userDetails.Active {
		return nil, ErrAccountNotActive
	}

	// Validates password
	if err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
		return nil, ErrInvalidPassword
	}
	return service.generateAuthResponse(*userDetails, ipAddress, userAgent)
}

// GenerateRefreshToken Refresh Token generates a new refresh token that will be used to get a new access token and a refresh token
func (service *AuthService) GenerateRefreshToken(oldRefreshToken, ipAddress, userAgent string) (*models.AuthenticationResponse, error) {
	var token models.UserRefreshToken

	service.db.Model(&models.UserRefreshToken{}).Select("user_id").Where("token = ? AND expired_time > NOW()", oldRefreshToken).First(&token)
	userId := token.UserId
	if userId == 0 {
		log.Println("Refresh Token is not there")
		return nil, ErrInvalidToken
	}

	// Check if account is active before refreshing token
	userDetails := service.userService.Get(int(userId))
	if !userDetails.Active {
		return nil, ErrAccountNotActive
	}
	roles, _ := service.userService.GetRoles(int(userId))
	tokenExpire := time.Duration(service.tokenTime)

	jwtToken, err := utils.GenerateJwtToken(int(userId), roles, time.Duration(tokenExpire))
	if err != nil {
		log.Println(err)
		return nil, err
	}

	// Delete the old token and generate new access token and refresh token
	refreshToken := utils.GenerateOpaqueToken(45)
	err = utils.Transaction(service.db, func(db *gorm.DB) error {
		if err := service.db.Model(&models.UserRefreshToken{}).Delete(&token).Error; err != nil {
			log.Println("log khi xoa user refresh token", err)
			return err
		}

		token.UserId = userId
		token.Token = refreshToken
		token.IpAddress = ipAddress
		token.UserAgent = userAgent
		token.ExpireTime = sql.NullTime{Time: time.Now().Add(tokenExpire), Valid: true}

		if err := service.db.Model(&models.UserRefreshToken{}).Create(&tokenExpire).Error; err != nil {
			log.Println("log khi them moi user refresh token", err)
			return err
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	response := &models.AuthenticationResponse{
		RefreshToken: refreshToken,
		Token:        jwtToken,
		Roles:        roles,
		Expires:      int(tokenExpire.Seconds()),
	}

	return response, nil

}

func (service *AuthService) generateAuthResponse(userDetails models.User, ipAddress, userAgent string) (*models.AuthenticationResponse, error) {
	if userDetails.TwoFactorEnabled {
		if userDetails.TwoFactorMethod != "TOTP" {
			return service.twoFactorRequest(userDetails, ipAddress, userAgent)
		}

		// Otherwise its TOTP then
		authResult := &models.AuthenticationResponse{}
		// Generate a short token which expires after 5minutes
		var roles []string
		for _, role := range userDetails.Roles {
			roles = append(roles, role.Type)
		}
		roles = append(roles)
		shortToken, _ := utils.GenerateJwtToken(int(userDetails.Model.ID), roles, 5*time.Minute)
		authResult.TwoFactorEnabled = true
		authResult.Token = shortToken
		authResult.TwoFactorMethod = userDetails.TwoFactorMethod
		return authResult, nil
	}

	// Get user roles
	//roles, err := service.userService.GetRoles(int(userDetails.Model.ID))
	//userDetails.Roles = roles
	//if err != nil {
	//	log.Println(err)
	//	return nil, err
	//}
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
	tokenExpiry := service.tokenTime

	token, err := utils.GenerateJwtToken(int(userDetails.ID), getRoles(userDetails), tokenExpiry)
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
	authResult.Roles = getRoles(userDetails)
	authResult.Expires = int(tokenExpiry.Seconds())
	authResult.TwoFactorEnabled = userDetails.TwoFactorEnabled
	return authResult, nil
}

// VerifyAndSetNewPassWord Verify And Set New-Password functions to verify and reset password
func (service *AuthService) VerifyAndSetNewPassWord(code string, password string) (bool, error) {

	if !utils.IsStrongPassword(password) {
		return false, ErrStrongPassword
	}

	//var userId uint
	//err := utils.Transaction(service.db, func(db *gorm.DB) error {
	//	var
	//})

	return true, nil
}

// ValidateTwoFactor Validate the two factors authentication request and complete the authentication request
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

// DeleteExpiredTokens Delete expired tokens
func (service *AuthService) DeleteExpiredTokens(days int) error {

	ch := make(chan error, 3)
	var errArr []string

	var wg sync.WaitGroup

	go func() {
		err := service.db.Exec("DELETE FROM user_refresh_tokens WHERE (DATE_PART('day', AGE(NOW()::date ,expiry_time::date))) >= ?", days).Error
		wg.Add(1)
		if err != nil {
			ch <- err
		}
	}()

	go func() {
		// Deletes Two factor requests
		err := service.db.Exec("DELETE FROM two_factor_requests WHERE (DATE_PART('day', AGE(NOW()::date ,expiry_time::date))) >= ?", days).Error
		wg.Add(1)
		if err != nil {
			ch <- err
		}
	}()

	go func() {
		// Delete Reset Password Requests
		err := service.db.Exec("DELETE FROM reset_password_requests WHERE (DATE_PART('day', AGE(NOW()::date ,expiry_time::date))) >= ?", days).Error
		wg.Add(1)
		if err != nil {
			ch <- err
		}
	}()

	wg.Done()
	// Deletes User Refresh tokens
	for i := 0; i < 3; i++ {
		if receive := <-ch; receive != nil {
			errArr = append(errArr, receive.Error())
		}
	}

	if errArr != nil {
		return errors.New(strings.Join(errArr, " _ "))
	}

	return nil
}

// VerifyPassCode Verify the passcode
func (service *AuthService) VerifyPassCode(userId uint, passCode string) bool {
	userDetail := service.userService.Get(int(userId))
	if totp.Validate(passCode, userDetail.TOTPSecret) {
		return true
	}
	return false
}

// VerifyOTP Validates the TOTP before the user finally logs in
func (service *AuthService) VerifyOTP(userId uint, passCode, ipAddress, userAgent string) (*models.AuthenticationResponse, error) {
	userDetails := service.userService.Get(int(userId))
	if !service.VerifyPassCode(userId, passCode) {
		return nil, ErrPassCode
	}
	return service.generateTokenDetails(*userDetails, ipAddress, userAgent)
}

// PasswordLessLogin Func loginByUsername this will send an otp to the user which then be verified
func (service *AuthService) PasswordLessLogin(username, sendMethod, ipAddress, userAgent string) (*models.PasswordLessAuthResponse, error) {
	userDetails := service.userService.GetByUsername(username)
	if userDetails == nil {
		return nil, ErrInvalidUsername
	}
	if userDetails.Active == false {
		return nil, ErrAccountNotActive
	}

	// Generates request ID
	requestId := utils.GenerateOpaqueToken(45)
	// Generate 6 random code
	randomCodes := utils.GenerateRandomDigits(6)

	err := utils.Transaction(service.db, func(db *gorm.DB) error {

		otpRequest := models.OTPRequest{
			UserId:     userDetails.ID,
			RequestId:  requestId,
			Code:       randomCodes,
			SendMethod: "EMAIL",
			ExpireTime: sql.NullTime{Time: time.Now().Add(1 * time.Minute), Valid: true},
			IpAddress:  ipAddress,
			UserAgent:  userAgent,
		}

		if err := service.db.Model(&models.OTPRequest{}).Create(&otpRequest).Error; err != nil {
			return err
		}

		if err := service.emailService.SendEmailLoginRequest(randomCodes, *userDetails); err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	var response = models.PasswordLessAuthResponse{RequestId: requestId, SendMethod: "EMAIL"}

	return &response, nil
}

// CompletePasswordLessLogin Func completePasswordLessLogin
func (service *AuthService) CompletePasswordLessLogin(code, requestId string) (*models.AuthenticationResponse, error) {

	println(code, requestId)

	var otpRequest models.OTPRequest
	if err := service.db.Model(&models.OTPRequest{}).Where("code = ? AND request_id = ? AND expire_time >= NOW()", code, requestId).First(&otpRequest).Error; err != nil {
		log.Println(err)
		return nil, err
	}

	userAgent := otpRequest.UserAgent
	ipAddress := otpRequest.IpAddress

	var userDetails models.User
	if err := service.db.Model(&models.User{}).Where("id = ?", otpRequest.UserId).First(&userDetails).Error; err != nil {
		log.Println(err)
		return nil, err
	}

	err := utils.Transaction(service.db, func(db *gorm.DB) error {

		if err := service.db.Model(&models.OTPRequest{}).Delete(&otpRequest).Error; err != nil {
			log.Println(err)
			return err
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return service.generateAuthResponse(userDetails, ipAddress, userAgent)
}

func getRoles(user models.User) []string {
	var roles []string
	for _, role := range user.Roles {
		roles = append(roles, role.Type)
	}
	return roles
}
