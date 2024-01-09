package services

import "errors"

var (
	ErrUserNameExists   = errors.New("the username exists")
	ErrSendingMail      = errors.New("failed sending Email")
	ErrAccountNotActive = errors.New("account is not Active")
	ErrTokenGeneration  = errors.New("failed to generate Token")
	ErrInvalidToken     = errors.New("token is Invalid")
	ErrAccessToken      = errors.New("failed to Access Token")
	ErrInvalidUsername  = errors.New("invalid Username")
	ErrInvalidPassword  = errors.New("invalid Password")
	ErrRegistration     = errors.New("failed to register ")
	ErrPasswordUpdate   = errors.New("failed to update password")
	ErrTwoFactorCode    = errors.New("failed to Verify Two Factor Code")
	ErrTwoFactorRequest = errors.New("failed to Send Two Factor Request")
	ErrInvalidCode      = errors.New("code is invalid")
	ErrServer           = errors.New("server Error, Try again later")
	ErrPassCode         = errors.New("invalid Passcode")
	ErrStrongPassword   = errors.New("password must be at least 8 characters and must contain special characters")
	ErrTOTPExists       = errors.New("TOTP Already Enabled ")
)
