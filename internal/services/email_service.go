package services

import (
	"os"

	"github.com/bachdang2k/security-golang/internal/models"
)

type EmailService struct {
	smtpHost         string
	smtpUsername     string
	smtpPassword     string
	smtpPort         string
	fromEmailAddress string
	secure           bool
}

func NewEmailService(secure bool) *EmailService {
	return &EmailService{
		smtpHost:         os.Getenv("SMTP_HOST"),
		smtpUsername:     os.Getenv("SMTP_USERNAME"),
		smtpPassword:     os.Getenv("SMTP_PORT"),
		smtpPort:         os.Getenv("SMTP_PASSWORD"),
		fromEmailAddress: os.Getenv("FROM_EMAIL_ADDRESS"),
		secure:           secure,
	}
}

func (emSrv *EmailService) SendTwoFactorRequest(randomCodes string, userDetails models.User) error {

	return nil
}
