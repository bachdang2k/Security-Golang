package services

import (
	"bytes"
	"crypto/tls"
	"html/template"
	"log"
	"os"
	"strconv"

	"github.com/bachdang2k/security-golang/internal/models"
	"gopkg.in/gomail.v2"
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

// sendEmail function sends email directly to an external server
func (service *EmailService) sendMail(to []string, subject, message string) error {
	portNumber, _ := strconv.Atoi(service.smtpPort)
	d := gomail.NewDialer(service.smtpHost, portNumber, service.smtpUsername, service.smtpPassword)
	d.TLSConfig = &tls.Config{InsecureSkipVerify: service.secure}
	// Compose the message to be sent
	m := gomail.NewMessage()
	m.SetHeader("From", service.fromEmailAddress)
	m.SetHeader("To ", to[:]...)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", message)

	if err := d.DialAndSend(m); err != nil {
		return err
	}
	return nil
}

// SendTwoFactorRequest sends two factor mail
func (service *EmailService) SendTwoFactorRequest(randomCodes string, userDetails models.User) error {

	var twoFactorRequestTemplateBuffer bytes.Buffer
	// Get email template from directory and assign random code to it
	emailTemplateFile, err := template.ParseFiles("static/email_templates/TwoFactorLogin.html")
	if err != nil {
		return err
	}

	_template := template.Must(emailTemplateFile, err)
	emailTemplateData := struct {
		FullName   string
		RandomCode string
	}{}
	emailTemplateData.RandomCode = randomCodes
	emailTemplateData.FullName = userDetails.FirstName + " " + userDetails.LastName
	_ = _template.Execute(&twoFactorRequestTemplateBuffer, emailTemplateData)
	recipient := []string{userDetails.EmailAddress}
	if err = service.sendMail(recipient, "Two-factor login", twoFactorRequestTemplateBuffer.String()); err != nil {
		log.Println("Sending Two Factor Request Email Error", err)
		return err
	}
	return nil
}

// SendEmailLoginRequest sends two factor mail
func (service *EmailService) SendEmailLoginRequest(randomCodes string, userDetails models.User) error {
	var twoFactorRequestTemplateBuffer bytes.Buffer
	// Get email template from directory and assign random code to it
	emailTemplateFile, err := template.ParseFiles("static/email_templates/EmailLogin.html")
	if err != nil {
		return err
	}
	tmpl := template.Must(emailTemplateFile, err)
	emailTemplateData := struct {
		FullName   string
		RandomCode string
	}{}
	emailTemplateData.RandomCode = randomCodes
	emailTemplateData.FullName = userDetails.FirstName + " " + userDetails.LastName
	_ = tmpl.Execute(&twoFactorRequestTemplateBuffer, emailTemplateData)
	recipient := []string{userDetails.EmailAddress}
	if err = service.sendMail(recipient, "Email login", twoFactorRequestTemplateBuffer.String()); err != nil {
		log.Println("Sending Email Login Request  Error", err)
		return err
	}
	return nil
}

// SendPasswordResetRequest
// Sends a password request mail to the receiver
func (service *EmailService) SendPasswordResetRequest(randomCodes string, userDetails models.User) error {
	var passwordResetTemplateBuffer bytes.Buffer
	// Get email template from directory and assign random code to it
	emailTemplateFile, err := template.ParseFiles("static/email_templates/PasswordRequest.html")
	if err != nil {
		log.Println("Template reading ", err)
		return err
	}
	tmpl := template.Must(emailTemplateFile, err)
	emailTemplateData := struct {
		FullName   string
		RandomCode string
	}{}
	emailTemplateData.RandomCode = randomCodes
	emailTemplateData.FullName = userDetails.FirstName + " " + userDetails.LastName
	_ = tmpl.Execute(&passwordResetTemplateBuffer, emailTemplateData)
	recipient := []string{userDetails.EmailAddress}
	if err = service.sendMail(recipient, "Password Reset Request", passwordResetTemplateBuffer.String()); err != nil {
		log.Println("Sending Password Reset Email Error", err)
		return err
	}
	return nil
}
