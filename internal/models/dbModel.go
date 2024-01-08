package models

import (
	"database/sql"

	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	//ID               int      `json:"-"`
	UUID             string  `json:"id"`
	Username         string  `json:"username"`
	EmailAddress     string  `json:"emailAddress"`
	FirstName        string  `json:"firstName"`
	LastName         string  `json:"lastName"`
	CellNumber       string  `json:"cellNumber"`
	Roles            []*Role `json:"roles" gorm:"many2many:user_languages;"`
	Active           bool    `json:"active"`
	TwoFactorEnabled bool    `json:"twoFactorEnabled"`
	TwoFactorMethod  string  `json:"twoFactorMethod"`
	TOTPSecret       string  `json:"-"`
	TOTPURL          string  `json:"-"`
	Metadata         JSONB   `json:"metadata"`
}

type TwoFactorRequest struct {
	gorm.Model
	UserId     uint
	RequestId  string
	IpAddress  string
	Code       string
	UserAgent  string
	SendType   string
	ExpireTime sql.NullTime
}

type UserRefreshToken struct {
	gorm.Model
	UserId     uint
	Token      string
	IpAddress  string
	UserAgent  string
	ExpireTime sql.NullTime
}

type ResetPasswordRequest struct {
	gorm.Model
	UserId     uint
	Code       string
	ExpireTime sql.NullTime
}

type Role struct {
	Id   uint `gorm:"primaryKey"`
	Type string
}

// type EmailService struct {
// 	SmtpHost         string
// 	SmtpUsername     string
// 	SmtpPassword     string
// 	SmtpPort         string
// 	FromEmailAddress string
// 	Secure           bool
// }
