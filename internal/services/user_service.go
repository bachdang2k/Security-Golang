package services

import (
	"database/sql"
	"errors"
	"log"
	"os"
	"strings"
	"time"

	"github.com/bachdang2k/security-golang/internal/models"
	"github.com/pquerna/otp/totp"
	"gorm.io/gorm"
)

type UserService struct {
	db *gorm.DB
}

func NewUserService(db *gorm.DB) *UserService {
	return &UserService{
		db: db,
	}
}

// List a bunch of users
func (service *UserService) List(offset int, limit int) ([]models.User, error) {
	users := []models.User{}
	//Get the list of users
	queryString :=
		`SELECT
			users.id,
			users.uu_id,
			users.username,
			users.first_name,
			users.last_name,
			users.email_address,
			users.phone_number,
			users.active,
			users.two_factor_enabled
		FROM
			users
		OFFSET ?
		LIMIT ?
	    `

	//rows, err := usrSrv.db.Model(&models.User{}).Offset(offset).Limit(limit).Rows()
	rows, err := service.db.Raw(queryString, offset, limit).Rows()
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		user := models.User{}
		rows.Scan(&user.ID, &user.UUID, &user.Username, &user.FirstName,
			&user.LastName, &user.CellNumber,
			&user.EmailAddress, &user.Active, &user.TwoFactorEnabled)
		//roles, _ := usrSrv.GetRoles(int(user.Model.ID))
		//user.Roles = roles
		users = append(users, user)
	}

	return users, nil
}

// Get user details based on ID
func (service *UserService) Get(userId int) *models.User {
	userDetails := &models.User{}
	queryString :=
		`SELECT 
			users.id,
			users.uu_id,
			users.username,
			users.first_name,
			users.last_name,
			users.email_address,
			users.phone_number,
			users.active,
			users.two_factor_enabled,
			users.two_factor_method,
			users.totp_secret ,
			users.totp_url,
			users.meta_data
		FROM 
			users 
		WHERE 
			users.id = ?      
		LIMIT 1
        `

	row := service.db.Raw(queryString, userId).Row()
	err := row.Scan(&userDetails.ID, &userDetails.UUID, &userDetails.Username, &userDetails.FirstName,
		&userDetails.LastName, &userDetails.EmailAddress, &userDetails.CellNumber, &userDetails.Active, &userDetails.TwoFactorEnabled,
		&userDetails.TwoFactorMethod, &userDetails.TOTPSecret, &userDetails.TOTPURL, &userDetails.Metadata,
	)

	//role, _ := service.GetRoles(int(userDetails.Model.ID))
	//userDetails.Roles = role
	if err != nil {
		log.Println(err)
		return nil
	}
	return userDetails
}

// GetByUsername GetUsername gets the usersDetails by username
func (service *UserService) GetByUsername(username string) *models.User {
	user := models.User{}
	if err := service.db.Model(&models.User{}).Where("username = ?", username).Or("email_address = ?", username).First(&user).Error; err != nil {
		log.Println("loi xay ra khi query user ", err)
		return nil
	}
	return &user
}

// GetRoles gets a list of user roles
func (service *UserService) GetRoles(userId int) ([]string, error) {
	roles := []string{}
	// Get user roles
	queryString := `
		SELECT 
			roles.type AS role_name
		FROM 
			user_roles
		LEFT JOIN 
			roles ON user_roles.role_id = roles.id 
		WHERE 
			user_roles.user_id = ?
	    `
	rows, err := service.db.Raw(queryString, userId).Rows()
	defer rows.Close()
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var role string
		rows.Scan(&role)
		roles = append(roles, role)
	}
	return roles, nil

}

func (service *UserService) Update(userId uint, request models.UserUpdateRequest) error {

	var user *models.User

	err := service.db.Model(&models.User{}).Where("id = ?", userId).First(user).Error
	if err != nil {
		log.Println("loi xay ra ", err)
		return err
	}
	if user == nil {
		return errors.New("user Not Found")
	}

	// Update first Name
	if strings.Trim(request.FirstName, "") != "" {
		user.FirstName = request.FirstName
	}
	// Update last Name
	if strings.Trim(request.LastName, "") != "" {
		user.LastName = request.LastName
	}
	// Update email Address
	if strings.Trim(request.EmailAddress, "") != "" {
		user.EmailAddress = request.EmailAddress
	}
	// Update cell number
	if strings.Trim(request.CellNumber, "") != "" {
		user.CellNumber = request.CellNumber
	}

	service.db.Model(&models.User{}).Save(user)

	return nil
}

func (service *UserService) DeleteToken(userId uint, refreshToken string) (bool, error) {

	var userRefreshToken *models.UserRefreshToken
	if err := service.db.Model(&models.TokenRefreshRequest{}).Where("user_id = ? AND token = ?", userId, refreshToken).First(userRefreshToken).Error; err != nil {
		log.Println("loi xay ra ", err)
		return false, err
	}

	if rowsAff := service.db.Model(&models.UserRefreshToken{}).Delete(userRefreshToken).RowsAffected; rowsAff == 0 {
		return false, nil
	}

	return true, nil
}

func (service *UserService) Enable2Factor(userId uint, methodCode string) error {

	var user *models.User
	if rowsAff := service.db.Model(&models.User{}).Where("user_id = ?", userId).First(user).RowsAffected; rowsAff == 0 {
		return errors.New("user Not Found")
	}

	user.TwoFactorEnabled = true
	user.TwoFactorMethod = methodCode

	if err := service.db.Model(&models.User{}).Updates(user).Error; err != nil {
		log.Println("loi xay ra ", err)
		return err
	}

	return nil
}

func (service *UserService) Enable2FactorTOTP(userId uint) (*models.EnableTOTPResponse, error) {

	var userDetail *models.User
	response := &models.EnableTOTPResponse{}

	if rowsAff := service.db.Model(&models.User{}).Where("id = ?", userId).Find(userDetail).RowsAffected; rowsAff == 0 {
		return response, errors.New("user Not Found")
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      os.Getenv("ISSUER_NAME"),
		AccountName: userDetail.Username,
		SecretSize:  50,
	})
	if err != nil {
		log.Println(err)
		return nil, err
	}

	response.URL = key.URL()

	userDetail.TwoFactorEnabled = true
	userDetail.TwoFactorMethod = "TOTP"
	userDetail.TOTPSecret = key.Secret()
	userDetail.TOTPURL = key.URL()
	userDetail.TOTPCreated = sql.NullTime{Time: time.Now(), Valid: true}

	if err := service.db.Model(&models.User{}).Updates(userDetail).Error; err != nil {
		return nil, err
	}

	return response, nil
}
