package services

import (
	"log"

	"github.com/bachdang2k/security-golang/internal/models"
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
func (usrSrv *UserService) List(offset int, limit int) ([]models.User, error) {
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
	rows, err := usrSrv.db.Raw(queryString, offset, limit).Rows()
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		user := models.User{}
		rows.Scan(&user.ID, &user.UUID, &user.Username, &user.FirstName,
			&user.LastName, &user.CellNumber,
			&user.EmailAddress, &user.Active, &user.TwoFactorEnabled)
		roles, _ := usrSrv.GetRoles(int(user.Model.ID))
		user.Roles = roles
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

	role, _ := service.GetRoles(int(userDetails.Model.ID))
	userDetails.Roles = role
	if err != nil {
		log.Println(err)
		return nil
	}
	return userDetails
}

// GetUsername gets the usersDetails by username
func (usrSrv *UserService) GetByUsername(username string) *models.User {
	user := models.User{}
	if err := usrSrv.db.Model(&models.User{}).Where("username = ?", username).Or("email_address = ?", username).First(&user).Error; err != nil {
		log.Println("loi xay ra khi query user ", err)
		return nil
	}
	return &user
}

// GetRoles gets a list of user roles
func (usrSrv *UserService) GetRoles(userId int) ([]string, error) {
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
	rows, err := usrSrv.db.Raw(queryString, userId).Rows()
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
