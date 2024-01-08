package utils

import (
	"fmt"
	"log"
	"time"

	"github.com/bachdang2k/security-golang/internal/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type DatabaseConfig struct {
	Host        string
	Username    string
	Password    string
	Port        string
	Database    string
	SSL         bool
	Certificate string
}

// GetMainDatabaseConnections connects to the main Database
func GetMainDatabaseConnections(config DatabaseConfig) (*gorm.DB, error) {

	sslConnectionString := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=verify-full sslrootcert=%s",
		config.Host,
		config.Port,
		config.Username,
		config.Password,
		config.Database,
		config.Certificate,
	)

	normalConnectionString := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		config.Host,
		config.Port,
		config.Username,
		config.Password,
		config.Database,
	)

	var connectionString string
	if config.SSL {
		connectionString = sslConnectionString
	} else {
		connectionString = normalConnectionString
	}

	db, err := gorm.Open(postgres.Open(connectionString))

	// var databaseConnection *sql.DB
	// databaseConnection, err := sql.Open("postgres", connectionString)
	if err != nil {
		log.Fatal("loi xay ra ", err)
		return nil, err
	}

	databaseConnection, err := db.DB()
	if err != nil {
		log.Fatal("loi xay ra ", err)
		return nil, err
	}

	if err := databaseConnection.Ping(); err != nil {
		log.Fatal("loi xay ra ", err)
		return nil, err
	}

	databaseConnection.SetMaxIdleConns(10)
	databaseConnection.SetMaxOpenConns(20)
	databaseConnection.SetConnMaxIdleTime(15 * time.Second)
	databaseConnection.SetConnMaxIdleTime(30 * time.Second)

	if err := MigrateDatabase(db); err != nil {
		return nil, err
	}

	return db, nil
}

func MigrateDatabase(db *gorm.DB) error {
	DropUnusedColumns(db, &models.User{})
	return db.AutoMigrate(&models.User{}, &models.TwoFactorRequest{}, &models.UserRefreshToken{}, &models.ResetPasswordRequest{}, &models.Role{})
}

func DropUnusedColumns(db *gorm.DB, table interface{}) {
	stmt := &gorm.Statement{DB: db}
	if err := stmt.Parse(table); err != nil { // parse with table name
		log.Println("loi xay ra ", err)
		return
	}

	fields := stmt.Schema.Fields
	columns, _ := db.Debug().Migrator().ColumnTypes(table) //get columns name of table
	for i := range columns {
		found := false
		for j := range fields {
			if columns[i].Name() == fields[j].DBName {
				found = true
				break
			}
		}
		if !found {
			err := db.Migrator().DropColumn(table, columns[i].Name())
			if err != nil {
				return
			}
		}
	}
}

func Transaction(db *gorm.DB, callback func(db *gorm.DB) error) error {
	tx := db.Debug().Begin()
	if tx.Error != nil {
		return tx.Error
	}
	committed := false
	defer (func() {
		if !committed {
			tx.Rollback()
		}
	})()
	if err := callback(tx); err != nil {
		return err
	}
	if err := tx.Commit().Error; err != nil {
		return err
	}
	committed = true
	return nil
}
