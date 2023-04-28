package repository

import (
	"database/sql"
	"log"

	"github.com/Uchel/auth-final/model"
)

type AdminWhLoginRepo interface {
	GetByEmailAdminWh(email string) (string, string)
}

type adminWhLoginRepo struct {
	db *sql.DB
}

func (u *adminWhLoginRepo) GetByEmailAdminWh(email string) (string, string) {
	var adminWh model.AdminWh

	query := "SELECT email, password FROM admin_wh WHERE email=$1"

	row := u.db.QueryRow(query, email)

	if err := row.Scan(&adminWh.Email, &adminWh.Password); err != nil {
		log.Println(err)
	}

	if adminWh.Email == "" {
		return "user not found", " or password uncorrect"
	}

	return adminWh.Email, adminWh.Password
}
func NewAdminWhLoginRepo(db *sql.DB) AdminWhLoginRepo {
	repo := new(adminWhLoginRepo)

	repo.db = db

	return repo
}
