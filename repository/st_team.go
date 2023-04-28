package repository

import (
	"database/sql"
	"log"

	"github.com/Uchel/auth-final/model"
)

type StTeamLoginRepo interface {
	GetByEmailSt(email string) (string, string)
}

type stTeamLoginRepo struct {
	db *sql.DB
}

func (u *stTeamLoginRepo) GetByEmailSt(email string) (string, string) {
	var StTeam model.StTeam

	query := "SELECT email, password FROM st_team WHERE email=$1"

	row := u.db.QueryRow(query, email)

	if err := row.Scan(&StTeam.Email, &StTeam.Password); err != nil {
		log.Println(err)
	}

	if StTeam.Email == "" {
		return "user not found", " or password uncorrect"
	}

	return StTeam.Email, StTeam.Password
}
func NewStTeamLoginRepo(db *sql.DB) StTeamLoginRepo {
	repo := new(stTeamLoginRepo)

	repo.db = db

	return repo
}
