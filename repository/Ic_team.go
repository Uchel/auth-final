package repository

import (
	"database/sql"
	"log"

	"github.com/Uchel/auth-final/model"
)

type IcTeamLoginRepo interface {
	GetByEmailIc(email string) (string, string)
}

type icTeamLoginRepo struct {
	db *sql.DB
}

func (u *icTeamLoginRepo) GetByEmailIc(email string) (string, string) {
	var IcTeam model.IcTeam

	query := "SELECT email, password FROM ic_team WHERE email=$1"

	row := u.db.QueryRow(query, email)

	if err := row.Scan(&IcTeam.Email, &IcTeam.Password); err != nil {
		log.Println(err)
	}

	if IcTeam.Email == "" {
		return "user not found", " or password uncorrect"
	}

	return IcTeam.Email, IcTeam.Password
}
func NewIcTeamLoginRepo(db *sql.DB) IcTeamLoginRepo {
	repo := new(icTeamLoginRepo)

	repo.db = db

	return repo
}
