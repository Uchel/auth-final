package usecase

import (
	"github.com/Uchel/auth-final/repository"
)

type StTeamLoginUsecase interface {
	FindByEmailSt(email string) (string, string)
}

type stTeamLoginUsecase struct {
	stTeamLoginRepo repository.StTeamLoginRepo
}

//==========================================================================================

func (u stTeamLoginUsecase) FindByEmailSt(email string) (string, string) {

	return u.stTeamLoginRepo.GetByEmailSt(email)
}

func NewStTeamLoginUsecase(stTeamLoginRepo repository.StTeamLoginRepo) StTeamLoginUsecase {
	return &stTeamLoginUsecase{
		stTeamLoginRepo: stTeamLoginRepo,
	}
}
