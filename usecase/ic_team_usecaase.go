package usecase

import (
	"github.com/Uchel/auth-final/repository"
)

type IcTeamLoginUsecase interface {
	FindByEmailIc(email string) (string, string)
}

type icTeamLoginUsecase struct {
	icTeamLoginRepo repository.IcTeamLoginRepo
}

//==========================================================================================

func (u icTeamLoginUsecase) FindByEmailIc(email string) (string, string) {

	return u.icTeamLoginRepo.GetByEmailIc(email)
}

func NewIcTeamUsecase(icTeamLoginRepo repository.IcTeamLoginRepo) IcTeamLoginUsecase {
	return &icTeamLoginUsecase{
		icTeamLoginRepo: icTeamLoginRepo,
	}
}
