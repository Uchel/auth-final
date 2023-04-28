package usecase

import (
	"github.com/Uchel/auth-final/repository"
)

type AdminWhLoginUsecase interface {
	FindByEmailAdminWh(email string) (string, string)
}

type adminWhLoginUsecase struct {
	adminWhLoginRepo repository.AdminWhLoginRepo
}

//==========================================================================================

func (u adminWhLoginUsecase) FindByEmailAdminWh(email string) (string, string) {

	return u.adminWhLoginRepo.GetByEmailAdminWh(email)
}

func NewAdminWhUsecase(AdminWhLoginRepo repository.AdminWhLoginRepo) AdminWhLoginUsecase {
	return &adminWhLoginUsecase{
		adminWhLoginRepo: AdminWhLoginRepo,
	}
}
