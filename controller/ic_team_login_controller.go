package controller

import (
	"net/http"

	"time"

	"github.com/dgrijalva/jwt-go"

	"github.com/Uchel/auth-final/model"
	"github.com/Uchel/auth-final/usecase"
	"github.com/gin-gonic/gin"
)

type AuthIcTeamLoginController struct {
	IcTeamLoginUsecase usecase.IcTeamLoginUsecase
	waktu              int
}

func (c *AuthIcTeamLoginController) LoginIcTeam(ctx *gin.Context) {

	var loginReq model.LoginReq

	if err := ctx.BindJSON(&loginReq); err != nil {
		ctx.JSON(http.StatusBadRequest, "invalid input")
		return
	}
	email, password := c.IcTeamLoginUsecase.FindByEmailIc(loginReq.Email)

	// authenticate user (compare username dan password)
	if loginReq.Email == email && loginReq.Password == password {
		// generate JWT token
		token := jwt.New(jwt.SigningMethodHS256)
		claims := token.Claims.(jwt.MapClaims)
		claims["email"] = loginReq.Email
		claims["role"] = "ic"
		claims["exp"] = time.Now().Add(time.Minute * time.Duration(c.waktu)).Unix()

		tokenString, err := token.SignedString([]byte("secret"))
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "gagal generate token"})
			return
		}

		ctx.JSON(http.StatusOK, gin.H{"token": tokenString})
	} else {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "unregistered user"})
	}
}

func NewIcTeamLoginController(u usecase.IcTeamLoginUsecase, waktu int) *AuthIcTeamLoginController {
	controller := AuthIcTeamLoginController{

		IcTeamLoginUsecase: u,
		waktu:              waktu,
	}

	return &controller
}
