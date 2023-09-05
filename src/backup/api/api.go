package api

import (
	"fmt"
	"log"
	"net/http"
	"notary/generates"
	"notary/user"
	"notary/utils"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

var PrivKey = []byte("notarysign")

const LIMIT_DEFAULT = "0"
const FILTER_DEFAULT = ""
const COUNT_DEFAULT = "false"
const ORDERASC_DEFAULT = "NA"
const ORDERDSC_DEFAULT = "NA"

var Healthy = false

// Health API

func GetHealth(c *gin.Context) {
	if !Healthy {
		c.Status(http.StatusServiceUnavailable)
		return
	}
	c.Status(http.StatusOK)
}

// User API

func DeleteUser(c *gin.Context) {
	var input []string
	if err := c.ShouldBindJSON(&input); err != nil {
		utils.Error(err, c, http.StatusInternalServerError)
		return
	}
	err := user.DeleteUser(input)
	if err != nil {
		utils.Error(err, c, http.StatusInternalServerError)
		return
	}
	c.Status(http.StatusOK)
}

func GetUsers(c *gin.Context) {
	filter := FILTER_DEFAULT
	limit := LIMIT_DEFAULT
	count := COUNT_DEFAULT
	orderasc := ORDERASC_DEFAULT
	orderdsc := ORDERDSC_DEFAULT
	if val, ok := c.GetQuery("filter"); ok {
		filter = val
	}
	if val, ok := c.GetQuery("limit"); ok {
		limit = val
	}
	if val, ok := c.GetQuery("count"); ok {
		count = val
	}
	if val, ok := c.GetQuery("orderasc"); ok {
		orderasc = val
	}
	if val, ok := c.GetQuery("orderdsc"); ok {
		orderdsc = val
	}
	data, err := user.GetUsers(limit, filter, count, orderasc, orderdsc)
	if err != nil {
		utils.Error(err, c, http.StatusInternalServerError)
		return
	}
	c.JSON(http.StatusOK, data)
}

func PostUser(c *gin.Context) {
	var input user.User
	if err := c.ShouldBindJSON(&input); err != nil {
		utils.Error(err, c, http.StatusInternalServerError)
		return
	}
	fileID := uuid.New().String()
	input.ID = fileID
	err := user.RegisterUser(input)
	if err != nil {
		utils.Error(err, c, http.StatusInternalServerError)
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": fileID})
}

func PutUser(c *gin.Context) {
	var input user.User
	if err := c.ShouldBindJSON(&input); err != nil {
		utils.Error(err, c, http.StatusInternalServerError)
		return
	}
	err := user.UpdateUser(input)
	if err != nil {
		utils.Error(err, c, http.StatusInternalServerError)
		return
	}
	c.Status(http.StatusOK)
}

func UserInfo(c *gin.Context) {
	if len(c.Request.Header["Authorization"]) > 0 {
		if val, ok := c.Request.Header["Authorization"]; ok {
			if len(val) > 0 {
				authToken := strings.Split(val[0], " ")[1]

				// Parse and verify jwt access token
				token, err := jwt.ParseWithClaims(authToken, &generates.JWTAccessClaims{}, func(t *jwt.Token) (interface{}, error) {
					if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
						return nil, fmt.Errorf("parse error")
					}
					return PrivKey, nil
				})
				if err != nil {
					log.Println(err)
					c.AbortWithStatus(500)
					return
				}

				claims, ok := token.Claims.(*generates.JWTAccessClaims)
				if !ok || !token.Valid {
					log.Println("invalid token")
					c.AbortWithStatus(500)
					return
				}

				c.JSON(http.StatusOK, gin.H{
					"given_name":  claims.GivenName,
					"family_name": claims.FamilyName,
					"email":       claims.Email,
					"groups":      claims.Groups,
					"roles":       claims.Roles,
					"exp":         claims.ExpiresAt,
					"sub":         claims.Subject,
					"aud":         claims.Audience,
				})
				return
			}
		}
	}
	c.AbortWithStatus(500)
}
