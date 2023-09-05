// user.go

package user

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"notary/config"
	"notary/utils"
	"reflect"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jfcarter2358/ceresdb-go/connection"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Username             string   `json:"username"`
	Password             string   `json:"password"`
	GivenName            string   `json:"given_name"`
	FamilyName           string   `json:"family_name"`
	ID                   string   `json:"id"`
	Roles                []string `json:"roles"`
	Groups               []string `json:"groups"`
	Email                string   `json:"email"`
	ResetToken           string   `json:"reset_token"`
	ResetTokenCreateDate string   `json:"reset_token_create_date"`
	Created              string   `json:"created"`
	Updated              string   `json:"updated"`
}

const LIMIT_DEFAULT = "0"
const FILTER_DEFAULT = ""
const COUNT_DEFAULT = "false"
const ORDERASC_DEFAULT = "NA"
const ORDERDSC_DEFAULT = "NA"

func RegisterUser(newUser User) error {
	if newUser.ID == "" {
		newUser.ID = uuid.New().String()
	}
	newUser.Password = HashAndSalt([]byte(newUser.Password))
	currentTime := time.Now().UTC()
	newUser.Created = currentTime.Format("2006-01-02T15:04:05Z")
	newUser.Updated = currentTime.Format("2006-01-02T15:04:05Z")
	queryData, _ := json.Marshal(&newUser)
	queryString := fmt.Sprintf("post record %v.users %v", config.Config.DB.Name, string(queryData))
	_, err := connection.Query(queryString)
	return err
}

func DeleteUser(userIDs []string) error {
	queryString := fmt.Sprintf("get record %v.users", config.Config.DB.Name)
	currentData, err := connection.Query(queryString)
	if err != nil {
		return err
	}
	ids := make([]string, 0)
	for _, datum := range currentData {
		if utils.Contains(userIDs, datum["id"].(string)) {
			ids = append(ids, datum[".id"].(string))
		}
	}
	queryData, _ := json.Marshal(&ids)
	queryString = fmt.Sprintf("delete record %v.users %v", config.Config.DB.Name, string(queryData))
	_, err = connection.Query(queryString)
	return err
}

func UpdateUser(newUser User) error {
	if newUser.ID == "" {
		err := errors.New("'id' field is required to update an user")
		return err
	}
	queryString := fmt.Sprintf("get record %v.users", config.Config.DB.Name)
	currentData, err := connection.Query(queryString)
	if err != nil {
		return err
	}
	for _, datum := range currentData {
		if datum["id"].(string) == newUser.ID {
			if newUser.Username != "" {
				if newUser.Username != datum["username"].(string) {
					datum["username"] = newUser.Username
				}
			}
			if newUser.Password != "" {
				if newUser.Password != datum["password"].(string) {
					datum["password"] = HashAndSalt([]byte(newUser.Password))
				}
			}
			if newUser.GivenName != "" {
				if newUser.GivenName != datum["given_name"].(string) {
					datum["given_name"] = newUser.GivenName
				}
			}
			if newUser.FamilyName != "" {
				if newUser.FamilyName != datum["family_name"].(string) {
					datum["family_name"] = newUser.FamilyName
				}
			}
			if newUser.Roles != nil {
				tmpRoles := make([]string, len(datum["roles"].([]interface{})))
				for idx, val := range datum["roles"].([]interface{}) {
					tmpRoles[idx] = val.(string)
				}
				if !reflect.DeepEqual(newUser.Roles, tmpRoles) {
					datum["roles"] = newUser.Roles
				}
			}
			if newUser.Groups != nil {
				tmpGroups := make([]string, len(datum["groups"].([]interface{})))
				for idx, val := range datum["groups"].([]interface{}) {
					tmpGroups[idx] = val.(string)
				}
				if !reflect.DeepEqual(newUser.Groups, tmpGroups) {
					datum["groups"] = newUser.Groups
				}
			}
			currentTime := time.Now().UTC()
			datum["updated"] = currentTime.Format("2006-01-02T15:04:05Z")
			queryData, _ := json.Marshal(&datum)
			queryString := fmt.Sprintf("put record %v.users %v", config.Config.DB.Name, string(queryData))
			_, err := connection.Query(queryString)
			if err != nil {
				return err
			}
			return nil
		}
	}
	err = RegisterUser(newUser)
	return err
}

func GetUsers(limit, filter, count, orderasc, orderdsc string) ([]User, error) {
	queryString := fmt.Sprintf("get record %v.users", config.Config.DB.Name)
	if filter != FILTER_DEFAULT {
		queryString += fmt.Sprintf(" | filter %v", filter)
	}
	if limit != LIMIT_DEFAULT {
		queryString += fmt.Sprintf(" | limit %v", limit)
	}
	if count != COUNT_DEFAULT {
		queryString += " | count"
	}
	if orderdsc != ORDERDSC_DEFAULT {
		queryString += fmt.Sprintf(" | orderdsc %v", orderdsc)
	}
	if count != COUNT_DEFAULT {
		queryString += " | count"
	}
	data, err := connection.Query(queryString)
	if err != nil {
		return nil, err
	}
	marshalled, _ := json.Marshal(data)
	var output []User
	json.Unmarshal(marshalled, &output)
	return output, nil
}

func IsUserPartOfGroup(id, group string) bool {
	users, err := GetUsers(LIMIT_DEFAULT, fmt.Sprintf("id = \"%v\"", id), COUNT_DEFAULT, ORDERASC_DEFAULT, ORDERDSC_DEFAULT)
	if err != nil || len(users) == 0 {
		return false
	}
	return utils.Contains(users[0].Groups, group)
}

func IsUserValid(username, password string) (bool, string) {
	users, err := GetUsers(LIMIT_DEFAULT, fmt.Sprintf("username = \"%v\"", username), COUNT_DEFAULT, ORDERASC_DEFAULT, ORDERDSC_DEFAULT)
	if err != nil || len(users) == 0 {
		return false, ""
	}
	err = bcrypt.CompareHashAndPassword([]byte(users[0].Password), []byte(password))
	if err != nil {
		log.Println(err)
		return false, ""
	}
	return true, users[0].ID
}

// Check if the supplied username is available
func IsUsernameAvailable(username string) bool {
	users, err := GetUsers(LIMIT_DEFAULT, FILTER_DEFAULT, COUNT_DEFAULT, ORDERASC_DEFAULT, ORDERDSC_DEFAULT)
	if err != nil {
		return false
	}
	for _, u := range users {
		if u.Username == username {
			return false
		}
	}
	return true
}

func HashAndSalt(pwd []byte) string {
	hash, err := bcrypt.GenerateFromPassword(pwd, bcrypt.MinCost)
	if err != nil {
		log.Println(err)
	}
	return string(hash)
}

func PerformLogin(c *gin.Context) {
	// Obtain the POSTed username and password values
	username := c.PostForm("username")
	password := c.PostForm("password")

	// Check if the username/password combination is valid
	is_valid, user_id := IsUserValid(username, password)
	if is_valid {
		// If the username/password is valid set the token in a cookie
		token := generateSessionToken()

		c.SetCookie("token", token, 3600, "", "", false, false)
		c.SetCookie("userId", user_id, 3600, "", "", false, false)
		c.Set("is_logged_in", true)
		c.Set("user", user_id)

		c.Redirect(302, "/")
		// showIndexPage(c)

	} else {
		// If the username/password combination is invalid,
		// show the error message on the login page
		c.HTML(http.StatusBadRequest, "local_login.html", gin.H{
			"ErrorTitle":   "Login Failed",
			"ErrorMessage": "Invalid credentials provided"})
	}
}

func generateSessionToken() string {
	// We're using a random 16 character string as the session token
	// This is NOT a secure way of generating session tokens
	// DO NOT USE THIS IN PRODUCTION
	return strconv.FormatInt(rand.Int63(), 16)
}

func Logout(c *gin.Context) {

	// var sameSiteCookie http.SameSite;

	// Clear the cookie
	// c.SetCookie("token", "", -1, "", "", sameSiteCookie, false, true)
	c.SetCookie("token", "", -1, "", "", false, true)

	// Redirect to the home page
	c.Redirect(http.StatusTemporaryRedirect, "/")
}
