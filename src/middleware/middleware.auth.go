// middleware.auth.go

package middleware

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"notary/config"
	"strings"

	"github.com/gin-gonic/gin"
	// "log"
)

// This middleware ensures that a request will be aborted with an error
// if the user is not logged in
func EnsureLoggedIn() gin.HandlerFunc {
	return func(c *gin.Context) {
		// If there's an error or if the token is empty
		// the user is not logged in
		var token string
		authString := c.Request.Header.Get("Authorization")
		if authString == "" {
			tempToken, err := c.Cookie("access_token")
			if err != nil {
				c.Redirect(307, "/u/login")
				return
			}
			token = tempToken
		} else {
			token = strings.Split(authString, " ")[1]
		}
		client := http.Client{}
		requestURL := "http://notary:9005" + config.Config.HTTPBasePath + "/oauth/userinfo"
		req, _ := http.NewRequest(http.MethodGet, requestURL, nil)
		req.Header = http.Header{
			"Authorization": []string{"Bearer " + token},
		}
		res, err := client.Do(req)
		if err != nil {
			log.Printf("Error on checking userinfo: %v", err)
			c.Redirect(307, "/ui/401")
			return
		}
		if res.StatusCode != http.StatusOK {
			log.Printf("Token is invalid: %v", err)
			c.Redirect(307, "/ui/401")
			return
		}
	}
}

func EnsureLoggedInAbort() gin.HandlerFunc {
	return func(c *gin.Context) {
		// If there's an error or if the token is empty
		// the user is not logged in
		var token string
		authString := c.Request.Header.Get("Authorization")
		if authString == "" {
			tempToken, err := c.Cookie("access_token")
			if err != nil {
				c.Redirect(307, "/u/login")
				return
			}
			token = tempToken
		} else {
			token = strings.Split(authString, " ")[1]
		}
		client := http.Client{}
		requestURL := "http://notary:9005" + config.Config.HTTPBasePath + "/oauth/userinfo"
		req, _ := http.NewRequest(http.MethodGet, requestURL, nil)
		req.Header = http.Header{
			"Authorization": []string{"Bearer " + token},
		}
		res, err := client.Do(req)
		if err != nil {
			log.Printf("Error on checking userinfo: %v", err)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		if res.StatusCode != http.StatusOK {
			log.Printf("Token is invalid: %v", err)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
	}
}

// This middleware ensures that a request will be aborted with an error
// if the user is already logged in
func EnsureNotLoggedIn() gin.HandlerFunc {
	return func(c *gin.Context) {
		// If there's an error or if the token is empty
		// the user is not logged in
		var token string
		authString := c.Request.Header.Get("Authorization")
		if authString == "" {
			tempToken, err := c.Cookie("access_token")
			if err != nil {
				return
			}
			token = tempToken
		} else {
			token = strings.Split(authString, " ")[1]
		}
		client := http.Client{}
		requestURL := "http://notary:9005" + config.Config.HTTPBasePath + "/oauth/userinfo"
		req, _ := http.NewRequest(http.MethodGet, requestURL, nil)
		req.Header = http.Header{
			"Authorization": []string{"Bearer " + token},
		}
		res, err := client.Do(req)
		if err != nil {
			return
		}
		if res.StatusCode != http.StatusOK {
			return
		}
		c.AbortWithStatus(http.StatusUnauthorized)
	}
}

func EnsureGroupAllowed(group string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// If there's an error or if the token is empty
		// the user is not logged in
		var token string
		authString := c.Request.Header.Get("Authorization")
		if authString == "" {
			tempToken, err := c.Cookie("access_token")
			if err != nil {
				c.Redirect(307, "/ui/401")
				return
			}
			token = tempToken
		} else {
			token = strings.Split(authString, " ")[1]
		}
		client := http.Client{}
		requestURL := "http://notary:9005" + config.Config.HTTPBasePath + "/oauth/userinfo"
		req, _ := http.NewRequest(http.MethodGet, requestURL, nil)
		req.Header = http.Header{
			"Authorization": []string{"Bearer " + token},
		}
		res, err := client.Do(req)
		if err != nil {
			log.Printf("Error on checking userinfo: %v", err)
			c.Redirect(307, "/ui/401")
			return
		}
		if res.StatusCode != http.StatusOK {
			log.Printf("Token is invalid: %v", err)
			c.Redirect(307, "/ui/401")
			return
		}
		var obj map[string]interface{}
		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			log.Printf("Encountered error reading body: %v", err)
			c.Redirect(307, "/ui/401")
		}
		err = json.Unmarshal([]byte(body), &obj)
		if err != nil {
			log.Printf("Encountered error parsing JSON: %v", err)
			c.Redirect(307, "/ui/401")
		}
		groups := make([]string, len(obj["groups"].([]interface{})))
		for idx, val := range obj["groups"].([]interface{}) {
			groups[idx] = val.(string)
		}
		if !StringSliceContains(groups, group) {
			c.Redirect(307, "/ui/401")
		}
	}
}

func EnsureRoleAllowed(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// If there's an error or if the token is empty
		// the user is not logged in
		var token string
		authString := c.Request.Header.Get("Authorization")
		if authString == "" {
			tempToken, err := c.Cookie("access_token")
			if err != nil {
				c.Redirect(307, "/ui/401")
				return
			}
			token = tempToken
		} else {
			token = strings.Split(authString, " ")[1]
		}
		client := http.Client{}
		requestURL := "http://notary:9005" + config.Config.HTTPBasePath + "/oauth/userinfo"
		req, _ := http.NewRequest(http.MethodGet, requestURL, nil)
		req.Header = http.Header{
			"Authorization": []string{"Bearer " + token},
		}
		res, err := client.Do(req)
		if err != nil {
			log.Printf("Error on checking userinfo: %v", err)
			c.Redirect(307, "/ui/401")
			return
		}
		if res.StatusCode != http.StatusOK {
			log.Printf("Token is invalid: %v", err)
			c.Redirect(307, "/ui/401")
			return
		}
		var obj map[string]interface{}
		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			log.Printf("Encountered error reading body: %v", err)
			c.Redirect(307, "/ui/401")
		}
		err = json.Unmarshal([]byte(body), &obj)
		if err != nil {
			log.Printf("Encountered error parsing JSON: %v", err)
			c.Redirect(307, "/ui/401")
		}
		roles := make([]string, len(obj["roles"].([]interface{})))
		for idx, val := range obj["roles"].([]interface{}) {
			roles[idx] = val.(string)
		}
		if !StringSliceContains(roles, role) {
			c.Redirect(307, "/ui/401")
		}
	}
}

func StringSliceContains(list []string, item string) bool {
	for _, v := range list {
		if v == item {
			return true
		}
	}
	return false
}
