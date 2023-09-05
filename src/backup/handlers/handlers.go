package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-session/session"
)

func render(c *gin.Context, data gin.H, templateName string) {
	/*
		loggedInInterface, _ := c.Get("is_logged_in")
		data["is_logged_in"] = loggedInInterface.(bool)
		user, _ := c.Get("user")
		data["user"] = user
	*/

	switch c.Request.Header.Get("Accept") {
	case "application/json":
		// Respond with JSON
		c.JSON(http.StatusOK, data["payload"])
	case "application/xml":
		// Respond with XML
		c.XML(http.StatusOK, data["payload"])
	default:
		// Respond with HTML
		c.HTML(http.StatusOK, templateName, data)
	}
}

func LoginGetHandler(c *gin.Context) {
	_, err := session.Start(c.Request.Context(), c.Writer, c.Request)
	if err != nil {
		http.Error(c.Writer, err.Error(), http.StatusInternalServerError)
		return
	}

	render(c, gin.H{}, "login.html")
}

func AuthGetHandler(c *gin.Context) {
	store, err := session.Start(nil, c.Writer, c.Request)
	if err != nil {
		http.Error(c.Writer, err.Error(), http.StatusInternalServerError)
		return
	}

	if _, ok := store.Get("LoggedInUserID"); !ok {
		c.Writer.Header().Set("Location", "/login")
		c.Writer.WriteHeader(http.StatusFound)
		return
	}

	render(c, gin.H{}, "auth.html")
}

func Handler401(c *gin.Context) {
	render(c, gin.H{}, "401.html")
}

func Handler404(c *gin.Context) {
	render(c, gin.H{}, "404.html")
}

func LocalLoginHandler(c *gin.Context) {
	render(c, gin.H{}, "local_login.html")
}

func RedirectIndexHandler(c *gin.Context) {
	c.Redirect(302, "/ui/index")
}

func IndexHandler(c *gin.Context) {
	render(c, gin.H{}, "index.html")
}

func CreateHandler(c *gin.Context) {
	render(c, gin.H{}, "create.html")
}

func DeleteHandler(c *gin.Context) {
	render(c, gin.H{}, "delete.html")
}

func EditHandler(c *gin.Context) {
	render(c, gin.H{}, "edit.html")
}

func EditIndexHandler(c *gin.Context) {
	render(c, gin.H{}, "edit.index.html")
}
