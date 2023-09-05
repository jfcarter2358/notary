package main

import (
	// "encoding/json"

	"io"
	"net/http"
	"net/http/httputil"
	"notary/api"
	"notary/ceresdb"
	"notary/generates"
	"strconv"

	// "time"

	"github.com/jfcarter2358/ceresdb-go/connection"
	"github.com/sirupsen/logrus"

	// "notary/internal/json"

	"notary/errors"
	"notary/manage"
	"notary/models"
	"notary/server"
	"notary/store"

	"github.com/go-session/session"

	"github.com/dgrijalva/jwt-go"

	"notary/config"
	"notary/middleware"
	"notary/user"

	"github.com/gin-gonic/gin"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

type WellKnownResponse struct {
	AuthorizationEndpoint             string `json:"authorization_endpoint"`
	TokenEndpoint                     string `json:"token_endpoint"`
	UserinfoEndpoint                  string `json:"userinfo_endpoint"`
	EndSessionEndpoint                string `json:"end_session_endpoint"`
	IntrospectionEndpoint             string `json:"introspection_endpoint"`
	JWKSUri                           string `json:"jwks_uri"`
	SubjectTypesSupported             string `json:"subject_types_supported"`
	TokenEndpointAuthMethodsSupported string `json:"token_endpoint_auth_methods_supported"`
}

var router *gin.Engine
var Privkey *ecdsa.PrivateKey
var JWKS []byte
var ClientStore *store.ClientStore
var Srv *server.Server

func main() {
	// Set Gin to production mode
	gin.SetMode(gin.ReleaseMode)

	log := logrus.New()

	// load config
	config.LoadConfig()

	routerPort := ":" + strconv.Itoa(config.Config.HTTPPort)
	connection.Initialize(config.Config.DB.Username, config.Config.DB.Password, config.Config.DB.Host, config.Config.DB.Port)

	if err := ceresdb.VerifyDatabase(config.Config.DB.Name); err != nil {
		panic(err)
	}
	if err := ceresdb.VerifyCollections(config.Config.DB.Name); err != nil {
		panic(err)
	}

	// Privkey, _, err := getEcdsaKey(2) //Generate elliptic curve private key
	// if err != nil {
	// 	fmt.Println("getEcdsaKey is error!", err)
	// 	return
	// }
	// api.Privkey = Privkey

	// jwkkey, err := jwk.New(Privkey)
	// if err != nil {
	// 	fmt.Printf("failed to create symmetric key: %s\n", err)
	// 	return
	// }
	// jwkkey.Set(jwk.KeyIDKey, "314159")
	// JWKS, _ = json.MarshalIndent(jwkkey, "", "  ")

	gin.SetMode(gin.ReleaseMode)

	router = gin.Default()
	router.LoadHTMLGlob("html/*.html")
	router.Use(middleware.CORSMiddleware())

	adminUser := user.User{
		Username:   config.Config.Admin.Username,
		Password:   config.Config.Admin.Password,
		FamilyName: "Admin",
		GivenName:  "Admin",
		Email:      "admin@admin.com",
		Roles:      []string{"read", "write", "admin"},
		Groups:     []string{"admin"},
	}
	user.RegisterUser(adminUser)

	manager := manage.NewDefaultManager()
	manager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)

	// token store
	manager.MustTokenStorage(store.NewMemoryTokenStore())

	// generate jwt access token
	manager.MapAccessGenerate(generates.NewJWTAccessGenerate("", []byte("notarysign"), jwt.SigningMethodHS512))
	// generate opaque access token
	// manager.MapAccessGenerate(generates.NewAccessGenerate())

	ClientStore := store.NewClientStore()

	for _, client := range config.Config.Clients {
		ClientStore.Set(client.ClientID, &models.Client{
			ID:     client.ClientID,
			Secret: client.ClientSecret,
			Domain: client.RedirectURL,
		})
	}
	manager.MapClientStorage(ClientStore)

	Srv = server.NewServer(server.NewConfig(), manager)

	Srv.SetPasswordAuthorizationHandler(func(username, password string) (userID string, err error) {
		isValid, userIdent := user.IsUserValid(username, password)
		if isValid {
			userID = userIdent
		} else {
			err = errors.New("Invalid username or password")
		}
		return
	})

	Srv.SetUserAuthorizationHandler(userAuthorizeHandler)

	Srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		log.Println("Internal Error:", err.Error())
		return
	})

	Srv.SetResponseErrorHandler(func(re *errors.Response) {
		log.Println("Response Error:", re.Error.Error())
	})

	log.Print("Running with port: " + strconv.Itoa(config.Config.HTTPPort))

	api.Healthy = true

	initializeRoutes()

	router.Run(routerPort)
}

func dumpRequest(writer io.Writer, header string, r *http.Request) error {
	data, err := httputil.DumpRequest(r, true)
	if err != nil {
		return err
	}
	writer.Write([]byte("\n" + header + ": \n"))
	writer.Write(data)
	return nil
}

func userAuthorizeHandler(w http.ResponseWriter, r *http.Request) (userID string, err error) {
	store, err := session.Start(r.Context(), w, r)
	if err != nil {
		return
	}

	uid, ok := store.Get("LoggedInUserID")
	if !ok {
		if r.Form == nil {
			r.ParseForm()
		}

		store.Set("ReturnUri", r.Form)
		store.Save()

		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusFound)
		return
	}

	userID = uid.(string)
	store.Delete("LoggedInUserID")
	store.Save()
	return
}

func getEcdsaKey(length int) (*ecdsa.PrivateKey, ecdsa.PublicKey, error) {
	var err error
	var prk *ecdsa.PrivateKey
	var puk ecdsa.PublicKey
	var curve elliptic.Curve
	switch length {
	case 1:
		curve = elliptic.P224()
	case 2:
		curve = elliptic.P256()
	case 3:
		curve = elliptic.P384()
	case 4:
		curve = elliptic.P521()
	default:
		err = errors.New("The entered signature level is wrong!")
	}
	prk, err = ecdsa.GenerateKey(curve, rand.Reader) //Generate private key by random number generated by "crypto/rand" module
	if err != nil {
		return prk, puk, err
	}
	puk = prk.PublicKey
	return prk, puk, err
}
