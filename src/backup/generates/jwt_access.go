package generates

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"strings"
	"time"

	"notary/errors"
	"notary/oauth2"
	"notary/user"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
)

// JWTAccessClaims jwt claims
type JWTAccessClaims struct {
	GivenName  string   `json:"given_name"`
	FamilyName string   `json:"family_name"`
	Email      string   `json:"email"`
	Groups     []string `json:"groups"`
	Roles      []string `json:"roles"`
	jwt.StandardClaims
}

// Valid claims verification
func (a *JWTAccessClaims) Valid() error {
	if time.Unix(a.ExpiresAt, 0).Before(time.Now()) {
		return errors.ErrInvalidAccessToken
	}
	return nil
}

// NewJWTAccessGenerate create to generate the jwt access token instance
func NewJWTAccessGenerate(kid string, key []byte, method jwt.SigningMethod) *JWTAccessGenerate {
	return &JWTAccessGenerate{
		SignedKeyID:  kid,
		SignedKey:    key,
		SignedMethod: method,
	}
}

// JWTAccessGenerate generate the jwt access token
type JWTAccessGenerate struct {
	SignedKeyID  string
	SignedKey    []byte
	SignedMethod jwt.SigningMethod
}

// Token based on the UUID generated token
func (a *JWTAccessGenerate) Token(ctx context.Context, data *oauth2.GenerateBasic, isGenRefresh bool) (string, string, error) {
	if data.UserID == "" {
		log.Printf("Client authentication flow")
		claims := &JWTAccessClaims{
			Roles:  []string{"read", "write", "admin"},
			Groups: []string{"admin"},
			StandardClaims: jwt.StandardClaims{
				Audience:  data.Client.GetID(),
				Subject:   data.UserID,
				ExpiresAt: data.TokenInfo.GetAccessCreateAt().Add(data.TokenInfo.GetAccessExpiresIn()).Unix(),
			},
		}

		token := jwt.NewWithClaims(a.SignedMethod, claims)
		if a.SignedKeyID != "" {
			token.Header["kid"] = a.SignedKeyID
		}
		var key interface{}
		if a.isEs() {
			v, err := jwt.ParseECPrivateKeyFromPEM(a.SignedKey)
			if err != nil {
				return "", "", err
			}
			key = v
		} else if a.isRsOrPS() {
			v, err := jwt.ParseRSAPrivateKeyFromPEM(a.SignedKey)
			if err != nil {
				return "", "", err
			}
			key = v
		} else if a.isHs() {
			key = a.SignedKey
		} else {
			return "", "", errors.New("unsupported sign method")
		}
		access, err := token.SignedString(key)
		if err != nil {
			return "", "", err
		}
		refresh := ""
		if isGenRefresh {
			t := uuid.NewSHA1(uuid.Must(uuid.NewRandom()), []byte(access)).String()
			refresh = base64.URLEncoding.EncodeToString([]byte(t))
			refresh = strings.ToUpper(strings.TrimRight(refresh, "="))
		}

		return access, refresh, nil
	} else {
		users, err := user.GetUsers("0", fmt.Sprintf("id = \"%v\"", data.UserID), "false", "NA", "NA")
		if err != nil {
			return "", "", err
		}
		if len(users) == 0 {
			return "", "", errors.New(fmt.Sprintf("User with id %v was not found", data.UserID))
		}
		claims := &JWTAccessClaims{
			GivenName:  users[0].GivenName,
			FamilyName: users[0].FamilyName,
			Roles:      users[0].Roles,
			Groups:     users[0].Groups,
			Email:      users[0].Email,
			StandardClaims: jwt.StandardClaims{
				Audience:  data.Client.GetID(),
				Subject:   data.UserID,
				ExpiresAt: data.TokenInfo.GetAccessCreateAt().Add(data.TokenInfo.GetAccessExpiresIn()).Unix(),
			},
		}

		token := jwt.NewWithClaims(a.SignedMethod, claims)
		if a.SignedKeyID != "" {
			token.Header["kid"] = a.SignedKeyID
		}
		var key interface{}
		if a.isEs() {
			v, err := jwt.ParseECPrivateKeyFromPEM(a.SignedKey)
			if err != nil {
				return "", "", err
			}
			key = v
		} else if a.isRsOrPS() {
			v, err := jwt.ParseRSAPrivateKeyFromPEM(a.SignedKey)
			if err != nil {
				return "", "", err
			}
			key = v
		} else if a.isHs() {
			key = a.SignedKey
		} else {
			return "", "", errors.New("unsupported sign method")
		}
		access, err := token.SignedString(key)
		if err != nil {
			return "", "", err
		}
		refresh := ""
		if isGenRefresh {
			t := uuid.NewSHA1(uuid.Must(uuid.NewRandom()), []byte(access)).String()
			refresh = base64.URLEncoding.EncodeToString([]byte(t))
			refresh = strings.ToUpper(strings.TrimRight(refresh, "="))
		}

		return access, refresh, nil
	}
}

func (a *JWTAccessGenerate) isEs() bool {
	return strings.HasPrefix(a.SignedMethod.Alg(), "ES")
}

func (a *JWTAccessGenerate) isRsOrPS() bool {
	isRs := strings.HasPrefix(a.SignedMethod.Alg(), "RS")
	isPs := strings.HasPrefix(a.SignedMethod.Alg(), "PS")
	return isRs || isPs
}

func (a *JWTAccessGenerate) isHs() bool {
	return strings.HasPrefix(a.SignedMethod.Alg(), "HS")
}
