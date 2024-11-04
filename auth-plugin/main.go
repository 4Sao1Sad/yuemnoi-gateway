package main

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/Kong/go-pdk"
	"github.com/Kong/go-pdk/server"
	"github.com/golang-jwt/jwt/v5"
)

const Version = "0.1"

const Priority = 1

func main() {
	server.StartServer(New, Version, Priority)
}

func New() interface{} {
	return &Config{}
}

type AuthTokenClaim struct {
	UserID int `json:"user_id"`
	jwt.RegisteredClaims
}

type Config struct {
	Endpoint       string
	CookieNameAuth string
	Secret         string
}

func (conf *Config) Access(kong *pdk.PDK) {
	cookieHeader, _ := kong.Request.GetHeader("cookie")
	cookies := getCookies(cookieHeader)

	token, err := jwt.ParseWithClaims(cookies[conf.CookieNameAuth], &AuthTokenClaim{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		secretKey := []byte(conf.Secret)
		return secretKey, nil
	})

	if err != nil {
		kong.Response.Exit(http.StatusUnauthorized, []byte(fmt.Sprintln(err)), nil)
		return
	}

	if claims, ok := token.Claims.(*AuthTokenClaim); ok && token.Valid {
		kong.ServiceRequest.SetHeader("X-User-Id", strconv.Itoa(claims.UserID))
	} else {
		kong.Response.Exit(http.StatusUnauthorized, []byte(fmt.Sprintln(err)), nil)
		return
	}

}

func getCookies(cookieHeaderValue string) map[string]string {
	if cookieHeaderValue == "" {
		return map[string]string{}
	}

	header := http.Header{}
	header.Add("Cookie", cookieHeaderValue)
	request := http.Request{Header: header}
	rs := map[string]string{}
	for _, c := range request.Cookies() {
		rs[c.Name] = c.Value
	}
	return rs
}
