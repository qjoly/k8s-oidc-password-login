package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/square/go-jose.v2"
)

const (
	// Must be set to the URL where this OIDC provider is hosted.
	// E.g., "https://oidc.example.com"
	// This URL is used in the discovery document and for redirect URIs.
	listenAddr        = ":8080"
	clientID          = "kubernetes"
	defaultExpiryTime = time.Hour * 1
)

var (
	users = map[string]string{
		"admin": hashPasword("toto"),
	}
	issuerURL = os.Getenv("OIDC_ISSUER_URL")

	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	jwks       jose.JSONWebKeySet
	keyID      = "je-suis-un-bon-key-id"
	mu         sync.Mutex
)

func hashPasword(password string) string {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		log.Fatalf("Error hashing password: %v", err)
	}
	return string(bytes)
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func generateKeys() {
	var err error
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Cannot generate RSA key: %s", err)
	}
	publicKey = &privateKey.PublicKey
	jwk := jose.JSONWebKey{
		Key:       publicKey,
		Algorithm: string(jose.RS256),
		Use:       "sig",
		KeyID:     keyID,
	}
	jwks = jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{jwk},
	}
}

func discoveryHandler(w http.ResponseWriter, r *http.Request) {
	config := map[string]interface{}{
		"issuer":                                issuerURL,
		"authorization_endpoint":                issuerURL + "/authorize",
		"token_endpoint":                        issuerURL + "/token",
		"jwks_uri":                              issuerURL + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code", "id_token", "token id_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "email", "profile", "groups"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic", "none"},
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "email", "name", "groups"},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

func authorizeHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method == http.MethodGet {
		loginPage := `
		<!DOCTYPE html>
		<html>
		<head><title>Login</title></head>
		<body>
			<h2>Login to OIDC Provider</h2>
			<form method="post">
				<input type="hidden" name="client_id" value="%s">
				<input type="hidden" name="redirect_uri" value="%s">
				<input type="hidden" name="response_type" value="%s">
				<input type="hidden" name="scope" value="%s">
				<input type="hidden" name="state" value="%s">
				<input type="hidden" name="nonce" value="%s">
				Username: <input type="text" name="username"><br>
				Password: <input type="password" name="password"><br>
				<input type="submit" value="Login">
			</form>
		</body>
		</html>
		`

		q := r.URL.Query()
		fmt.Fprintf(w, loginPage, q.Get("client_id"), q.Get("redirect_uri"), q.Get("response_type"), q.Get("scope"), q.Get("state"), q.Get("nonce"))
		return
	}

	if r.Method == http.MethodPost {
		r.ParseForm()
		username := r.FormValue("username")
		password := r.FormValue("password")

		mu.Lock()
		hashedPassword, ok := users[username]
		mu.Unlock()

		if !ok || !checkPasswordHash(password, hashedPassword) {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		fmt.Fprintf(w, `
		<!DOCTYPE html>
		<html>
		<head><title>OIDC Login Success</title></head>
		<body>
			<h2>OIDC Login Successful</h2>
			<p>You can now use the following command to configure kubectl:</p>
			<pre>
		kubectl oidc-login setup --oidc-issuer-url=%s --oidc-client-id=%s --grant-type=password --username=%s
			</pre>
		</body>
		</html>
		`, issuerURL, clientID, username)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func tokenHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse form: %v", err), http.StatusBadRequest)
		return
	}

	grantType := r.FormValue("grant_type")

	var username, sub string
	var userGroups []string

	switch grantType {
	case "password":
		formUser := r.FormValue("username")
		formPassword := r.FormValue("password")

		mu.Lock()
		hashedPassword, ok := users[formUser]
		mu.Unlock()

		if !ok || !checkPasswordHash(formPassword, hashedPassword) {
			log.Printf("Invalid credentials for user: %s", formUser)
			http.Error(w, `{"error": "invalid_grant", "error_description": "Invalid credentials"}`, http.StatusUnauthorized)
			return
		}
		username = formUser
		sub = formUser

		userGroups = []string{"developers", "admins"}

	default:
		log.Printf("Unsupported grant type: %s", grantType)
		http.Error(w, fmt.Sprintf(`{"error": "unsupported_grant_type", "error_description": "Unsupported grant type: %s"}`, grantType), http.StatusBadRequest)
		return
	}

	now := time.Now()
	idTokenClaims := jwt.MapClaims{
		"iss":    issuerURL,
		"sub":    sub,
		"aud":    clientID,
		"exp":    now.Add(defaultExpiryTime).Unix(),
		"iat":    now.Unix(),
		"name":   username,
		"email":  username + "@une-tasse-de.cafe",
		"groups": userGroups,
	}

	idToken := jwt.NewWithClaims(jwt.SigningMethodRS256, idTokenClaims)
	idToken.Header["kid"] = keyID
	signedIDToken, err := idToken.SignedString(privateKey)
	if err != nil {
		log.Printf("Error signing ID token: %v", err)
		http.Error(w, `{"error": "server_error", "error_description": "Failed to sign ID token"}`, http.StatusInternalServerError)
		return
	}

	accessToken := "dummy-access-token-" + fmt.Sprintf("%d", time.Now().UnixNano())

	refreshToken := "dummy-refresh-token-" + fmt.Sprintf("%d", time.Now().UnixNano())

	response := map[string]interface{}{
		"id_token":      signedIDToken,
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    int(defaultExpiryTime.Seconds()),
		"refresh_token": refreshToken,
		"scope":         r.FormValue("scope"),
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	json.NewEncoder(w).Encode(response)
	log.Printf("Issued tokens for user: %s, grant_type: %s", username, grantType)
}

func jwksHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}

func main() {

	generateKeys()
	log.Printf("Generated RSA key pair. Key ID: %s", keyID)

	http.HandleFunc("/.well-known/openid-configuration", discoveryHandler)
	http.HandleFunc("/.well-known/jwks.json", jwksHandler)
	http.HandleFunc("/authorize", authorizeHandler)
	http.HandleFunc("/token", tokenHandler)

	log.Printf("OIDC Provider starting on %s (issuer: %s)", listenAddr, issuerURL)
	log.Println("Let's give everyone a chance to login by bruteforcing your api-server")

	if err := http.ListenAndServe(listenAddr, nil); err != nil {
		log.Fatalf("ListenAndServe: %v", err)
	}
}
