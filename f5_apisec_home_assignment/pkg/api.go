package api_sec

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
)

var jwtKey = []byte("my_secret_key")

type Claims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	UserID   string `json:"userid"` // Added userID to associate token and ID
	jwt.StandardClaims
}

func Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Added validation on empty fields
	if user.Username == "" || user.Password == "" || user.Role == "" {
		http.Error(w, "Username, password and role cannot be empty", http.StatusBadRequest)
		return
	}

	// Added a check if password length is at least 8 characters
	if len(user.Password) < 8 {
		http.Error(w, "Password must be at least 8 characters long", http.StatusBadRequest)
		return
	}

	// Added a validation for role to be either "user" or "admin"
	if user.Role != "user" && user.Role != "admin" {
		http.Error(w, "Role must be either 'user' or 'admin'", http.StatusBadRequest)
		return
	}

	// Added a check to make usernames unique
	for _, u := range users {
		if u.Username == user.Username {
			http.Error(w, "Username already exists", http.StatusConflict)
			return
		}
	}

	newUUID := uuid.New().String() // Generate a new UUID
	user.ID = newUUID
	users = append(users, user)
	json.NewEncoder(w).Encode(user)
}

func Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var creds User
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Added validation on empty fields
	if creds.Username == "" || creds.Password == "" {
		http.Error(w, "Username and password cannot be empty", http.StatusBadRequest)
		return
	}

	// Authenticate user
	var authenticatedUser *User
	for _, user := range users {
		if user.Username == creds.Username && user.Password == creds.Password {
			authenticatedUser = &user
			break
		}
	}
	if authenticatedUser == nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	expirationTime := time.Now().Add(1 * time.Hour)
	claims := &Claims{
		Username: authenticatedUser.Username,
		Role:     authenticatedUser.Role,
		UserID:   authenticatedUser.ID, // Added UserID in claims
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

func AccountsHandler(w http.ResponseWriter, r *http.Request, claims *Claims) {
	// Added the admin role validation to the GET request also, it holds for both operations
	if claims.Role != "admin" {
		http.Error(w, "Unauthorized", http.StatusForbidden)
		return
	}
	if r.Method == http.MethodPost {
		createAccount(w, r, claims)
		return
	}
	if r.Method == http.MethodGet {
		listAccounts(w, r, claims)
		return
	}
}

func createAccount(w http.ResponseWriter, r *http.Request, claims *Claims) {
	var acc Account
	if err := json.NewDecoder(r.Body).Decode(&acc); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if acc.UserID == "" { // Added validatrion for empty field
		http.Error(w, "UserID cannot be empty", http.StatusBadRequest)
		return
	}

	for _, user := range users { // validate that a user with this userID exists
		if user.ID == acc.UserID {
			newUUID := uuid.New().String() // Generate a new UUID
			acc.ID = newUUID
			acc.CreatedAt = time.Now()
			accounts = append(accounts, acc)
			json.NewEncoder(w).Encode(acc)
			return
		}
	}

	http.Error(w, "No such User exists, please register", http.StatusBadRequest)
}

func listAccounts(w http.ResponseWriter, r *http.Request, claims *Claims) {
	json.NewEncoder(w).Encode(accounts)
}

func BalanceHandler(w http.ResponseWriter, r *http.Request, claims *Claims) {
	// Added a validation of a user
	if claims.Role != "user" {
		http.Error(w, "Unauthorized", http.StatusForbidden)
		return
	}

	switch r.Method {
	case http.MethodGet:
		userID := r.URL.Query().Get("user_id")
		if userID == "" {
			http.Error(w, "UserID cannot be empty", http.StatusBadRequest)
			return
		}
		getBalance(w, r, claims)
	case http.MethodPost:
		depositBalance(w, r, claims)
	case http.MethodDelete:
		withdrawBalance(w, r, claims)
	}
}

func getBalance(w http.ResponseWriter, r *http.Request, claims *Claims) {
	userId := r.URL.Query().Get("user_id")
	if userId != claims.UserID {
		http.Error(w, "Unauthorized: Token does not match userID", http.StatusUnauthorized)
		return
	}

	for _, acc := range accounts {
		if acc.UserID == userId {
			json.NewEncoder(w).Encode(map[string]float64{"balance": acc.Balance})
			return
		}
	}
	http.Error(w, "Account not found", http.StatusNotFound)
}

func depositBalance(w http.ResponseWriter, r *http.Request, claims *Claims) {
	var body struct {
		UserID string  `json:"user_id"`
		Amount float64 `json:"amount"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if body.Amount < 0 { // Added a validation of positive amount deposit
		http.Error(w, "Can't deposit negative amount", http.StatusBadRequest)
	}
	for i, acc := range accounts {
		if acc.UserID == body.UserID {
			accounts[i].Balance += body.Amount
			json.NewEncoder(w).Encode(accounts[i])
			return
		}
	}
	http.Error(w, "Account not found", http.StatusNotFound)
}

func withdrawBalance(w http.ResponseWriter, r *http.Request, claims *Claims) {
	var body struct {
		UserID string  `json:"user_id"`
		Amount float64 `json:"amount"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if body.Amount < 0 { // Added a validation of positive amount withdraw
		http.Error(w, "Can't withdraw negative amount", http.StatusBadRequest)
	}
	for i, acc := range accounts {
		if acc.UserID == body.UserID {
			if acc.Balance < body.Amount {
				http.Error(w, ErrInsufficientFunds.Error(), http.StatusBadRequest)
				return
			}
			accounts[i].Balance -= body.Amount
			json.NewEncoder(w).Encode(accounts[i])
			return
		}
	}
	http.Error(w, "Account not found", http.StatusNotFound)
}

func Auth(next func(http.ResponseWriter, *http.Request, *Claims)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenStr := r.Header.Get("Authorization")
		if tokenStr == "" {
			http.Error(w, "Missing token", http.StatusUnauthorized)
			return
		}
		tokenStr = strings.TrimPrefix(tokenStr, "Bearer ")
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if claims.Role != "admin" { // If not admin , need to check if the ID matches the token provided
			// Extract User ID based on method and endpoint
			var userID string
			if r.Method == "POST" || r.Method == "PUT" || r.Method == "DELETE" {
				var body struct {
					UserID string `json:"user_id"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					http.Error(w, "Error decoding request body", http.StatusBadRequest)
					return
				}
				userID = body.UserID
				// Validate the extracted user ID against the one in the token
				if claims.UserID != userID {
					http.Error(w, "Unauthorized: Token does not match userID", http.StatusUnauthorized)
					return
				}
			}
		}

		next(w, r, claims)
	}
}

// Logger that logs the request and response details
func Logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Capture the response details by wrapping the ResponseWriter
		lrw := &loggedResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		// Before passing to the next handler
		next.ServeHTTP(lrw, r)

		// After handling the request, create the log entry
		logEntry := map[string]interface{}{
			"req": map[string]interface{}{
				"url":          r.URL.Path,
				"qs_params":    r.URL.Query(),
				"headers":      r.Header,
				"req_body_len": r.ContentLength,
			},
			"rsp": map[string]interface{}{
				"status_class": getStatusClass(lrw.statusCode),
				"rsp_body_len": lrw.responseLength,
			},
		}

		// Convert log entry to JSON
		logData, err := json.Marshal(logEntry)
		if err != nil {
			log.Printf("Error marshaling log data: %v", err)
			return
		}

		// Append log entry to a file
		logToFile(string(logData))
	})
}

// loggedResponseWriter is a custom http.ResponseWriter to capture response details
type loggedResponseWriter struct {
	http.ResponseWriter
	statusCode     int
	responseLength int64
}

// WriteHeader captures the status code
func (lrw *loggedResponseWriter) WriteHeader(statusCode int) {
	lrw.statusCode = statusCode
	lrw.ResponseWriter.WriteHeader(statusCode)
}

// Write captures the response length
func (lrw *loggedResponseWriter) Write(b []byte) (int, error) {
	size, err := lrw.ResponseWriter.Write(b)
	lrw.responseLength += int64(size)
	return size, err
}

// getStatusClass categorizes the status code
func getStatusClass(statusCode int) string {
	return fmt.Sprintf("%dxx", statusCode/100)
}

// logToFile appends log data to a file
func logToFile(data string) {
	file, err := os.OpenFile("access_log.json", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	defer file.Close()

	if _, err := file.WriteString(data + "\n"); err != nil {
		log.Fatalf("Failed to write to log file: %v", err)
	}
}
