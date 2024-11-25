package api_sec

import (
	"errors"
	"time"
)

type User struct {
	ID       string
	Username string
	Password string
	Role     string // "admin" or "user"
}

type Account struct {
	ID        string
	UserID    string
	Balance   float64
	CreatedAt time.Time
}

var users []User
var accounts []Account

var (
	ErrUserNotFound      = errors.New("user not found")
	ErrAccountNotFound   = errors.New("account not found")
	ErrInsufficientFunds = errors.New("insufficient funds")
)
