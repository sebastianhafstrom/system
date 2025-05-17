package user

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

var users = make(map[string]User)

func RegisterUser(username, password string, role Role) error {
	if _, exists := users[username]; exists {
		return errors.New("username already exists")
	}

	if !role.IsValid() {
		return errors.New("invalid role")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	users[username] = User{
		Username:     username,
		PasswordHash: string(hashedPassword),
		Role:         role,
	}
	return nil
}

func AuthenticateUser(username, password string) (*User, error) {
	user, exists := users[username]
	if !exists {
		return nil, errors.New("invalid username or password")
	}

	err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		return nil, errors.New("invalid username or password")
	}

	return &user, nil
}
