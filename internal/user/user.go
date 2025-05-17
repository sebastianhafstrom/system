package user

type User struct {
	ID           int
	Username     string
	PasswordHash string
	Role         Role
}
