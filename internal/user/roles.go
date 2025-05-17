package user

type Role string

const (
	RoleAdmin   Role = "admin"
	RoleManager Role = "manager"
	RoleUser    Role = "user"
)

// IsValid checks if the role is a valid UserRole
func (r Role) IsValid() bool {
	switch r {
	case RoleAdmin, RoleManager, RoleUser:
		return true
	default:
		return false
	}
}
