package domain

type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password,omitempty"` // nolint:gosec // G117: This is a user password field
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"` // nolint:gosec // G117: This is a user password field
}

type RegisterRequest struct {
	Username string `json:"username" binding:"required"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"` // nolint:gosec // G117: This is a user password field
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"` // nolint:gosec // G117: opaque refresh token, not a password
}

type AuthResponse struct {
	Token        string `json:"token"`
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	User         User   `json:"user"`
}
