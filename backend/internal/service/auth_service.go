package service

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/vulture/backend/internal/model"
	"github.com/vulture/backend/internal/repository"

	"golang.org/x/crypto/bcrypt"
)

type AuthService interface {
	Register(req *model.RegisterRequest) (*model.AuthResponse, error)
	Login(req *model.LoginRequest) (*model.AuthResponse, error)
	ValidateToken(token string) (*model.User, error)
	ValidateLocalUser() (*model.User, error)
	// IssueLocalAdminToken returns a JWT for the seeded local admin
	// without checking a password. Caller is responsible for gating
	// this on VULTURE_LOCAL_MODE=true — exposing it without that gate
	// is an immediate admin compromise. Eliminates the need for any
	// component to know the (now CSPRNG-generated) dev password.
	IssueLocalAdminToken() (*model.AuthResponse, error)
}

type authService struct {
	repo   repository.UserRepository
	secret []byte
}

func NewAuthService(repo repository.UserRepository, jwtSecret string) AuthService {
	return &authService{
		repo:   repo,
		secret: []byte(jwtSecret),
	}
}

func (s *authService) Register(req *model.RegisterRequest) (*model.AuthResponse, error) {
	existing, _ := s.repo.GetUserByEmail(req.Email)
	if existing != nil {
		return nil, fmt.Errorf("email already registered")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	var teamID string
	if req.TeamName != "" {
		team, err := s.repo.CreateTeam(req.TeamName)
		if err != nil {
			return nil, fmt.Errorf("create team: %w", err)
		}
		teamID = team.ID
	}

	user := &model.User{
		Email:        req.Email,
		PasswordHash: string(hash),
		Name:         req.Name,
		Role:         "member",
		TeamID:       teamID,
		CreatedAt:    time.Now().UTC(),
	}

	if err := s.repo.CreateUser(user); err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}

	token, err := s.generateToken(user)
	if err != nil {
		return nil, err
	}

	return &model.AuthResponse{Token: token, User: *user}, nil
}

func (s *authService) Login(req *model.LoginRequest) (*model.AuthResponse, error) {
	user, err := s.repo.GetUserByEmail(req.Email)
	if err != nil || user == nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	now := time.Now().UTC()
	user.LastLoginAt = &now
	_ = s.repo.UpdateLastLogin(user.ID)

	token, err := s.generateToken(user)
	if err != nil {
		return nil, err
	}

	return &model.AuthResponse{Token: token, User: *user}, nil
}

func (s *authService) ValidateToken(token string) (*model.User, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	// Verify signature (constant-time comparison to prevent timing oracle)
	sigInput := parts[0] + "." + parts[1]
	expectedSig := s.sign(sigInput)
	if !hmac.Equal([]byte(parts[2]), []byte(expectedSig)) {
		return nil, fmt.Errorf("invalid token signature")
	}

	// Decode payload
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}

	var claims struct {
		UserID string `json:"sub"`
		Email  string `json:"email"`
		Role   string `json:"role"`
		TeamID string `json:"team_id"`
		Exp    int64  `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal claims: %w", err)
	}

	if time.Now().Unix() > claims.Exp {
		return nil, fmt.Errorf("token expired")
	}

	user, err := s.repo.GetUser(claims.UserID)
	if err != nil || user == nil {
		return nil, fmt.Errorf("user not found")
	}

	return user, nil
}

func (s *authService) ValidateLocalUser() (*model.User, error) {
	user, err := s.repo.GetUserByEmail("admin@vulture.local")
	if err != nil || user == nil {
		return nil, fmt.Errorf("local user not found")
	}
	return user, nil
}

func (s *authService) IssueLocalAdminToken() (*model.AuthResponse, error) {
	user, err := s.ValidateLocalUser()
	if err != nil {
		return nil, err
	}
	token, err := s.generateToken(user)
	if err != nil {
		return nil, fmt.Errorf("generate token: %w", err)
	}
	return &model.AuthResponse{Token: token, User: *user}, nil
}

func (s *authService) generateToken(user *model.User) (string, error) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))

	claims := map[string]interface{}{
		"sub":     user.ID,
		"email":   user.Email,
		"role":    user.Role,
		"team_id": user.TeamID,
		"iat":     time.Now().Unix(),
		"exp":     time.Now().Add(24 * time.Hour).Unix(),
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)

	sigInput := header + "." + payload
	signature := s.sign(sigInput)

	return sigInput + "." + signature, nil
}

func (s *authService) sign(input string) string {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(input))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
