package repository

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/vulture/backend/internal/model"
)

type UserRepository interface {
	CreateUser(user *model.User) error
	GetUser(id string) (*model.User, error)
	GetUserByEmail(email string) (*model.User, error)
	UpdateLastLogin(id string) error
	CreateTeam(name string) (*model.Team, error)
	GetTeam(id string) (*model.Team, error)
}

type PostgresUserRepo struct {
	db *sql.DB
}

func NewPostgresUserRepo(db *sql.DB) *PostgresUserRepo {
	return &PostgresUserRepo{db: db}
}

func (r *PostgresUserRepo) CreateUser(user *model.User) error {
	var id string
	err := r.db.QueryRow(
		`INSERT INTO users (email, password_hash, name, role, team_id, created_at) VALUES ($1, $2, $3, $4, NULLIF($5, '')::uuid, $6) RETURNING id`,
		user.Email, user.PasswordHash, user.Name, user.Role, user.TeamID, user.CreatedAt,
	).Scan(&id)
	if err != nil {
		return fmt.Errorf("insert user: %w", err)
	}
	user.ID = id
	return nil
}

func (r *PostgresUserRepo) GetUser(id string) (*model.User, error) {
	row := r.db.QueryRow(
		`SELECT id, email, password_hash, name, role, COALESCE(team_id::text, ''), created_at, last_login_at FROM users WHERE id = $1`, id,
	)
	return scanUser(row)
}

func (r *PostgresUserRepo) GetUserByEmail(email string) (*model.User, error) {
	row := r.db.QueryRow(
		`SELECT id, email, password_hash, name, role, COALESCE(team_id::text, ''), created_at, last_login_at FROM users WHERE email = $1`, email,
	)
	return scanUser(row)
}

func scanUser(row *sql.Row) (*model.User, error) {
	var u model.User
	var lastLogin sql.NullTime
	err := row.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Name, &u.Role, &u.TeamID, &u.CreatedAt, &lastLogin)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan user: %w", err)
	}
	if lastLogin.Valid {
		u.LastLoginAt = &lastLogin.Time
	}
	return &u, nil
}

func (r *PostgresUserRepo) UpdateLastLogin(id string) error {
	_, err := r.db.Exec(`UPDATE users SET last_login_at = $1 WHERE id = $2`, time.Now().UTC(), id)
	return err
}

func (r *PostgresUserRepo) CreateTeam(name string) (*model.Team, error) {
	var team model.Team
	err := r.db.QueryRow(
		`INSERT INTO teams (name, created_at) VALUES ($1, $2) RETURNING id, name, created_at`,
		name, time.Now().UTC(),
	).Scan(&team.ID, &team.Name, &team.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("insert team: %w", err)
	}
	return &team, nil
}

func (r *PostgresUserRepo) GetTeam(id string) (*model.Team, error) {
	var team model.Team
	err := r.db.QueryRow(
		`SELECT id, name, created_at FROM teams WHERE id = $1`, id,
	).Scan(&team.ID, &team.Name, &team.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan team: %w", err)
	}
	return &team, nil
}

// --- SQLite User Repository ---

type SQLiteUserRepo struct {
	db *sql.DB
}

func NewSQLiteUserRepo(db *sql.DB) *SQLiteUserRepo {
	return &SQLiteUserRepo{db: db}
}

func generateID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (r *SQLiteUserRepo) CreateUser(user *model.User) error {
	if user.ID == "" {
		user.ID = generateID()
	}
	_, err := r.db.Exec(
		`INSERT INTO users (id, email, password_hash, name, role, team_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		user.ID, user.Email, user.PasswordHash, user.Name, user.Role, user.TeamID, user.CreatedAt.Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("insert user: %w", err)
	}
	return nil
}

func (r *SQLiteUserRepo) GetUser(id string) (*model.User, error) {
	row := r.db.QueryRow(
		`SELECT id, email, password_hash, name, role, COALESCE(team_id, ''), created_at, last_login_at FROM users WHERE id = ?`, id,
	)
	return scanSQLiteUser(row)
}

func (r *SQLiteUserRepo) GetUserByEmail(email string) (*model.User, error) {
	row := r.db.QueryRow(
		`SELECT id, email, password_hash, name, role, COALESCE(team_id, ''), created_at, last_login_at FROM users WHERE email = ?`, email,
	)
	return scanSQLiteUser(row)
}

func scanSQLiteUser(row *sql.Row) (*model.User, error) {
	var u model.User
	var createdAt string
	var lastLogin sql.NullString
	err := row.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Name, &u.Role, &u.TeamID, &createdAt, &lastLogin)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan user: %w", err)
	}
	u.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	if lastLogin.Valid {
		t, _ := time.Parse(time.RFC3339, lastLogin.String)
		u.LastLoginAt = &t
	}
	return &u, nil
}

func (r *SQLiteUserRepo) UpdateLastLogin(id string) error {
	_, err := r.db.Exec(`UPDATE users SET last_login_at = ? WHERE id = ?`, time.Now().UTC().Format(time.RFC3339), id)
	return err
}

func (r *SQLiteUserRepo) CreateTeam(name string) (*model.Team, error) {
	team := model.Team{
		ID:        generateID(),
		Name:      name,
		CreatedAt: time.Now().UTC(),
	}
	_, err := r.db.Exec(
		`INSERT INTO teams (id, name, created_at) VALUES (?, ?, ?)`,
		team.ID, team.Name, team.CreatedAt.Format(time.RFC3339),
	)
	if err != nil {
		return nil, fmt.Errorf("insert team: %w", err)
	}
	return &team, nil
}

func (r *SQLiteUserRepo) GetTeam(id string) (*model.Team, error) {
	var team model.Team
	var createdAt string
	err := r.db.QueryRow(
		`SELECT id, name, created_at FROM teams WHERE id = ?`, id,
	).Scan(&team.ID, &team.Name, &createdAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan team: %w", err)
	}
	team.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	return &team, nil
}
