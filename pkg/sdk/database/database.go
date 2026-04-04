package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	sdkerrors "github.com/authplex/pkg/sdk/errors"
)

// Driver identifies the database backend.
type Driver string

const (
	Postgres  Driver = "postgres"
	SQLServer Driver = "sqlserver"
)

// DB is the port interface for database access. Infrastructure adapters
// for PostgreSQL and SQL Server implement this interface.
type DB interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error)
	PingContext(ctx context.Context) error
	Close() error
}

// ConnOption configures the database connection pool.
type ConnOption func(*connConfig)

type connConfig struct {
	maxOpenConns    int
	maxIdleConns    int
	connMaxLifetime time.Duration
	connMaxIdleTime time.Duration
}

func defaultConnConfig() connConfig {
	return connConfig{
		maxOpenConns:    25,
		maxIdleConns:    5,
		connMaxLifetime: 30 * time.Minute,
		connMaxIdleTime: 5 * time.Minute,
	}
}

// WithMaxOpenConns sets the maximum number of open connections.
func WithMaxOpenConns(n int) ConnOption {
	return func(cfg *connConfig) {
		cfg.maxOpenConns = n
	}
}

// WithMaxIdleConns sets the maximum number of idle connections.
func WithMaxIdleConns(n int) ConnOption {
	return func(cfg *connConfig) {
		cfg.maxIdleConns = n
	}
}

// WithConnMaxLifetime sets the maximum lifetime of a connection.
func WithConnMaxLifetime(d time.Duration) ConnOption {
	return func(cfg *connConfig) {
		cfg.connMaxLifetime = d
	}
}

// WithConnMaxIdleTime sets the maximum idle time for a connection.
func WithConnMaxIdleTime(d time.Duration) ConnOption {
	return func(cfg *connConfig) {
		cfg.connMaxIdleTime = d
	}
}

// NewConnection creates a database connection using the provided driver and DSN.
// Returns Result[*sql.DB] — never panics.
func NewConnection(ctx context.Context, driver Driver, dsn string, opts ...ConnOption) sdkerrors.Result[*sql.DB] {
	cfg := defaultConnConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	driverName, err := resolveDriverName(driver)
	if err != nil {
		return sdkerrors.Err[*sql.DB](err)
	}

	db, sqlErr := sql.Open(driverName, dsn)
	if sqlErr != nil {
		return sdkerrors.Err[*sql.DB](
			sdkerrors.Wrap(sdkerrors.ErrInternal, "failed to open database connection", sqlErr),
		)
	}

	db.SetMaxOpenConns(cfg.maxOpenConns)
	db.SetMaxIdleConns(cfg.maxIdleConns)
	db.SetConnMaxLifetime(cfg.connMaxLifetime)
	db.SetConnMaxIdleTime(cfg.connMaxIdleTime)

	if pingErr := db.PingContext(ctx); pingErr != nil {
		db.Close()
		return sdkerrors.Err[*sql.DB](
			sdkerrors.Wrap(sdkerrors.ErrInternal, "failed to ping database", pingErr),
		)
	}

	return sdkerrors.Ok(db)
}

func resolveDriverName(driver Driver) (string, *sdkerrors.AppError) {
	switch driver {
	case Postgres:
		return "pgx", nil
	case SQLServer:
		return "sqlserver", nil
	default:
		return "", sdkerrors.New(sdkerrors.ErrBadRequest,
			fmt.Sprintf("unsupported database driver: %s", driver))
	}
}

// Migrator runs schema migrations against the database.
type Migrator interface {
	Up(ctx context.Context) error
	Down(ctx context.Context) error
	Version(ctx context.Context) (int, error)
}
