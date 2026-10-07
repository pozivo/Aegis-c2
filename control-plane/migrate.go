package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
)

//go:embed migrations/001_initial.sql migrations/002_agent_heartbeat.sql
var migrationFiles embed.FS

const latestMigration = 2

var migrationNames = []string{"001_initial.sql", "002_agent_heartbeat.sql"}

func applyMigrations(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(475325)`); err != nil {
		return err
	}
	var trackingExists bool
	if err := tx.QueryRowContext(ctx, `SELECT to_regclass('public.schema_migrations') IS NOT NULL`).Scan(&trackingExists); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version integer PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	if len(migrationNames) != latestMigration {
		return fmt.Errorf("expected %d migrations, found %d", latestMigration, len(migrationNames))
	}
	// Earlier alpha releases applied SQL directly without a tracking table.
	if !trackingExists {
		var schemaExists, agentTableExists, heartbeatExists bool
		if err := tx.QueryRowContext(ctx, `SELECT
			to_regclass('public.engagements') IS NOT NULL,
			to_regclass('public.agents') IS NOT NULL,
			EXISTS (SELECT 1 FROM information_schema.columns
				WHERE table_schema = 'public' AND table_name = 'agents' AND column_name = 'heartbeat_token_digest')`).Scan(&schemaExists, &agentTableExists, &heartbeatExists); err != nil {
			return err
		}
		if schemaExists != agentTableExists || (heartbeatExists && !schemaExists) {
			return errors.New("partial legacy schema: manual recovery required")
		}
		baseline := 0
		if schemaExists {
			baseline = 1
		}
		if heartbeatExists {
			baseline = 2
		}
		for i := 0; i < baseline; i++ {
			checksum, err := migrationChecksum(migrationNames[i])
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, checksum) VALUES ($1, $2)`, i+1, checksum); err != nil {
				return err
			}
		}
	}
	for i, name := range migrationNames {
		version := i + 1
		content, err := migrationFiles.ReadFile("migrations/" + name)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(content)
		checksum := hex.EncodeToString(digest[:])
		var stored string
		err = tx.QueryRowContext(ctx, `SELECT checksum FROM schema_migrations WHERE version = $1`, version).Scan(&stored)
		if err == nil {
			if stored != checksum {
				return fmt.Errorf("migration %d checksum changed", version)
			}
			continue
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if _, err := tx.ExecContext(ctx, string(content)); err != nil {
			return fmt.Errorf("migration %d: %w", version, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, checksum) VALUES ($1, $2)`, version, checksum); err != nil {
			return err
		}
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&count); err != nil {
		return err
	}
	if count != latestMigration {
		return fmt.Errorf("unexpected migration count %d", count)
	}
	return tx.Commit()
}

func migrationChecksum(name string) (string, error) {
	content, err := migrationFiles.ReadFile("migrations/" + name)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:]), nil
}
