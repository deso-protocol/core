package lib

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestNewPostgresFromURI(t *testing.T) {
	require := require.New(t)
	_ = require

	// No password.
	pgURI := "postgresql://testUser@localhost:5432/testDatabase"
	pgOptions := ParsePostgresURI(pgURI)
	require.Equal(pgOptions.Addr, "localhost:5432")
	require.Equal(pgOptions.User, "testUser")
	require.Equal(pgOptions.Database, "testDatabase")
	require.Equal(pgOptions.Password, "")

	// With password.
	pgURI = "postgresql://testUser:testPassword@postgres:5432/testDatabase"
	pgOptions = ParsePostgresURI(pgURI)
	require.Equal(pgOptions.Addr, "postgres:5432")
	require.Equal(pgOptions.User, "testUser")
	require.Equal(pgOptions.Database, "testDatabase")
	require.Equal(pgOptions.Password, "testPassword")
}
