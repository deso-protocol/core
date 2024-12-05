package lib

import (
	"fmt"
	"github.com/deso-protocol/core/migrate"
	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/go-pg/pg/v10"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	migrations "github.com/robinjoseph08/go-pg-migrations/v3"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestParsePostgresURI(t *testing.T) {
	t.Parallel()
	require := require.New(t)

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

func TestEmbedPg(t *testing.T) {
	t.Parallel()
	require := require.New(t)
	return

	_, embpg, err := StartTestEmbeddedPostgresDB("", 5433)
	require.NoError(err)
	fmt.Println("Started embedded postgres")
	defer require.NoError(StopTestEmbeddedPostgresDB(embpg))
}

// Use this utility function to start a test DB at the beginning of your test.
// Don't forget to queue a call to StopTestEmbeddedPostgresDB after you do this.
func StartTestEmbeddedPostgresDB(dataPath string, port uint32) (
	*Postgres, *embeddedpostgres.EmbeddedPostgres, error) {

	glog.Infof("StartTestEmbeddedPostgresDB: Starting embedded postgres")
	viper.SetConfigFile("../.env")
	viper.ReadInConfig()
	viper.Set("ENV", "TEST")
	viper.AutomaticEnv()

	var embeddedPostgres *embeddedpostgres.EmbeddedPostgres
	if viper.GetUint32("EMBEDDED_PG_PORT") > 0 {
		port = viper.GetUint32("EMBEDDED_PG_PORT")
	}

	// If we are in a local environment, start up embedded postgres.
	if !viper.GetBool("BUILDKITE_ENV") {
		embeddedPostgres = embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
			Port(port).
			// Setting a DataPath will make it use the same DB every time.
			DataPath(dataPath).
			// Setting a BinariesPath makes the tests run faster because otherwise it will
			// re-download the binaries every time.
			BinariesPath("/tmp/pg_bin").
			Version(embeddedpostgres.V14).
			Logger(nil))
		err := embeddedPostgres.Start()
		if err != nil {
			return nil, nil, errors.Wrapf(err, "StartTestEmbeddedPostgresDB: Problem starting embedded postgres")
		}
	} else {
		embeddedPostgres = nil
	}

	// Open a PostgreSQL database.
	dsn := viper.GetString("TEST_PG_URI")
	if dsn == "" {
		dsn = "postgresql://postgres:postgres@localhost:" + fmt.Sprint(port) + "/postgres?sslmode=disable"
	}
	db := pg.Connect(ParsePostgresURI(dsn))
	postgresDb := NewPostgres(db)

	migrate.LoadMigrations()
	if err := migrations.Run(db, "migrate", []string{"", "migrate"}); err != nil {
		return nil, nil, errors.Wrapf(err, "StartTestEmbeddedPostgresDB: Problem running migrations")
	}
	return postgresDb, embeddedPostgres, nil
}

func StopTestEmbeddedPostgresDB(epg *embeddedpostgres.EmbeddedPostgres) error {

	glog.Infof("StopTestEmbeddedPostgresDB: Stopping embedded postgres")
	if !viper.GetBool("BUILDKITE_ENV") {
		if err := epg.Stop(); err != nil {
			return errors.Wrapf(err, "StopTestEmbeddedPostgresDB: Problem stopping embedded postgres")
		}
	}
	return nil
}

func ResetPostgres(postgres *Postgres) error {
	migrate.LoadMigrations()
	if err := migrations.Run(postgres.db, "migrate", []string{"", "rollback"}); err != nil {
		return errors.Wrapf(err, "StopTestEmbeddedPostgresDB: Problem running rollback")
	}
	if err := migrations.Run(postgres.db, "migrate", []string{"", "migrate"}); err != nil {
		return errors.Wrapf(err, "StopTestEmbeddedPostgresDB: Problem running migrations")
	}
	return nil
}
