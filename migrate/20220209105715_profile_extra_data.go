package migrate

import (
	"github.com/go-pg/pg/v10/orm"
	migrations "github.com/robinjoseph08/go-pg-migrations/v3"
)

func init() {
	up := func(db orm.DB) error {

		_, err := db.Exec(`
			ALTER TABLE pg_profiles
				ADD COLUMN extra_data JSONB; 
			`)
		if err != nil {
			return err
		}

		return nil
	}

	down := func(db orm.DB) error {
		_, err := db.Exec(`
			ALTER TABLE pg_profiles
				DROP COLUMN extra_data;
		`)
		return err
	}

	opts := migrations.MigrationOptions{}

	migrations.Register("20220209105715_profile_extra_data", up, down, opts)
}
