package lib

import (
	"fmt"
	"reflect"
	"testing"
)

func TestMigrationHeights(t *testing.T) {
	fmt.Println("Checking mainnet migration heights")
	_verifyEncoderMigrationHeights(t, GetEncoderMigrationHeights(&MainnetForkHeights))
	fmt.Println("Checking testnet migration heights")
	_verifyEncoderMigrationHeights(t, GetEncoderMigrationHeights(&TestnetForkHeights))
}

func _verifyEncoderMigrationHeights(t *testing.T, migrationHeights *EncoderMigrationHeights) {
	var migrationArray []*MigrationHeight
	elements := reflect.ValueOf(migrationHeights).Elem()
	structFields := elements.Type()
	for ii := 0; ii < structFields.NumField(); ii++ {
		elementField := elements.Field(ii)
		mig := elementField.Interface().(MigrationHeight)
		migCopy := mig
		migrationArray = append(migrationArray, &migCopy)
	}

	// Make sure that blockHeights are non-decreasing when ordered by version.
	previousHeight := uint64(0)
	for version := byte(0); version < byte(len(migrationArray)); version++ {
		found := false
		ii := 0
		for ; ii < len(migrationArray); ii++ {
			if migrationArray[ii].Version == version {
				if !found {
					found = true
					if migrationArray[ii].Height < previousHeight {
						t.Fatalf("Migration block heights don't form a non-decreasing sequence when ordered by version.")
					}
					previousHeight = migrationArray[ii].Height
				} else {
					t.Fatalf("Overlap in migrationArray versions, seems like EncoderMigrationHeights schema is invalid.")
				}
			}
		}
		if !found {
			t.Fatalf("Migration version not found. Versions should be increasing by +1 starting from 0.")
		}
	}
}
