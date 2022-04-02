package lib

import (
	"github.com/deso-protocol/go-deadlock"
	"github.com/dgraph-io/badger/v3"
)

type encoderPrefixProgress struct {
	prefix  []byte
	lastKey []byte

	encoder   DeSoEncoder
	completed bool
}

type encoderMigrationProgress struct {
	outstandingPrefixes []*encoderPrefixProgress
	completed           bool

	blockHeight uint64
}

type EncoderMigration struct {
	migrationProgress []*encoderMigrationProgress

	db        *badger.DB
	chainLock *deadlock.RWMutex
}

// MigrationMap describes the migrations. To define one, simply put a kv pair in the map with a
// strictly increasing version byte key and corresponding blockHeight uint64 value.
var MigrationMap = map[byte]uint64{}

func VersionByteToMigrationHeight(version byte) (_blockHeight uint64) {
	if blockHeight, exists := MigrationMap[version]; exists {
		return blockHeight
	}
	return 0
}

func (migration *EncoderMigration) Initialize(db *badger.DB, chainLock *deadlock.RWMutex) {
	migration.db = db
	migration.chainLock = chainLock

	// Check for state db prefixes that use a DeSoEncoder, because they are candidates for a migration.
	// Add a placeholder encoderPrefixProgress entry to the outstandingPrefixes array.
	//for prefixByte, isState := range StatePrefixes.StatePrefixesMap {
	//	if isState {
	//		prefix := []byte{prefixByte}
	//		if isEncoder, encoder := StatePrefixToDeSoEncoder(prefix); isEncoder && encoder != nil {
	//			migration.outstandingPrefixes = append(migration.outstandingPrefixes, &encoderPrefixProgress{
	//				prefix:    prefix,
	//				lastKey:   prefix,
	//				encoder:   encoder,
	//				completed: false,
	//			})
	//		}
	//	}
	//}
}

func (migration *EncoderMigration) ProcessMigration(blockTipHeight uint64) {

}
