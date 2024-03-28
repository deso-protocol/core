package lib

import "bytes"

// -------------------------------------------------------------------------------------
// DBEntry
// -------------------------------------------------------------------------------------

// DBEntry is used to represent a database record. It's more convenient than passing
// <key, value> everywhere.
type DBEntry struct {
	Key   []byte
	Value []byte
}

func NewDBEntry(key []byte, value []byte) *DBEntry {
	return &DBEntry{
		Key:   key,
		Value: value,
	}
}

func (entry *DBEntry) ToBytes() []byte {
	data := []byte{}

	data = append(data, EncodeByteArray(entry.Key)...)
	data = append(data, EncodeByteArray(entry.Value)...)
	return data
}

func (entry *DBEntry) FromBytes(rr *bytes.Reader) error {
	var err error

	// Decode key.
	entry.Key, err = DecodeByteArray(rr)
	if err != nil {
		return err
	}

	// Decode value.
	entry.Value, err = DecodeByteArray(rr)
	if err != nil {
		return err
	}

	return nil
}

// KeyValueToDBEntry is used to instantiate db entry from a <key, value> pair.
func KeyValueToDBEntry(key []byte, value []byte) *DBEntry {
	dbEntry := &DBEntry{}
	// Encode the key.
	dbEntry.Key = make([]byte, len(key))
	copy(dbEntry.Key, key)

	// Encode the value.
	dbEntry.Value = make([]byte, len(value))
	copy(dbEntry.Value, value)

	return dbEntry
}

// EmptyDBEntry indicates an empty DB entry. It's used for convenience.
func EmptyDBEntry() *DBEntry {
	// We do not use prefix 0 for state so we can use it in the empty DBEntry.
	return &DBEntry{
		Key:   []byte{0},
		Value: []byte{},
	}
}

// IsEmpty return true if the DBEntry is empty, false otherwise.
func (entry *DBEntry) IsEmpty() bool {
	return bytes.Equal(entry.Key, []byte{0})
}
