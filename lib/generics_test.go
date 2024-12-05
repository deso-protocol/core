package lib

import (
	"bytes"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSet(t *testing.T) {
	t.Parallel()
	// Set of strings
	set := NewSet([]string{"a", "b", "c"})
	require.Equal(t, set.Size(), 3)
	require.True(t, set.Includes("c"))
	set.Add("d")
	require.Equal(t, set.Size(), 4)
	set.Remove("c")
	require.Equal(t, set.Size(), 3)
	require.False(t, set.Includes("c"))
	toSlice := set.ToSlice()
	require.Contains(t, toSlice, "a")
	require.Contains(t, toSlice, "b")
	require.Contains(t, toSlice, "d")
	set.Add("e")
	require.Equal(t, set.Size(), 4)
	mappedSet, err := MapSet(set, func(elem string) (string, error) {
		return elem + "!", nil
	})
	require.NoError(t, err)
	require.Contains(t, mappedSet, "a!")
	require.Contains(t, mappedSet, "b!")
	require.Contains(t, mappedSet, "d!")
	counter := 0
	nilSet, err := MapSet(set, func(elem string) (string, error) {
		if counter == 1 {
			return "", errors.New("TESTERROR")
		}
		counter++
		return elem, nil
	})
	require.Error(t, err)
	require.Equal(t, err.Error(), "TESTERROR")
	require.Nil(t, nilSet)
}

func TestGenericDeSoEncoderAndDecode(t *testing.T) {
	t.Parallel()

	tne := &TransactorNonceEntry{
		TransactorPKID: &PKID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
		Nonce: &DeSoNonce{
			ExpirationBlockHeight: 1723,
			PartialID:             142,
		},
	}
	encoded := EncodeToBytes(0, tne, false)
	var decoded *TransactorNonceEntry
	var err error
	decoded, err = DecodeDeSoEncoder(&TransactorNonceEntry{}, bytes.NewReader(encoded))

	require.NoError(t, err)
	require.True(t, decoded.TransactorPKID.Eq(tne.TransactorPKID))
	require.Equal(t, decoded.Nonce.ExpirationBlockHeight, tne.Nonce.ExpirationBlockHeight)
	require.Equal(t, decoded.Nonce.PartialID, tne.Nonce.PartialID)

	tneSlice := []*TransactorNonceEntry{tne}
	for i := 0; i < 10; i++ {
		copiedTNE := tne.Copy()
		copiedTNE.Nonce.ExpirationBlockHeight += 10
		copiedTNE.Nonce.PartialID += 10
		tneSlice = append(tneSlice, tne)
	}

	encodedSlice := EncodeDeSoEncoderSlice[*TransactorNonceEntry](tneSlice, 0, false)
	decodedSlice, err := DecodeDeSoEncoderSlice[*TransactorNonceEntry](bytes.NewReader(encodedSlice))

	require.NoError(t, err)
	require.Equal(t, len(decodedSlice), len(tneSlice))
	for i := 0; i < len(decodedSlice); i++ {
		require.True(t, decodedSlice[i].TransactorPKID.Eq(tneSlice[i].TransactorPKID))
		require.Equal(t, decodedSlice[i].Nonce.ExpirationBlockHeight, tneSlice[i].Nonce.ExpirationBlockHeight)
		require.Equal(t, decodedSlice[i].Nonce.PartialID, tneSlice[i].Nonce.PartialID)
	}
}
