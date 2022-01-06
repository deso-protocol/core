package desohash

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strconv"
	"testing"
	"time"
)

type output struct {
	V0 [32]byte
	V1 [32]byte
}

type testVector struct {
	input    []byte
	expected output
}

var (
	empty = testVector{
		input: []byte{},
		expected: output{
			V0: [32]byte{114, 23, 202, 186, 96, 139, 52, 36, 242, 19, 30, 176, 125, 131, 78, 220, 163, 169, 29, 234, 101, 225, 173, 227, 218, 14, 111, 145, 145, 42, 12, 224},
			V1: [32]byte{206, 229, 20, 193, 88, 210, 180, 26, 86, 122, 78, 46, 187, 40, 195, 65, 42, 27, 24, 130, 105, 217, 202, 144, 145, 53, 166, 51, 23, 42, 68, 67},
		},
	}

	zeroHeaderV0 = testVector{
		input: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		expected: output{
			V0: [32]byte{163, 26, 132, 217, 121, 192, 98, 38, 25, 124, 55, 0, 118, 142, 73, 208, 127, 207, 123, 226, 205, 66, 183, 103, 54, 32, 115, 162, 37, 41, 100, 168},
			V1: [32]byte{220, 154, 17, 120, 104, 154, 164, 84, 48, 65, 141, 33, 70, 75, 247, 102, 147, 110, 103, 251, 75, 96, 75, 52, 186, 204, 52, 205, 95, 25, 91, 71},
		},
	}

	maxHeaderV0 = testVector{
		input: []byte{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255},
		expected: output{
			V0: [32]byte{224, 40, 180, 163, 199, 90, 133, 139, 57, 187, 38, 22, 99, 131, 161, 190, 129, 114, 237, 219, 32, 136, 135, 104, 223, 246, 90, 51, 15, 207, 210, 240},
			V1: [32]byte{208, 117, 164, 127, 17, 189, 225, 172, 116, 108, 103, 77, 3, 164, 73, 168, 147, 187, 128, 62, 123, 86, 36, 156, 112, 70, 92, 130, 39, 253, 90, 109},
		},
	}

	genesisHeaderV0 = testVector{
		input: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 75, 113, 209, 3, 221, 111, 255, 27, 214, 17, 11, 200, 237, 10, 47, 49, 24, 187, 226, 154, 103, 228, 92, 108, 125, 151, 84, 106, 209, 38, 144, 111, 192, 31, 5, 96, 0, 0, 0, 0, 0, 0, 0, 0},
		expected: output{
			V0: [32]byte{85, 103, 196, 91, 123, 131, 182, 4, 249, 255, 92, 181, 232, 141, 252, 154, 215, 213, 161, 221, 88, 24, 221, 25, 230, 208, 36, 102, 244, 124, 189, 98},
			V1: [32]byte{91, 127, 218, 187, 252, 235, 213, 244, 72, 16, 177, 30, 58, 33, 141, 12, 52, 228, 126, 215, 95, 102, 156, 107, 170, 24, 68, 75, 67, 56, 206, 188},
		},
	}

	zeroHeaderV1 = testVector{
		input: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		expected: output{
			V0: [32]byte{208, 249, 212, 35, 44, 185, 9, 71, 200, 202, 67, 203, 45, 160, 126, 226, 237, 32, 73, 189, 236, 28, 23, 150, 116, 171, 215, 253, 178, 65, 62, 219},
			V1: [32]byte{246, 215, 207, 120, 242, 33, 199, 221, 121, 141, 54, 155, 96, 107, 190, 93, 59, 171, 22, 121, 187, 92, 0, 128, 78, 135, 219, 51, 38, 205, 92, 91},
		},
	}

	maxHeaderV1 = testVector{
		input: []byte{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255},
		expected: output{
			V0: [32]byte{2, 7, 246, 17, 87, 211, 208, 147, 234, 79, 179, 55, 226, 109, 21, 2, 190, 20, 71, 52, 240, 136, 41, 100, 65, 159, 37, 242, 20, 47, 157, 143},
			V1: [32]byte{45, 146, 175, 74, 163, 141, 154, 116, 242, 153, 16, 47, 67, 23, 225, 207, 25, 229, 2, 133, 182, 130, 179, 128, 74, 159, 25, 219, 79, 6, 252, 75},
		},
	}
)

var testVectors = []testVector{empty, zeroHeaderV0, maxHeaderV0, genesisHeaderV0, zeroHeaderV1, maxHeaderV1}

func TestDeSoHashV1Distribution(t *testing.T) {
	const iterations = 1e5

	r := rand.New(rand.NewSource(time.Now().Unix()))

	bytes := [32]uint64{}

	for i := uint64(0); i < iterations; i++ {
		hash := DeSoHashV1([]byte(fmt.Sprintf("%b", r.Uint64())))

		for j, b := range hash {
			bytes[j] += uint64(b)
		}
	}

	for i, b := range bytes {
		bytes[i] = b / iterations
	}

	for _, b := range bytes {
		spread := int(b) - 127
		if spread > 1 || spread < -1 {
			t.Fatalf("TestDeSoHashV1Distribution: Non-random distribution! - %v", bytes)
		}
	}
}

func TestDeSoHashV1(t *testing.T) {
	for _, vec := range testVectors {
		hash := DeSoHashV1(vec.input)

		if bytes.Compare(vec.expected.V1[:], hash[:]) != 0 {
			t.Errorf("TestDeSoHashV1: Mismatched hash value! Input: %v, Hash: %v, Expected: %v", hex.EncodeToString(vec.input), hex.EncodeToString(hash[:]), hex.EncodeToString(vec.expected.V1[:]))
			t.Errorf("TestDeSoHashV1: Mismatched hash value! Input: %v, Hash: %v, Expected: %v", hex.EncodeToString(vec.input), (hash[:]), (vec.expected.V1[:]))
		}
	}
}

func TestDeSoHashV0(t *testing.T) {
	for _, vec := range testVectors {
		hash := DeSoHashV0(vec.input)

		if bytes.Compare(vec.expected.V0[:], hash[:]) != 0 {
			t.Errorf("TestDeSoHashV0: Mismatched hash value! Input: %v, Hash: %v, Expected: %v", hex.EncodeToString(vec.input), hex.EncodeToString(hash[:]), hex.EncodeToString(vec.expected.V0[:]))
			t.Errorf("TestDeSoHashV0: Mismatched hash value! Input: %v, Hash: %v, Expected: %v", hex.EncodeToString(vec.input), (hash[:]), (vec.expected.V0[:]))
		}
	}
}

func BenchmarkDeSoHashV0(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = DeSoHashV0([]byte(strconv.FormatInt(int64(i), 10)))
	}
}

func BenchmarkDeSoHashV1(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = DeSoHashV1([]byte(strconv.FormatInt(int64(i), 10)))
	}
}
