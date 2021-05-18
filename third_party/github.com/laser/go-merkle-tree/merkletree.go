package merkletree

import (
	"bytes"
	"errors"
	"fmt"
	"math"
)

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// TYPES
////////

type Tree struct {
	Root     Node
	Rows     [][]Node
	HashFunc func(isLeaf bool, block []byte) []byte
}

type Node interface {
	GetHash() []byte
	ToString(HashToStrFunc, int) string
}

type Branch struct {
	Hash  []byte
	Left  Node
	Right Node
}

type Leaf struct {
	Hash []byte
	Data []byte
}

type ProofPart struct {
	IsRight bool
	Hash    []byte
}

const (
	ProofPartSerializeSize = 1 + 32
)

func (pf *ProofPart) Serialize() ([]byte, error) {
	data := []byte{}

	if pf.IsRight {
		data = append(data, 1)
	} else {
		data = append(data, 0)
	}

	if len(pf.Hash) != 32 {
		return nil, fmt.Errorf(
			"ProofPart.Serailize: Hash size %d should equal %d", pf.Hash, 32)
	}
	data = append(data, pf.Hash...)

	return data, nil
}

func (pf *ProofPart) Deserialize(data []byte) error {
	if len(data) != ProofPartSerializeSize {
		return fmt.Errorf(
			"ProofPart.Deserialize: data length %d should equal %d",
			len(data), ProofPartSerializeSize)
	}

	if data[0] == 0 {
		pf.IsRight = false
	} else {
		pf.IsRight = true
	}

	pf.Hash = data[1:]

	return nil
}

type Proof struct {
	HashFunc func(isLeaf bool, xs []byte) []byte
	// PathToRoot is a path from the LeafHash up to the root of the Merkle
	// tree. Note that the LeafHash and the Root hash are not included in
	// the this list. Rather, the list is everything in between these two
	// items. To put it visually, below is how to think about a Merkle proof
	// as it is described by this library:
	//
	//             RootHash
	//            /        \
	//        ... PathToRoot ...
	//          /            \
	//         ... LeafHash ...
	//
	PathToRoot []*ProofPart
	// LeafHash is the hash of an element at the lowest level of
	// the Merkle tree. It is the hash of the element we want to
	// prove actually exists in the tree.
	LeafHash []byte
}

type HashToStrFunc func([]byte) string

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// CONSTRUCTORS
///////////////

func NewLeafFromHash(hash []byte) *Leaf {
	return &Leaf{
		Hash: hash,
		Data: nil,
	}
}

func NewLeaf(sumFunc func(bool, []byte) []byte, block []byte) *Leaf {
	return &Leaf{
		Hash: sumFunc(true, block),
		Data: block,
	}
}

func NewBranch(sumFunc func(bool, []byte) []byte, left Node, right Node) *Branch {
	return &Branch{
		Hash:  sumFunc(false, append(left.GetHash(), right.GetHash()...)),
		Left:  left,
		Right: right,
	}
}

func NewTreeFromHashes(providedSumFunc func([]byte) []byte, hashes [][]byte) *Tree {
	levels := int(math.Ceil(math.Log2(float64(len(hashes)+len(hashes)%2))) + 1)

	sumFunc := func(isLeaf bool, xs []byte) []byte {
		return providedSumFunc(xs)
	}

	// represents each row in the tree, where rows[0] is the base and rows[len(rows)-1] is the root
	rows := make([][]Node, levels)

	// build our base of leaves
	for i := 0; i < len(hashes); i++ {
		rows[0] = append(rows[0], NewLeafFromHash(hashes[i]))
	}

	// build upwards until we hit the root
	for i := 1; i < levels; i++ {
		prev := rows[i-1]

		// each iteration creates a branch from a pair of values originating from the previous level
		for j := 0; j < len(prev); j = j + 2 {
			var l, r Node

			// if we don't have enough to make a pair, duplicate the left
			if j+1 >= len(prev) {
				l = prev[j]
				r = l
			} else {
				l = prev[j]
				r = prev[j+1]
			}

			b := NewBranch(sumFunc, l, r)

			rows[i] = append(rows[i], b)
		}
	}

	return &Tree{
		HashFunc: sumFunc,
		Rows:     rows,
		Root:     rows[len(rows)-1][0],
	}
}

func NewTree(providedSumFunc func([]byte) []byte, blocks [][]byte) *Tree {
	levels := int(math.Ceil(math.Log2(float64(len(blocks)+len(blocks)%2))) + 1)

	// Note: The below code has been commented out and replaced because it causes
	// the library to be incompatible with Bitcoin. This code is intended to make
	// the library more resistant to pre-image attacks, but this is a very minor
	// concern that Bitcoin doesn't worry about.
	/*
		sumFunc := func(isLeaf bool, xs []byte) []byte {
			if isLeaf {
				return providedSumFunc(append([]byte{0x00}, xs...))
			}

			return providedSumFunc(append([]byte{0x01}, xs...))
		}
	*/
	sumFunc := func(isLeaf bool, xs []byte) []byte {
		return providedSumFunc(xs)
	}

	// represents each row in the tree, where rows[0] is the base and rows[len(rows)-1] is the root
	rows := make([][]Node, levels)

	// build our base of leaves
	for i := 0; i < len(blocks); i++ {
		rows[0] = append(rows[0], NewLeaf(sumFunc, blocks[i]))
	}

	// build upwards until we hit the root
	for i := 1; i < levels; i++ {
		prev := rows[i-1]

		// each iteration creates a branch from a pair of values originating from the previous level
		for j := 0; j < len(prev); j = j + 2 {
			var l, r Node

			// if we don't have enough to make a pair, duplicate the left
			if j+1 >= len(prev) {
				l = prev[j]
				r = l
			} else {
				l = prev[j]
				r = prev[j+1]
			}

			b := NewBranch(sumFunc, l, r)

			rows[i] = append(rows[i], b)
		}
	}

	return &Tree{
		HashFunc: sumFunc,
		Rows:     rows,
		Root:     rows[len(rows)-1][0],
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// METHODS
//////////

func (b *Branch) GetHash() []byte {
	return b.Hash
}

func (l *Leaf) GetHash() []byte {
	return l.Hash
}

func VerifyProof(leafHash []byte, pathToTarget []*ProofPart, target []byte) bool {
	return VerifyProofCustomHash(leafHash, pathToTarget, target, Sha256DoubleHash)
}

func VerifyProofCustomHash(leafHash []byte, pathToTarget []*ProofPart, target []byte, hashFunc func([]byte) []byte) bool {
	z := leafHash
	for i := 0; i < len(pathToTarget); i++ {
		if pathToTarget[i].IsRight {
			z = hashFunc(append(z, pathToTarget[i].Hash...))
		} else {
			z = hashFunc(append(pathToTarget[i].Hash, z...))
		}
	}

	return bytes.Equal(target, z)
}

func (t *Tree) getLeafIdxByChecksum(Hash []byte) int {
	index := -1
	for i := 0; i < len(t.Rows[0]); i++ {
		if bytes.Equal(Hash, t.Rows[0][i].GetHash()) {
			return i
		}
	}

	return index
}

func (t *Tree) CreateProof(leafChecksum []byte) (*Proof, error) {
	var parts []*ProofPart

	index := t.getLeafIdxByChecksum(leafChecksum)

	if index == -1 {
		return nil, errors.New("LeafHash not found in receiver")
	}

	for i := 0; i < len(t.Rows)-1; i++ {
		if index%2 == 1 {
			// is right, so go back one to get left
			parts = append(parts, &ProofPart{
				IsRight: false,
				Hash:    t.Rows[i][index-1].GetHash(),
			})
		} else {
			var Hash []byte
			if (index + 1) < len(t.Rows[i]) {
				Hash = t.Rows[i][index+1].GetHash()
			} else {
				Hash = t.Rows[i][index].GetHash()
			}

			// is left, so go one forward to get hash pair
			parts = append(parts, &ProofPart{
				IsRight: true,
				Hash:    Hash,
			})
		}

		index = int(float64(index / 2))
	}

	return &Proof{
		HashFunc:   t.HashFunc,
		PathToRoot: parts,
		LeafHash:   leafChecksum,
	}, nil
}

func (p *Proof) Equals(o *Proof) bool {
	if !bytes.Equal(p.LeafHash, o.LeafHash) {
		return false
	}

	if len(p.PathToRoot) != len(o.PathToRoot) {
		return false
	}

	ok := true

	for i := 0; i < len(p.PathToRoot); i++ {
		ok = ok && p.PathToRoot[i].IsRight && o.PathToRoot[i].IsRight && bytes.Equal(p.PathToRoot[i].Hash, o.PathToRoot[i].Hash)
	}

	return ok
}
