package merkletree

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

// drops the unprintable prefix
func bytesToStrForTest(xs []byte) string {
	var xs2 []byte

	for i, c := range xs {
		if c < 128 && c > 31 {
			xs2 = append(xs2, xs[i])
		}
	}

	return string(xs2)
}

func trimNewlines(str string) string {
	return strings.Trim(str, "\n")
}

func expectStrEqual(t *testing.T, actual string, expected string) {
	if trimNewlines(actual) != expected {
		fmt.Println(fmt.Sprintf("=====ACTUAL======\n\n%s\n\n=====EXPECTED======\n\n%s\n", actual, expected))
		t.Fail()
	}
}

var givenOneBlock = trimNewlines(`
(B root: alphaalpha 
  (L root: alpha) 
  (L root: alpha))
`)

var givenFourBlocks = trimNewlines(`
(B root: alphabetakappagamma 
  (B root: alphabeta 
    (L root: alpha) 
    (L root: beta)) 
  (B root: kappagamma 
    (L root: kappa) 
    (L root: gamma)))
`)

var givenTwoBlocks = trimNewlines(`
(B root: alphabeta 
  (L root: alpha) 
  (L root: beta))
`)

var givenThreeBlocks = trimNewlines(`
(B root: alphabetakappakappa 
  (B root: alphabeta 
    (L root: alpha) 
    (L root: beta)) 
  (B root: kappakappa 
    (L root: kappa) 
    (L root: kappa)))
`)

var givenSixBlocks = trimNewlines(`
(B root: alphabetakappagammaepsilonomegaepsilonomega 
  (B root: alphabetakappagamma 
    (B root: alphabeta 
      (L root: alpha) 
      (L root: beta)) 
    (B root: kappagamma 
      (L root: kappa) 
      (L root: gamma))) 
  (B root: epsilonomegaepsilonomega 
    (B root: epsilonomega 
      (L root: epsilon) 
      (L root: omega)) 
    (B root: epsilonomega 
      (L root: epsilon) 
      (L root: omega))))
`)

var proofA = trimNewlines(`
route from omega (leaf) to root:

epsilon + omega = epsilonomega
epsilonomega + muzeta = epsilonomegamuzeta
alphabetakappagamma + epsilonomegamuzeta = alphabetakappagammaepsilonomegamuzeta
`)

func TestCreateMerkleTree(t *testing.T) {
	t.Run("easy tree - just one level (the root) of nodes", func(t *testing.T) {
		blocks := [][]byte{[]byte("alpha"), []byte("beta")}
		tree := NewTree(IdentityHashForTest, blocks)

		expectStrEqual(t, tree.ToString(bytesToStrForTest, 0), givenTwoBlocks)
	})

	t.Run("two levels of nodes", func(t *testing.T) {
		blocks := [][]byte{[]byte("alpha"), []byte("beta"), []byte("kappa"), []byte("gamma")}
		tree := NewTree(IdentityHashForTest, blocks)

		expectStrEqual(t, tree.ToString(bytesToStrForTest, 0), givenFourBlocks)
	})

	t.Run("one block - one level", func(t *testing.T) {
		blocks := [][]byte{[]byte("alpha")}
		tree := NewTree(IdentityHashForTest, blocks)

		expectStrEqual(t, tree.ToString(bytesToStrForTest, 0), givenOneBlock)
	})

	/*

				duplicate a leaf

		            123{3}
				 /        \
			   12          3{3}
			 /    \      /    \
			1      2    3      {3}

	*/
	t.Run("duplicate a leaf to keep the binary tree balanced", func(t *testing.T) {
		blocks := [][]byte{[]byte("alpha"), []byte("beta"), []byte("kappa")}
		tree := NewTree(IdentityHashForTest, blocks)

		expectStrEqual(t, tree.ToString(bytesToStrForTest, 0), givenThreeBlocks)
	})

	/*

			          duplicate a node

		                123456{56}
		          /                    \
		        1234                  56{56}
		     /        \              /      \
		   12          34          56        {56}
		 /    \      /    \      /    \     /    \
		1      2    3      4    5      6  {5}    {6}

	*/
	t.Run("duplicate a branch to keep the tree balanced", func(t *testing.T) {
		blocks := [][]byte{[]byte("alpha"), []byte("beta"), []byte("kappa"), []byte("gamma"), []byte("epsilon"), []byte("omega")}
		tree := NewTree(IdentityHashForTest, blocks)

		expectStrEqual(t, tree.ToString(bytesToStrForTest, 0), givenSixBlocks)
	})
}

func TestAuditProof(t *testing.T) {
	t.Run("Tree#CreateProof", func(t *testing.T) {
		blocks := [][]byte{
			[]byte("alpha"),
			[]byte("beta"),
			[]byte("kappa"),
		}

		tree := NewTree(IdentityHashForTest, blocks)
		LeafHash := tree.HashFunc(true, []byte("alpha"))

		proof, err := tree.CreateProof(LeafHash)
		if err != nil {
			t.Fail()
		}

		expected := Proof{
			PathToRoot: []*ProofPart{{
				IsRight: true,
				Hash:    tree.HashFunc(true, []byte("beta")),
			}, {
				IsRight: true,
				Hash:    tree.HashFunc(false, append(tree.HashFunc(true, []byte("kappa")), tree.HashFunc(true, []byte("kappa"))...)),
			}},
			LeafHash: LeafHash,
		}

		if !expected.Equals(proof) {
			t.Fail()
		}
	})

	t.Run("Proof#ToString", func(t *testing.T) {
		blocks := [][]byte{
			[]byte("alpha"),
			[]byte("beta"),
			[]byte("kappa"),
			[]byte("gamma"),
			[]byte("epsilon"),
			[]byte("omega"),
			[]byte("mu"),
			[]byte("zeta"),
		}

		tree := NewTree(IdentityHashForTest, blocks)
		LeafHash := tree.HashFunc(true, []byte("omega"))
		proof, _ := tree.CreateProof(LeafHash)

		expectStrEqual(t, proof.ToString(bytesToStrForTest), proofA)
	})

	t.Run("Tree#VerifyProof", func(t *testing.T) {
		t.Run("valid proof for a two-leaf tree", func(t *testing.T) {
			blocks := [][]byte{
				[]byte("alpha"),
				[]byte("beta"),
			}

			tree := NewTree(IdentityHashForTest, blocks)

			proof := &Proof{
				PathToRoot: []*ProofPart{{
					IsRight: true,
					Hash:    tree.HashFunc(true, []byte("beta")),
				}},
				LeafHash: tree.HashFunc(true, []byte("alpha")),
			}

			if !VerifyProofCustomHash(proof.LeafHash, proof.PathToRoot, tree.Root.GetHash(), IdentityHashForTest) {
				t.Fail()
			}
		})

		t.Run("invalid proof (IsRight should be true) for a two-leaf tree", func(t *testing.T) {
			blocks := [][]byte{
				[]byte("alpha"),
				[]byte("beta"),
			}

			tree := NewTree(IdentityHashForTest, blocks)

			proof := &Proof{
				PathToRoot: []*ProofPart{{
					IsRight: false,
					Hash:    tree.HashFunc(true, []byte("beta")),
				}},
				LeafHash: tree.HashFunc(true, []byte("alpha")),
			}

			if VerifyProofCustomHash(proof.LeafHash, proof.PathToRoot, tree.Root.GetHash(), IdentityHashForTest) {
				t.Fail()
			}
		})

		t.Run("invalid proof (wrong sibling) for a two-leaf tree", func(t *testing.T) {
			blocks := [][]byte{
				[]byte("alpha"),
				[]byte("beta"),
			}

			tree := NewTree(IdentityHashForTest, blocks)

			proof := &Proof{
				PathToRoot: []*ProofPart{{
					IsRight: true,
					Hash:    tree.HashFunc(true, []byte("kappa")),
				}},
				LeafHash: tree.HashFunc(true, []byte("alpha")),
			}

			if VerifyProofCustomHash(proof.LeafHash, proof.PathToRoot, tree.Root.GetHash(), IdentityHashForTest) {
				t.Fail()
			}
		})

		t.Run("invalid proof (tree doesn't contain LeafHash) for a two-leaf tree", func(t *testing.T) {
			blocks := [][]byte{
				[]byte("alpha"),
				[]byte("beta"),
			}

			tree := NewTree(IdentityHashForTest, blocks)

			proof := &Proof{
				PathToRoot: []*ProofPart{{
					IsRight: true,
					Hash:    tree.HashFunc(true, []byte("beta")),
				}},
				LeafHash: tree.HashFunc(true, []byte("kappa")),
			}

			if VerifyProofCustomHash(proof.LeafHash, proof.PathToRoot, tree.Root.GetHash(), IdentityHashForTest) {
				t.Fail()
			}
		})

		t.Run("valid proof for eight leaf tree", func(t *testing.T) {
			blocks := [][]byte{
				[]byte("alpha"),
				[]byte("beta"),
				[]byte("kappa"),
				[]byte("gamma"),
				[]byte("epsilon"),
				[]byte("omega"),
				[]byte("mu"),
				[]byte("zeta"),
			}

			tree := NewTree(IdentityHashForTest, blocks)
			LeafHash := tree.HashFunc(true, []byte("alpha"))

			proof, err := tree.CreateProof(LeafHash)
			if err != nil {
				t.Fail()
			}

			if !VerifyProofCustomHash(proof.LeafHash, proof.PathToRoot, tree.Root.GetHash(), IdentityHashForTest) {
				t.Fail()
			}
		})
	})
}

// Note: Bitcoin doesn't care about pre-image attacks and the mechanism in the library
// that protects against them causes the library to be incompatible with Bitcoin. As such
// we comment out the code that protects against pre-image attacks and comment out
// this test.
/*
func TestHandlesPreimageAttack(t *testing.T) {
	blocks := [][]byte{
		[]byte("alpha"),
		[]byte("beta"),
		[]byte("kappa"),
	}

	tree := NewTree(Sha256DoubleHash, blocks)

	l := append(tree.HashFunc(true, []byte("alpha")), tree.HashFunc(true, []byte("beta"))...)
	r := append(tree.HashFunc(true, []byte("kappa")), tree.HashFunc(true, []byte("kappa"))...)

	tree2 := NewTree(Sha256DoubleHash, [][]byte{l, r})

	if bytes.Equal(tree.Root.GetHash(), tree2.Root.GetHash()) {
		t.Fail()
	}
}
*/

func TestDocsCreateAndPrintAuditProof(t *testing.T) {
	blocks := [][]byte{
		[]byte("alpha"),
		[]byte("beta"),
		[]byte("kappa"),
	}

	tree := NewTree(Sha256DoubleHash, blocks)
	LeafHash := tree.HashFunc(true, []byte("alpha"))
	proof, _ := tree.CreateProof(LeafHash)

	fmt.Println(proof.ToString(func(bytes []byte) string {
		return hex.EncodeToString(bytes)[0:16]
	}))
}

func TestDocsCreateAndPrintTree(t *testing.T) {
	blocks := [][]byte{
		[]byte("alpha"),
		[]byte("beta"),
		[]byte("kappa"),
	}

	tree := NewTree(Sha256DoubleHash, blocks)

	fmt.Println(tree.ToString(func(bytes []byte) string {
		return hex.EncodeToString(bytes)[0:16]
	}, 0))
}

func TestDocsValidateProof(t *testing.T) {
	blocks := [][]byte{
		[]byte("alpha"),
		[]byte("beta"),
		[]byte("kappa"),
	}

	tree := NewTree(Sha256DoubleHash, blocks)

	proof, err := tree.CreateProof(tree.Rows[0][0].GetHash())
	if err != nil {
		panic(err)
	}

	if !VerifyProof(proof.LeafHash, proof.PathToRoot, tree.Root.GetHash()) {
		t.Fail()
	}
}
