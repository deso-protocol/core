package lib

import (
	"github.com/golang/glog"
	"github.com/holiman/uint256"
)

func (srv *Server) submitRegtestValidatorRegistrationTxns(block *MsgDeSoBlock) {
	if block.Header.Height != uint64(srv.blockchain.params.ForkHeights.ProofOfStake1StateSetupBlockHeight+15) {
		return
	}

	glog.Infof(CLog(Yellow, "Reached ProofOfStake1StateSetupMigration.Height. Setting Up PoS Validator"))

	blsSigner := srv.fastHotStuffConsensus.signer
	privKey := srv.blockProducer.blockProducerPrivateKey
	transactorPubKey := privKey.PubKey().SerializeCompressed()

	// Register as a validator
	{
		votingAuthorizationPayload := CreateValidatorVotingAuthorizationPayload(transactorPubKey)
		votingAuthorization, err := blsSigner.Sign(votingAuthorizationPayload)
		if err != nil {
			panic(err)
		}

		var domain string
		if len(srv.GetConnectionManager().listeners) == 0 {
			domain = "localhost:18000"
		}
		domain = srv.GetConnectionManager().listeners[0].Addr().String()

		txnMeta := RegisterAsValidatorMetadata{
			Domains:                             [][]byte{[]byte(domain)},
			DisableDelegatedStake:               false,
			DelegatedStakeCommissionBasisPoints: 100,
			VotingPublicKey:                     blsSigner.GetPublicKey(),
			VotingAuthorization:                 votingAuthorization,
		}

		txn, _, _, _, err := srv.blockchain.CreateRegisterAsValidatorTxn(
			transactorPubKey,
			&txnMeta,
			make(map[string][]byte),
			1000,
			srv.mempool,
			[]*DeSoOutput{},
		)
		if err != nil {
			panic(err)
		}

		txnSignature, err := txn.Sign(privKey)
		if err != nil {
			panic(err)
		}

		txn.Signature.SetSignature(txnSignature)

		err = srv.VerifyAndBroadcastTransaction(txn)
		if err != nil {
			panic(err)
		}
	}

	// Stake DESO to the validator
	{
		stakeTxnMeta := StakeMetadata{
			ValidatorPublicKey: NewPublicKey(transactorPubKey),
			RewardMethod:       StakingRewardMethodPayToBalance,
			StakeAmountNanos:   uint256.NewInt().SetUint64(10 * 1e6),
		}

		stakeTxn, _, _, _, err := srv.blockProducer.chain.CreateStakeTxn(
			transactorPubKey,
			&stakeTxnMeta,
			make(map[string][]byte),
			1000,
			srv.mempool,
			[]*DeSoOutput{},
		)
		if err != nil {
			panic(err)
		}

		stakeTxnSignature, err := stakeTxn.Sign(privKey)
		if err != nil {
			panic(err)
		}

		stakeTxn.Signature.SetSignature(stakeTxnSignature)

		err = srv.VerifyAndBroadcastTransaction(stakeTxn)
		if err != nil {
			panic(err)
		}
	}
}
