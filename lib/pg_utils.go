package lib

import (
	"fmt"

	"github.com/go-pg/pg/v10"
)

type Chain struct {
	ID      uint64
	TipHash string
	Name    string `pg:",unique"`
}

// Block represents BlockNode and MsgBitCloutHeader
type Block struct {
	ID uint64

	// BlockNode and MsgBitCloutHeader
	Hash       *BlockHash `pg:",unique"`
	ParentHash *BlockHash
	Height     uint64 `pg:",use_zero"`

	// BlockNode
	DifficultyTarget *BlockHash
	CumWork          *BlockHash
	Status           BlockStatus

	// MsgBitCloutHeader
	TxMerkleRoot *BlockHash
	Version      uint32 `pg:",use_zero"`
	Timestamp    uint64 `pg:",use_zero"`
	Nonce        uint64 `pg:",use_zero"`
	ExtraNonce   uint64 `pg:",use_zero"`
}

// Transaction represents MsgBitCloutTxn
type Transaction struct {
	ID        uint64
	Hash      *BlockHash
	BlockHash *BlockHash
	PublicKey []byte
	ExtraData map[string][]byte
	R         *BlockHash
	S         *BlockHash
}

// TransactionInput represents BitCloutInput
type TransactionInput struct {
	ID         uint64
	OutputHash *BlockHash
	InputHash  *BlockHash
	InputIndex uint32 `pg:",use_zero"`
}

// TransactionOutput represents BitCloutOutput
type TransactionOutput struct {
	ID          uint64
	OutputHash  *BlockHash
	OutputIndex uint32 `pg:",use_zero"`
	PublicKey   []byte
	AmountNanos uint64 `pg:",use_zero"`
}

// MetadataBlockReward represents BlockRewardMetadataa
type MetadataBlockReward struct {
	ID        uint64
	ExtraData []byte
}

// MetadataBitcoinExchange represents BitcoinExchangeMetadata
type MetadataBitcoinExchange struct {
	ID                uint64
	BitcoinBlockHash  *BlockHash
	BitcoinMerkleRoot *BlockHash
	// Not storing BitcoinTransaction *wire.MsgTx
	// Not storing BitcoinMerkleProof []*merkletree.ProofPart
}

// MetadataPrivateMessage represents PrivateMessageMetadata
type MetadataPrivateMessage struct {
	ID                 uint64
	RecipientPublicKey []byte
	EncryptedText      []byte
	TimestampNanos     uint64
}

// MetadataSubmitPost represents SubmitPostMetadata
type MetadataSubmitPost struct {
	ID                       uint64
	PostHashToModify         []byte
	ParentStakeID            []byte
	Body                     []byte
	TimestampNanos           uint64
	IsHidden                 bool
}

// MetadataUpdateBitcoinUSDExchangeRate represents UpdateBitcoinUSDExchangeRateMetadataa
type MetadataUpdateBitcoinUSDExchangeRate struct {
	ID                 uint64
	USDCentsPerBitcoin uint64
}

// MetadataUpdateProfile represents UpdateProfileMetadata
type MetadataUpdateProfile struct {
	ID                          uint64
	ProfilePublicKey            []byte
	NewUsername                 []byte
	NewDescription              []byte
	NewProfilePic               []byte
	NewCreatorBasisPoints       uint64
	IsHidden                    bool
}

// MetadataFollow represents FollowMetadata
type MetadataFollow struct {
	ID                uint64
	FollowedPublicKey []byte
	IsUnfollow        bool
}

// MetadataLike represents LikeMetadata
type MetadataLike struct {
	ID            uint64
	LikedPostHash *BlockHash
	IsUnlike      bool
}

// MetadataCreatorCoin represents CreatorCoinMetadataa
type MetadataCreatorCoin struct {
	ID                          uint64
	ProfilePublicKey            []byte
	OperationType               CreatorCoinOperationType
	BitCloutToSellNanos         uint64
	CreatorCoinToSellNanos      uint64
	BitCloutToAddNanos          uint64
	MinBitCloutExpectedNanos    uint64
	MinCreatorCoinExpectedNanos uint64
}

// MetadataCreatorCoinTransfer represents CreatorCoinTransferMetadataa
type MetadataCreatorCoinTransfer struct {
	ID                         uint64
	ProfilePublicKey           []byte
	CreatorCoinToTransferNanos uint64
	ReceiverPublicKey          []byte
}

// MetadataSwapIdentity represents SwapIdentityMetadataa
type MetadataSwapIdentity struct {
	ID            uint64
	FromPublicKey []byte
	ToPublicKey   []byte
}

func UpsertBlock(db *pg.DB, blockNode *BlockNode) error {
	return db.RunInTransaction(db.Context(), func(tx *pg.Tx) error {
		_, err := UpsertBlockTx(tx, blockNode)
		return err
	})
}

func UpsertBlockTx(tx *pg.Tx, blockNode *BlockNode) (*Block, error) {
	block := &Block{
		Hash:       blockNode.Hash,
		ParentHash: blockNode.Parent.Hash,
		Height:     blockNode.Header.Height,

		DifficultyTarget: blockNode.DifficultyTarget,
		CumWork:          BigintToHash(blockNode.CumWork),
		Status:           blockNode.Status,

		TxMerkleRoot: blockNode.Header.TransactionMerkleRoot,
		Version:      blockNode.Header.Version,
		Timestamp:    blockNode.Header.TstampSecs,
		Nonce:        blockNode.Header.Nonce,
		ExtraNonce:   blockNode.Header.ExtraNonce,
	}

	_, err := tx.Model(block).
		OnConflict("(hash) DO UPDATE").
		Insert()
	if err != nil {
		return nil, err
	}

	return block, nil
}

func UpsertChainTx(tx *pg.Tx, name string, tipHash string) error {
	bestChain := &Chain{
		TipHash: tipHash,
		Name:    name,
	}

	_, err := tx.Model(bestChain).
		OnConflict("(name) DO UPDATE").
		Insert()
	return err
}

func InsertTransactionTx(tx *pg.Tx, txn *MsgBitCloutTxn, blockHash *BlockHash) error {
	txnHash := txn.Hash()
	transaction := &Transaction{
		Hash:      txnHash,
		BlockHash: blockHash,
		PublicKey: txn.PublicKey,
		ExtraData: txn.ExtraData,
		// TOOD: Include signature
		// R:         BigintToHash(txn.Signature.R),
		// S:         BigintToHash(txn.Signature.S),
	}

	_, err := tx.Model(transaction).Insert()
	if err != nil {
		return err
	}

	for _, input := range txn.TxInputs {
		transactionInput := &TransactionInput{
			OutputHash: txnHash,
			InputHash:  &input.TxID,
			InputIndex: input.Index,
		}

		_, err = tx.Model(transactionInput).Insert()
		if err != nil {
			return err
		}
	}

	for i, output := range txn.TxOutputs {
		transactionOutput := &TransactionOutput{
			OutputHash:  txnHash,
			OutputIndex: uint32(i),
			PublicKey:   output.PublicKey,
			AmountNanos: output.AmountNanos,
		}

		_, err = tx.Model(transactionOutput).Insert()
		if err != nil {
			return err
		}
	}

	if txn.TxnMeta.GetTxnType() == TxnTypeBasicTransfer || txn.TxnMeta.GetTxnType() == TxnTypeUpdateGlobalParams {
		// No extra metadata needed
	} else if txn.TxnMeta.GetTxnType() == TxnTypeBlockReward {
		txMeta := txn.TxnMeta.(*BlockRewardMetadataa)
		_, err = tx.Model(&BlockRewardMetadataa{
			ExtraData: txMeta.ExtraData,
		}).Insert()
	} else if txn.TxnMeta.GetTxnType() == TxnTypeBitcoinExchange {
		txMeta := txn.TxnMeta.(*BitcoinExchangeMetadata)
		_, err = tx.Model(&MetadataBitcoinExchange{
			BitcoinBlockHash:  txMeta.BitcoinBlockHash,
			BitcoinMerkleRoot: txMeta.BitcoinMerkleRoot,
		}).Insert()
	} else if txn.TxnMeta.GetTxnType() == TxnTypePrivateMessage {
		txMeta := txn.TxnMeta.(*PrivateMessageMetadata)
		_, err = tx.Model(&MetadataPrivateMessage{
			RecipientPublicKey: txMeta.RecipientPublicKey,
			EncryptedText:      txMeta.EncryptedText,
			TimestampNanos:     txMeta.TimestampNanos,
		}).Insert()
	} else if txn.TxnMeta.GetTxnType() == TxnTypeSubmitPost {
		txMeta := txn.TxnMeta.(*SubmitPostMetadata)
		_, err = tx.Model(&MetadataSubmitPost{
			PostHashToModify:         txMeta.PostHashToModify,
			ParentStakeID:            txMeta.ParentStakeID,
			Body:                     txMeta.Body,
			TimestampNanos:           txMeta.TimestampNanos,
			IsHidden:                 txMeta.IsHidden,
		}).Insert()
	} else if txn.TxnMeta.GetTxnType() == TxnTypeUpdateProfile {
		txMeta := txn.TxnMeta.(*UpdateProfileMetadata)
		_, err = tx.Model(&MetadataUpdateProfile{
			ProfilePublicKey:            txMeta.ProfilePublicKey,
			NewUsername:                 txMeta.NewUsername,
			NewProfilePic:               txMeta.NewProfilePic,
			NewCreatorBasisPoints:       txMeta.NewCreatorBasisPoints,
			IsHidden:                    txMeta.IsHidden,
		}).Insert()
	} else if txn.TxnMeta.GetTxnType() == TxnTypeUpdateBitcoinUSDExchangeRate {
		txMeta := txn.TxnMeta.(*UpdateBitcoinUSDExchangeRateMetadataa)
		_, err = tx.Model(&MetadataUpdateBitcoinUSDExchangeRate{
			USDCentsPerBitcoin: txMeta.USDCentsPerBitcoin,
		}).Insert()
	} else if txn.TxnMeta.GetTxnType() == TxnTypeFollow {
		txMeta := txn.TxnMeta.(*FollowMetadata)
		_, err = tx.Model(&MetadataFollow{
			FollowedPublicKey: txMeta.FollowedPublicKey,
			IsUnfollow: txMeta.IsUnfollow,
		}).Insert()
	} else if txn.TxnMeta.GetTxnType() == TxnTypeLike {
		txMeta := txn.TxnMeta.(*LikeMetadata)
		_, err = tx.Model(&MetadataLike{
			LikedPostHash: txMeta.LikedPostHash,
			IsUnlike: txMeta.IsUnlike,
		}).Insert()
	} else if txn.TxnMeta.GetTxnType() == TxnTypeCreatorCoin {
		txMeta := txn.TxnMeta.(*CreatorCoinMetadataa)
		_, err = tx.Model(&MetadataCreatorCoin{
			ProfilePublicKey: txMeta.ProfilePublicKey,
			OperationType: txMeta.OperationType,
			BitCloutToSellNanos: txMeta.BitCloutToSellNanos,
			CreatorCoinToSellNanos: txMeta.CreatorCoinToSellNanos,
			BitCloutToAddNanos: txMeta.BitCloutToAddNanos,
			MinBitCloutExpectedNanos: txMeta.MinBitCloutExpectedNanos,
			MinCreatorCoinExpectedNanos: txMeta.MinCreatorCoinExpectedNanos,
		}).Insert()
	} else if txn.TxnMeta.GetTxnType() == TxnTypeCreatorCoinTransfer {
		txMeta := txn.TxnMeta.(*CreatorCoinTransferMetadataa)
		_, err = tx.Model(&MetadataCreatorCoinTransfer{
			ProfilePublicKey: txMeta.ProfilePublicKey,
			CreatorCoinToTransferNanos: txMeta.CreatorCoinToTransferNanos,
			ReceiverPublicKey: txMeta.ReceiverPublicKey,
		}).Insert()
	} else if txn.TxnMeta.GetTxnType() == TxnTypeSwapIdentity {
		txMeta := txn.TxnMeta.(*SwapIdentityMetadataa)
		_, err = tx.Model(&MetadataSwapIdentity{
			FromPublicKey: txMeta.FromPublicKey,
			ToPublicKey: txMeta.ToPublicKey,
		}).Insert()
	} else {
		err = fmt.Errorf("InsertTransactionTx: Unimplemented txn type %v", txn.TxnMeta.GetTxnType().String())
	}

	return err
}

func UpsertBlockAndTransactions(db *pg.DB, blockNode *BlockNode, bitcloutBlock *MsgBitCloutBlock) error {
	return db.RunInTransaction(db.Context(), func(tx *pg.Tx) error {
		//block, err := UpsertBlockTx(tx, blockNode)
		//if err != nil {
		//	return err
		//}

		blockHash := blockNode.Hash
		//err = UpsertChainTx(tx, "main", blockHash)
		//if err != nil {
		//	return err
		//}

		for _, txn := range bitcloutBlock.Txns {
			err := InsertTransactionTx(tx, txn, blockHash)
			if err != nil {
				return err
			}
		}

		return nil
	})
}
