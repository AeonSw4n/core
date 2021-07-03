package lib

import (
	"fmt"
	"github.com/dgraph-io/badger/v3"
	"github.com/go-pg/pg/v10"
	"github.com/golang/glog"
)

type Postgres struct {
	db *pg.DB
}

func NewPostgres(postgesURI string) (*Postgres, error) {
	options, err := pg.ParseURL(postgesURI)
	if err != nil {
		return nil, err
	}

	db := pg.Connect(options)

	// Print all queries.
	//db.AddQueryHook(pgdebug.DebugHook{
	//	Verbose: true,
	//})

	return &Postgres{
		db: db,
	}, nil
}

//
// Tables
//
// When we can, we use unique fields (or combinations of unique fields) as the primary keys on the models.
// This lets us use the WherePK() query while also minimizing columns and indicies on disk.
//

type Chain struct {
	Name    string `pg:",pk"`
	TipHash *BlockHash
}

// Block represents BlockNode and MsgBitCloutHeader
type Block struct {
	// BlockNode and MsgBitCloutHeader
	Hash       *BlockHash `pg:",pk,unique"`
	ParentHash *BlockHash
	Height     uint64 `pg:",use_zero"`

	// BlockNode
	DifficultyTarget *BlockHash
	CumWork          *BlockHash
	Status           BlockStatus // TODO: Refactor

	// MsgBitCloutHeader
	TxMerkleRoot *BlockHash
	Version      uint32 `pg:",use_zero"`
	Timestamp    uint64 `pg:",use_zero"`
	Nonce        uint64 `pg:",use_zero"`
	ExtraNonce   uint64 `pg:",use_zero"`

	// Notifications
	Notified bool `pg:",use_zero"`
}

// Transaction represents MsgBitCloutTxn
type Transaction struct {
	Hash      *BlockHash `pg:",pk"`
	BlockHash *BlockHash
	Type      TxnType
	PublicKey []byte
	ExtraData map[string][]byte
	R         *BlockHash
	S         *BlockHash

	// Relationships
	Outputs                     []*TransactionOutput         `pg:"rel:has-many,join_fk:output_hash"`
	MetadataBlockReward         *MetadataBlockReward         `pg:"rel:belongs-to,join_fk:transaction_hash"`
	MetadataBitcoinExchange     *MetadataBitcoinExchange     `pg:"rel:belongs-to,join_fk:transaction_hash"`
	MetadataPrivateMessage      *MetadataPrivateMessage      `pg:"rel:belongs-to,join_fk:transaction_hash"`
	MetadataSubmitPost          *MetadataSubmitPost          `pg:"rel:belongs-to,join_fk:transaction_hash"`
	MetadataUpdateExchangeRate  *MetadataUpdateExchangeRate  `pg:"rel:belongs-to,join_fk:transaction_hash"`
	MetadataUpdateProfile       *MetadataUpdateProfile       `pg:"rel:belongs-to,join_fk:transaction_hash"`
	MetadataFollow              *MetadataFollow              `pg:"rel:belongs-to,join_fk:transaction_hash"`
	MetadataLike                *MetadataLike                `pg:"rel:belongs-to,join_fk:transaction_hash"`
	MetadataCreatorCoin         *MetadataCreatorCoin         `pg:"rel:belongs-to,join_fk:transaction_hash"`
	MetadataCreatorCoinTransfer *MetadataCreatorCoinTransfer `pg:"rel:belongs-to,join_fk:transaction_hash"`
	MetadataSwapIdentity        *MetadataSwapIdentity        `pg:"rel:belongs-to,join_fk:transaction_hash"`
}

// TransactionOutput represents BitCloutOutput, BitCloutInput, and UtxoEntry
type TransactionOutput struct {
	OutputHash  *BlockHash `pg:",pk"`
	OutputIndex uint32     `pg:",pk,use_zero"`
	OutputType  UtxoType   `pg:",use_zero"`
	PublicKey   []byte
	AmountNanos uint64 `pg:",use_zero"`
	Spent       bool   `pg:",use_zero"`
	InputHash   *BlockHash
	InputIndex  uint32 `pg:",pk,use_zero"`
}

// MetadataBlockReward represents BlockRewardMetadataa
type MetadataBlockReward struct {
	TransactionHash *BlockHash `pg:",pk"`
	ExtraData       []byte
}

// MetadataBitcoinExchange represents BitcoinExchangeMetadata
type MetadataBitcoinExchange struct {
	TransactionHash   *BlockHash `pg:",pk"`
	BitcoinBlockHash  *BlockHash
	BitcoinMerkleRoot *BlockHash
	// Not storing BitcoinTransaction *wire.MsgTx
	// Not storing BitcoinMerkleProof []*merkletree.ProofPart
}

// MetadataPrivateMessage represents PrivateMessageMetadata
type MetadataPrivateMessage struct {
	TransactionHash    *BlockHash `pg:",pk"`
	RecipientPublicKey []byte
	EncryptedText      []byte
	TimestampNanos     uint64
}

// MetadataSubmitPost represents SubmitPostMetadata
type MetadataSubmitPost struct {
	TransactionHash  *BlockHash `pg:",pk"`
	PostHashToModify *BlockHash
	ParentStakeID    *BlockHash
	Body             []byte
	TimestampNanos   uint64
	IsHidden         bool `pg:",use_zero"`
}

// MetadataUpdateExchangeRate represents UpdateBitcoinUSDExchangeRateMetadataa
type MetadataUpdateExchangeRate struct {
	TransactionHash    *BlockHash `pg:",pk"`
	USDCentsPerBitcoin uint64     `pg:",use_zero"`
}

// MetadataUpdateProfile represents UpdateProfileMetadata
type MetadataUpdateProfile struct {
	TransactionHash       *BlockHash `pg:",pk"`
	ProfilePublicKey      []byte
	NewUsername           []byte
	NewDescription        []byte
	NewProfilePic         []byte
	NewCreatorBasisPoints uint64 `pg:",use_zero"`
}

// MetadataFollow represents FollowMetadata
type MetadataFollow struct {
	TransactionHash   *BlockHash `pg:",pk"`
	FollowedPublicKey []byte
	IsUnfollow        bool `pg:",use_zero"`
}

// MetadataLike represents LikeMetadata
type MetadataLike struct {
	TransactionHash *BlockHash `pg:",pk"`
	LikedPostHash   *BlockHash
	IsUnlike        bool `pg:",use_zero"`
}

// MetadataCreatorCoin represents CreatorCoinMetadataa
type MetadataCreatorCoin struct {
	TransactionHash             *BlockHash `pg:",pk"`
	ProfilePublicKey            []byte
	OperationType               CreatorCoinOperationType `pg:",use_zero"`
	BitCloutToSellNanos         uint64                   `pg:",use_zero"`
	CreatorCoinToSellNanos      uint64                   `pg:",use_zero"`
	BitCloutToAddNanos          uint64                   `pg:",use_zero"`
	MinBitCloutExpectedNanos    uint64                   `pg:",use_zero"`
	MinCreatorCoinExpectedNanos uint64                   `pg:",use_zero"`
}

// MetadataCreatorCoinTransfer represents CreatorCoinTransferMetadataa
type MetadataCreatorCoinTransfer struct {
	TransactionHash            *BlockHash `pg:",pk"`
	ProfilePublicKey           []byte
	CreatorCoinToTransferNanos uint64 `pg:",use_zero"`
	ReceiverPublicKey          []byte
}

// MetadataSwapIdentity represents SwapIdentityMetadataa
type MetadataSwapIdentity struct {
	TransactionHash *BlockHash `pg:",pk"`
	FromPublicKey   []byte
	ToPublicKey     []byte
}

type Notification struct {
	TransactionHash *BlockHash `pg:",pk"`
	Mined           bool
	ToUser          []byte
	FromUser        []byte
	OtherUser       []byte
	Type            NotificationType
	Amount          uint64
	PostHash        *BlockHash
	Timestamp       uint64
}

type NotificationType uint8

const (
	NotificationUnknown NotificationType = iota
	NotificationSendClout
	NotificationLike
	NotificationFollow
	NotificationCoinPurchase
	NotificationCoinTransfer
	NotificationCoinDiamond
	NotificationPostMention
	NotificationPostReply
	NotificationPostReclout
)

//
// Blockchain and Transactions
//

func (postgres *Postgres) UpsertBlock(blockNode *BlockNode) error {
	return postgres.db.RunInTransaction(postgres.db.Context(), func(tx *pg.Tx) error {
		return postgres.UpsertBlockTx(tx, blockNode)
	})
}

func (postgres *Postgres) UpsertBlockTx(tx *pg.Tx, blockNode *BlockNode) error {
	block := &Block{
		Hash:   blockNode.Hash,
		Height: blockNode.Header.Height,

		DifficultyTarget: blockNode.DifficultyTarget,
		CumWork:          BigintToHash(blockNode.CumWork),
		Status:           blockNode.Status,

		TxMerkleRoot: blockNode.Header.TransactionMerkleRoot,
		Version:      blockNode.Header.Version,
		Timestamp:    blockNode.Header.TstampSecs,
		Nonce:        blockNode.Header.Nonce,
		ExtraNonce:   blockNode.Header.ExtraNonce,
	}

	// The genesis block has a nil parent
	if blockNode.Parent != nil {
		block.ParentHash = blockNode.Parent.Hash
	}

	_, err := tx.Model(block).WherePK().OnConflict("(hash) DO UPDATE").Insert()
	return err
}

func (postgres *Postgres) GetBlockIndex() (map[BlockHash]*BlockNode, error) {
	var blocks []Block
	err := postgres.db.Model(&blocks).Select()
	if err != nil {
		return nil, err
	}

	blockMap := make(map[BlockHash]*BlockNode)
	for _, block := range blocks {
		blockMap[*block.Hash] = &BlockNode{
			Hash:             block.Hash,
			Height:           uint32(block.Height),
			DifficultyTarget: block.DifficultyTarget,
			CumWork:          HashToBigint(block.CumWork),
			Header: &MsgBitCloutHeader{
				Version:               block.Version,
				PrevBlockHash:         block.ParentHash,
				TransactionMerkleRoot: block.TxMerkleRoot,
				TstampSecs:            block.Timestamp,
				Height:                block.Height,
				Nonce:                 block.Nonce,
				ExtraNonce:            block.ExtraNonce,
			},
			Status: block.Status,
		}
	}

	// Setup parent pointers
	for _, blockNode := range blockMap {
		// Genesis block has nil parent
		parentHash := blockNode.Header.PrevBlockHash
		if parentHash != nil {
			blockNode.Parent = blockMap[*parentHash]
		}
	}

	return blockMap, nil
}

func (postgres *Postgres) GetChain(name string) *Chain {
	chain := &Chain{
		Name: name,
	}

	err := postgres.db.Model(chain).First()
	if err != nil {
		return nil
	}

	return chain
}

func (postgres *Postgres) UpsertChain(name string, tipHash *BlockHash) error {
	return postgres.db.RunInTransaction(postgres.db.Context(), func(tx *pg.Tx) error {
		return postgres.UpsertChainTx(tx, name, tipHash)
	})
}

func (postgres *Postgres) UpsertChainTx(tx *pg.Tx, name string, tipHash *BlockHash) error {
	bestChain := &Chain{
		TipHash: tipHash,
		Name:    name,
	}

	_, err := tx.Model(bestChain).WherePK().OnConflict("(name) DO UPDATE").Insert()
	return err
}

func (postgres *Postgres) InsertTransactionsTx(tx *pg.Tx, bitCloutTxns []*MsgBitCloutTxn, blockHash *BlockHash) error {
	var transactions []*Transaction
	var transactionOutputs []*TransactionOutput
	var transactionInputs []*TransactionOutput
	var metadataBlockRewards []*MetadataBlockReward
	var metadataBitcoinExchanges []*MetadataBitcoinExchange
	var metadataPrivateMessages []*MetadataPrivateMessage
	var metadataSubmitPosts []*MetadataSubmitPost
	var metadataUpdateProfiles []*MetadataUpdateProfile
	var metadataExchangeRates []*MetadataUpdateExchangeRate
	var metadataFollows []*MetadataFollow
	var metadataLikes []*MetadataLike
	var metadataCreatorCoins []*MetadataCreatorCoin
	var metadataCreatorCoinTransfers []*MetadataCreatorCoinTransfer
	var metadataSwapIdentities []*MetadataSwapIdentity

	for _, txn := range bitCloutTxns {
		txnHash := txn.Hash()
		transaction := &Transaction{
			Hash:      txnHash,
			BlockHash: blockHash,
			Type:      txn.TxnMeta.GetTxnType(),
			PublicKey: txn.PublicKey,
			ExtraData: txn.ExtraData,
		}

		if txn.Signature != nil {
			transaction.R = BigintToHash(txn.Signature.R)
			transaction.S = BigintToHash(txn.Signature.S)
		}

		transactions = append(transactions, transaction)

		for i, input := range txn.TxInputs {
			transactionInputs = append(transactionInputs, &TransactionOutput{
				OutputHash:  &input.TxID,
				OutputIndex: input.Index,
				InputHash:   txnHash,
				InputIndex:  uint32(i),
				Spent:       true,
			})
		}

		for i, output := range txn.TxOutputs {
			transactionOutputs = append(transactionOutputs, &TransactionOutput{
				OutputHash:  txnHash,
				OutputIndex: uint32(i),
				OutputType:  0, // TODO
				PublicKey:   output.PublicKey,
				AmountNanos: output.AmountNanos,
			})
		}

		if txn.TxnMeta.GetTxnType() == TxnTypeUpdateGlobalParams {
			// No extra metadata needed
		} else if txn.TxnMeta.GetTxnType() == TxnTypeBasicTransfer {
		} else if txn.TxnMeta.GetTxnType() == TxnTypeBlockReward {
			txMeta := txn.TxnMeta.(*BlockRewardMetadataa)
			metadataBlockRewards = append(metadataBlockRewards, &MetadataBlockReward{
				TransactionHash: txnHash,
				ExtraData:       txMeta.ExtraData,
			})
		} else if txn.TxnMeta.GetTxnType() == TxnTypeBitcoinExchange {
			txMeta := txn.TxnMeta.(*BitcoinExchangeMetadata)
			metadataBitcoinExchanges = append(metadataBitcoinExchanges, &MetadataBitcoinExchange{
				TransactionHash:   txnHash,
				BitcoinBlockHash:  txMeta.BitcoinBlockHash,
				BitcoinMerkleRoot: txMeta.BitcoinMerkleRoot,
			})
		} else if txn.TxnMeta.GetTxnType() == TxnTypePrivateMessage {
			txMeta := txn.TxnMeta.(*PrivateMessageMetadata)
			metadataPrivateMessages = append(metadataPrivateMessages, &MetadataPrivateMessage{
				TransactionHash:    txnHash,
				RecipientPublicKey: txMeta.RecipientPublicKey,
				EncryptedText:      txMeta.EncryptedText,
				TimestampNanos:     txMeta.TimestampNanos,
			})
		} else if txn.TxnMeta.GetTxnType() == TxnTypeSubmitPost {
			txMeta := txn.TxnMeta.(*SubmitPostMetadata)

			postHashToModify := &BlockHash{}
			parentStakeId := &BlockHash{}
			copy(postHashToModify[:], txMeta.PostHashToModify)
			copy(parentStakeId[:], txMeta.ParentStakeID)

			metadataSubmitPosts = append(metadataSubmitPosts, &MetadataSubmitPost{
				TransactionHash:  txnHash,
				PostHashToModify: postHashToModify,
				ParentStakeID:    parentStakeId,
				Body:             txMeta.Body,
				TimestampNanos:   txMeta.TimestampNanos,
				IsHidden:         txMeta.IsHidden,
			})
		} else if txn.TxnMeta.GetTxnType() == TxnTypeUpdateProfile {
			txMeta := txn.TxnMeta.(*UpdateProfileMetadata)
			metadataUpdateProfiles = append(metadataUpdateProfiles, &MetadataUpdateProfile{
				TransactionHash:       txnHash,
				ProfilePublicKey:      txMeta.ProfilePublicKey,
				NewUsername:           txMeta.NewUsername,
				NewProfilePic:         txMeta.NewProfilePic,
				NewCreatorBasisPoints: txMeta.NewCreatorBasisPoints,
			})
		} else if txn.TxnMeta.GetTxnType() == TxnTypeUpdateBitcoinUSDExchangeRate {
			txMeta := txn.TxnMeta.(*UpdateBitcoinUSDExchangeRateMetadataa)
			metadataExchangeRates = append(metadataExchangeRates, &MetadataUpdateExchangeRate{
				TransactionHash:    txnHash,
				USDCentsPerBitcoin: txMeta.USDCentsPerBitcoin,
			})
		} else if txn.TxnMeta.GetTxnType() == TxnTypeFollow {
			txMeta := txn.TxnMeta.(*FollowMetadata)
			metadataFollows = append(metadataFollows, &MetadataFollow{
				TransactionHash:   txnHash,
				FollowedPublicKey: txMeta.FollowedPublicKey,
				IsUnfollow:        txMeta.IsUnfollow,
			})
		} else if txn.TxnMeta.GetTxnType() == TxnTypeLike {
			txMeta := txn.TxnMeta.(*LikeMetadata)
			metadataLikes = append(metadataLikes, &MetadataLike{
				TransactionHash: txnHash,
				LikedPostHash:   txMeta.LikedPostHash,
				IsUnlike:        txMeta.IsUnlike,
			})
		} else if txn.TxnMeta.GetTxnType() == TxnTypeCreatorCoin {
			txMeta := txn.TxnMeta.(*CreatorCoinMetadataa)
			metadataCreatorCoins = append(metadataCreatorCoins, &MetadataCreatorCoin{
				TransactionHash:             txnHash,
				ProfilePublicKey:            txMeta.ProfilePublicKey,
				OperationType:               txMeta.OperationType,
				BitCloutToSellNanos:         txMeta.BitCloutToSellNanos,
				CreatorCoinToSellNanos:      txMeta.CreatorCoinToSellNanos,
				BitCloutToAddNanos:          txMeta.BitCloutToAddNanos,
				MinBitCloutExpectedNanos:    txMeta.MinBitCloutExpectedNanos,
				MinCreatorCoinExpectedNanos: txMeta.MinCreatorCoinExpectedNanos,
			})
		} else if txn.TxnMeta.GetTxnType() == TxnTypeCreatorCoinTransfer {
			txMeta := txn.TxnMeta.(*CreatorCoinTransferMetadataa)
			metadataCreatorCoinTransfers = append(metadataCreatorCoinTransfers, &MetadataCreatorCoinTransfer{
				TransactionHash:            txnHash,
				ProfilePublicKey:           txMeta.ProfilePublicKey,
				CreatorCoinToTransferNanos: txMeta.CreatorCoinToTransferNanos,
				ReceiverPublicKey:          txMeta.ReceiverPublicKey,
			})
		} else if txn.TxnMeta.GetTxnType() == TxnTypeSwapIdentity {
			txMeta := txn.TxnMeta.(*SwapIdentityMetadataa)
			metadataSwapIdentities = append(metadataSwapIdentities, &MetadataSwapIdentity{
				TransactionHash: txnHash,
				FromPublicKey:   txMeta.FromPublicKey,
				ToPublicKey:     txMeta.ToPublicKey,
			})
		} else {
			return fmt.Errorf("InsertTransactionTx: Unimplemented txn type %v", txn.TxnMeta.GetTxnType().String())
		}
	}

	if len(transactions) > 0 {
		if _, err := tx.Model(&transactions).Returning("NULL").Insert(); err != nil {
			return err
		}
	}

	if len(transactionOutputs) > 0 {
		if _, err := tx.Model(&transactionOutputs).Returning("NULL").OnConflict("(output_hash, output_index) DO UPDATE").Insert(); err != nil {
			return err
		}
	}

	if len(transactionInputs) > 0 {
		if _, err := tx.Model(&transactionInputs).WherePK().Column("input_hash", "input_index", "spent").Update(); err != nil {
			return err
		}
	}

	if len(metadataBlockRewards) > 0 {
		if _, err := tx.Model(&metadataBlockRewards).Returning("NULL").Insert(); err != nil {
			return err
		}
	}

	if len(metadataBitcoinExchanges) > 0 {
		if _, err := tx.Model(&metadataBitcoinExchanges).Returning("NULL").Insert(); err != nil {
			return err
		}
	}

	if len(metadataPrivateMessages) > 0 {
		if _, err := tx.Model(&metadataPrivateMessages).Returning("NULL").Insert(); err != nil {
			return err
		}
	}

	if len(metadataSubmitPosts) > 0 {
		if _, err := tx.Model(&metadataSubmitPosts).Returning("NULL").Insert(); err != nil {
			return err
		}
	}

	if len(metadataUpdateProfiles) > 0 {
		if _, err := tx.Model(&metadataUpdateProfiles).Returning("NULL").Insert(); err != nil {
			return err
		}
	}

	if len(metadataExchangeRates) > 0 {
		if _, err := tx.Model(&metadataExchangeRates).Returning("NULL").Insert(); err != nil {
			return err
		}
	}

	if len(metadataFollows) > 0 {
		if _, err := tx.Model(&metadataFollows).Returning("NULL").Insert(); err != nil {
			return err
		}
	}

	if len(metadataLikes) > 0 {
		if _, err := tx.Model(&metadataLikes).Returning("NULL").Insert(); err != nil {
			return err
		}
	}

	if len(metadataCreatorCoins) > 0 {
		if _, err := tx.Model(&metadataCreatorCoins).Returning("NULL").Insert(); err != nil {
			return err
		}
	}

	if len(metadataCreatorCoinTransfers) > 0 {
		if _, err := tx.Model(&metadataCreatorCoinTransfers).Returning("NULL").Insert(); err != nil {
			return err
		}
	}

	if len(metadataSwapIdentities) > 0 {
		if _, err := tx.Model(&metadataSwapIdentities).Returning("NULL").Insert(); err != nil {
			return err
		}
	}

	return nil
}

func (postgres *Postgres) UpsertBlockAndTransactions(blockNode *BlockNode, bitcloutBlock *MsgBitCloutBlock) error {
	return postgres.db.RunInTransaction(postgres.db.Context(), func(tx *pg.Tx) error {
		err := postgres.UpsertBlockTx(tx, blockNode)
		if err != nil {
			return err
		}

		blockHash := blockNode.Hash
		err = postgres.UpsertChainTx(tx, "main", blockHash)
		if err != nil {
			return err
		}

		err = postgres.InsertTransactionsTx(tx, bitcloutBlock.Txns, blockHash)
		if err != nil {
			return err
		}

		return nil
	})
}

func (postgres *Postgres) GetUtxoEntryForUtxoKey(utxoKey *UtxoKey) *UtxoEntry {
	utxo := &TransactionOutput{
		OutputHash:  &utxoKey.TxID,
		OutputIndex: utxoKey.Index,
		Spent:       false,
	}

	err := postgres.db.Model(utxo).WherePK().Select()
	if err != nil {
		return nil
	}

	return &UtxoEntry{
		PublicKey:   utxo.PublicKey,
		AmountNanos: utxo.AmountNanos,
		// TODO: Block height?
		UtxoType: utxo.OutputType,
		isSpent:  utxo.Spent,
		UtxoKey:  utxoKey,
	}
}

//
// BlockView Flushing
//

func (postgres *Postgres) FlushView(view *UtxoView) error {
	return postgres.db.RunInTransaction(postgres.db.Context(), func(tx *pg.Tx) error {
		if err := postgres.flushUtxos(tx, view); err != nil {
			return err
		}

		return nil
	})
}

func (postgres *Postgres) flushUtxos(tx *pg.Tx, view *UtxoView) error {
	var outputs []TransactionOutput
	for utxoKeyIter, utxoEntry := range view.UtxoKeyToUtxoEntry {
		// Make a copy of the iterator since it might change from under us.
		utxoKey := utxoKeyIter
		outputs = append(outputs, TransactionOutput{
			OutputHash:  &utxoKey.TxID,
			OutputIndex: utxoKey.Index,
			OutputType:  utxoEntry.UtxoType,
			PublicKey:   utxoEntry.PublicKey,
			AmountNanos: utxoEntry.AmountNanos,
			Spent:       utxoEntry.isSpent,
		})
	}

	result, err := tx.Model(&outputs).WherePK().OnConflict("(output_hash, output_index) DO NOTHING").Insert()
	if err != nil {
		return err
	}

	glog.Debugf("flushUtxos: %d mappings affected %d rows", len(view.UtxoKeyToUtxoEntry), result.RowsAffected())

	return nil
}

//
// Chain Init
//

func (postgres *Postgres) InitGenesisBlock(params *BitCloutParams, db *badger.DB) error {
	// Construct a node for the genesis block. Its height is zero and it has no parents. Its difficulty should be
	// set to the initial difficulty specified in the parameters and it should be assumed to be
	// valid and stored by the end of this function.
	genesisBlock := params.GenesisBlock
	diffTarget := NewBlockHash(params.MinDifficultyTargetHex)
	blockHash := NewBlockHash(params.GenesisBlockHashHex)
	genesisNode := NewBlockNode(
		nil,
		blockHash,
		0,
		diffTarget,
		BytesToBigint(ExpectedWorkForBlockHash(diffTarget)[:]),
		genesisBlock.Header,
		StatusHeaderValidated|StatusBlockProcessed|StatusBlockStored|StatusBlockValidated,
	)

	// Create the chain
	err := postgres.UpsertChain("main", blockHash)
	if err != nil {
		return fmt.Errorf("InitGenesisBlock: Error upserting chain: %v", err)
	}

	// Set the fields in the db to reflect the current state of our chain.
	//
	// Set the best hash to the genesis block in the db since its the only node
	// we're currently aware of. Set it for both the header chain and the block
	// chain.
	err = postgres.UpsertBlock(genesisNode)
	if err != nil {
		return fmt.Errorf("InitGenesisBlock: Error upserting block: %v", err)
	}

	for index, txOutput := range params.SeedBalances {
		_, err := postgres.db.Model(&TransactionOutput{
			OutputHash:  &BlockHash{},
			OutputIndex: uint32(index),
			OutputType:  UtxoTypeOutput,
			AmountNanos: txOutput.AmountNanos,
			PublicKey:   txOutput.PublicKey,
		}).Returning("NULL").Insert()
		if err != nil {
			return err
		}
	}

	return nil
}
