package lib

import (
	"encoding/hex"
	"fmt"
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

	return &Postgres{
		db: pg.Connect(options),
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

// TransactionOutput represents BitCloutOutput and UtxoEntry
type TransactionOutput struct {
	OutputHash  *BlockHash `pg:",pk"`
	OutputIndex uint32     `pg:",pk,use_zero"`
	OutputType  UtxoType   `pg:",use_zero"`
	PublicKey   []byte
	AmountNanos uint64     `pg:",use_zero"`
	Spent       bool       `pg:",use_zero"`
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
	IsHidden                 bool `pg:",use_zero"`
}

// MetadataUpdateBitcoinUSDExchangeRate represents UpdateBitcoinUSDExchangeRateMetadataa
type MetadataUpdateBitcoinUSDExchangeRate struct {
	ID                 uint64
	USDCentsPerBitcoin uint64 `pg:",use_zero"`
}

// MetadataUpdateProfile represents UpdateProfileMetadata
type MetadataUpdateProfile struct {
	ID                          uint64
	ProfilePublicKey            []byte
	NewUsername                 []byte
	NewDescription              []byte
	NewProfilePic               []byte
	NewCreatorBasisPoints       uint64 `pg:",use_zero"`
}

// MetadataFollow represents FollowMetadata
type MetadataFollow struct {
	ID                uint64
	FollowedPublicKey []byte
	IsUnfollow        bool `pg:",use_zero"`
}

// MetadataLike represents LikeMetadata
type MetadataLike struct {
	ID            uint64
	LikedPostHash *BlockHash
	IsUnlike      bool `pg:",use_zero"`
}

// MetadataCreatorCoin represents CreatorCoinMetadataa
type MetadataCreatorCoin struct {
	ID                          uint64
	ProfilePublicKey            []byte
	OperationType               CreatorCoinOperationType `pg:",use_zero"`
	BitCloutToSellNanos         uint64 `pg:",use_zero"`
	CreatorCoinToSellNanos      uint64 `pg:",use_zero"`
	BitCloutToAddNanos          uint64 `pg:",use_zero"`
	MinBitCloutExpectedNanos    uint64 `pg:",use_zero"`
	MinCreatorCoinExpectedNanos uint64 `pg:",use_zero"`
}

// MetadataCreatorCoinTransfer represents CreatorCoinTransferMetadataa
type MetadataCreatorCoinTransfer struct {
	ID                         uint64
	ProfilePublicKey           []byte
	CreatorCoinToTransferNanos uint64 `pg:",use_zero"`
	ReceiverPublicKey          []byte
}

// MetadataSwapIdentity represents SwapIdentityMetadataa
type MetadataSwapIdentity struct {
	ID            uint64
	FromPublicKey []byte
	ToPublicKey   []byte
}

func (postgres *Postgres) UpsertBlock(blockNode *BlockNode) error {
	return postgres.db.RunInTransaction(postgres.db.Context(), func(tx *pg.Tx) error {
		return postgres.UpsertBlockTx(tx, blockNode)
	})
}

func (postgres *Postgres) UpsertBlockTx(tx *pg.Tx, blockNode *BlockNode) error {
	block := &Block{
		Hash:       blockNode.Hash,
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

	// The genesis block has a nil parent
	if blockNode.Parent != nil {
		block.ParentHash = blockNode.Parent.Hash
	}

	_, err := tx.Model(block).WherePK().OnConflict("(hash) DO UPDATE").Insert()
	return err
}

func (postgres *Postgres) GetBlockIndex() (map[BlockHash]*BlockNode, error) {
	glog.Info("Getting block index")
	var blocks []Block
	err := postgres.db.Model(&blocks).Select()
	if err != nil {
		return nil, err
	}

	blockMap := make(map[BlockHash]*BlockNode)
	for _, block := range blocks {
		blockMap[*block.Hash] = &BlockNode{
			Hash: block.Hash,
			Height: uint32(block.Height),
			DifficultyTarget: block.DifficultyTarget,
			CumWork: HashToBigint(block.CumWork),
			Header: &MsgBitCloutHeader{
				Version: block.Version,
				PrevBlockHash: block.ParentHash,
				TransactionMerkleRoot: block.TxMerkleRoot,
				TstampSecs: block.Timestamp,
				Height: block.Height,
				Nonce: block.Nonce,
				ExtraNonce: block.ExtraNonce,
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

//
// Chain
//

func (postgres *Postgres) GetChain(name string) *Chain {
	chain := &Chain{
		Name: name,
	}

	err :=postgres.db.Model(chain).First()
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

func (postgres *Postgres) InsertTransactionTx(tx *pg.Tx, txn *MsgBitCloutTxn, blockHash *BlockHash) error {
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

	_, err := tx.Model(transaction).Returning("NULL").Insert()
	if err != nil {
		return err
	}

	for _, input := range txn.TxInputs {
		transactionInput := &TransactionInput{
			OutputHash: txnHash,
			InputHash:  &input.TxID,
			InputIndex: input.Index,
		}

		_, err = tx.Model(transactionInput).Returning("NULL").Insert()
		if err != nil {
			return err
		}
	}

	for i, output := range txn.TxOutputs {
		transactionOutput := &TransactionOutput{
			OutputHash:  txnHash,
			OutputIndex: uint32(i),
			OutputType:  0, // TODO
			PublicKey:   output.PublicKey,
			AmountNanos: output.AmountNanos,
		}

		glog.Infof("Insert %s:%d", txnHash, uint32(i))

		_, err = tx.Model(transactionOutput).Returning("NULL").Insert()
		if err != nil {
			return err
		}
	}

	if txn.TxnMeta.GetTxnType() == TxnTypeBasicTransfer || txn.TxnMeta.GetTxnType() == TxnTypeUpdateGlobalParams {
		// No extra metadata needed
	} else if txn.TxnMeta.GetTxnType() == TxnTypeBlockReward {
		txMeta := txn.TxnMeta.(*BlockRewardMetadataa)
		_, err = tx.Model(&MetadataBlockReward{
			ExtraData: txMeta.ExtraData,
		}).Returning("NULL").Insert()
	} else if txn.TxnMeta.GetTxnType() == TxnTypeBitcoinExchange {
		txMeta := txn.TxnMeta.(*BitcoinExchangeMetadata)
		_, err = tx.Model(&MetadataBitcoinExchange{
			BitcoinBlockHash:  txMeta.BitcoinBlockHash,
			BitcoinMerkleRoot: txMeta.BitcoinMerkleRoot,
		}).Returning("NULL").Insert()
	} else if txn.TxnMeta.GetTxnType() == TxnTypePrivateMessage {
		txMeta := txn.TxnMeta.(*PrivateMessageMetadata)
		_, err = tx.Model(&MetadataPrivateMessage{
			RecipientPublicKey: txMeta.RecipientPublicKey,
			EncryptedText:      txMeta.EncryptedText,
			TimestampNanos:     txMeta.TimestampNanos,
		}).Returning("NULL").Insert()
	} else if txn.TxnMeta.GetTxnType() == TxnTypeSubmitPost {
		txMeta := txn.TxnMeta.(*SubmitPostMetadata)
		_, err = tx.Model(&MetadataSubmitPost{
			PostHashToModify:         txMeta.PostHashToModify,
			ParentStakeID:            txMeta.ParentStakeID,
			Body:                     txMeta.Body,
			TimestampNanos:           txMeta.TimestampNanos,
			IsHidden:                 txMeta.IsHidden,
		}).Returning("NULL").Insert()
	} else if txn.TxnMeta.GetTxnType() == TxnTypeUpdateProfile {
		txMeta := txn.TxnMeta.(*UpdateProfileMetadata)
		_, err = tx.Model(&MetadataUpdateProfile{
			ProfilePublicKey:            txMeta.ProfilePublicKey,
			NewUsername:                 txMeta.NewUsername,
			NewProfilePic:               txMeta.NewProfilePic,
			NewCreatorBasisPoints:       txMeta.NewCreatorBasisPoints,
		}).Returning("NULL").Insert()
	} else if txn.TxnMeta.GetTxnType() == TxnTypeUpdateBitcoinUSDExchangeRate {
		txMeta := txn.TxnMeta.(*UpdateBitcoinUSDExchangeRateMetadataa)
		_, err = tx.Model(&MetadataUpdateBitcoinUSDExchangeRate{
			USDCentsPerBitcoin: txMeta.USDCentsPerBitcoin,
		}).Returning("NULL").Insert()
	} else if txn.TxnMeta.GetTxnType() == TxnTypeFollow {
		txMeta := txn.TxnMeta.(*FollowMetadata)
		_, err = tx.Model(&MetadataFollow{
			FollowedPublicKey: txMeta.FollowedPublicKey,
			IsUnfollow: txMeta.IsUnfollow,
		}).Returning("NULL").Insert()
	} else if txn.TxnMeta.GetTxnType() == TxnTypeLike {
		txMeta := txn.TxnMeta.(*LikeMetadata)
		_, err = tx.Model(&MetadataLike{
			LikedPostHash: txMeta.LikedPostHash,
			IsUnlike: txMeta.IsUnlike,
		}).Returning("NULL").Insert()
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
		}).Returning("NULL").Insert()
	} else if txn.TxnMeta.GetTxnType() == TxnTypeCreatorCoinTransfer {
		txMeta := txn.TxnMeta.(*CreatorCoinTransferMetadataa)
		_, err = tx.Model(&MetadataCreatorCoinTransfer{
			ProfilePublicKey: txMeta.ProfilePublicKey,
			CreatorCoinToTransferNanos: txMeta.CreatorCoinToTransferNanos,
			ReceiverPublicKey: txMeta.ReceiverPublicKey,
		}).Returning("NULL").Insert()
	} else if txn.TxnMeta.GetTxnType() == TxnTypeSwapIdentity {
		txMeta := txn.TxnMeta.(*SwapIdentityMetadataa)
		_, err = tx.Model(&MetadataSwapIdentity{
			FromPublicKey: txMeta.FromPublicKey,
			ToPublicKey: txMeta.ToPublicKey,
		}).Returning("NULL").Insert()
	} else {
		err = fmt.Errorf("InsertTransactionTx: Unimplemented txn type %v", txn.TxnMeta.GetTxnType().String())
	}

	return err
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

		for _, txn := range bitcloutBlock.Txns {
			err := postgres.InsertTransactionTx(tx, txn, blockHash)
			if err != nil {
				return err
			}
		}

		return nil
	})
}

func (postgres *Postgres) GetUtxoEntryForUtxoKey(utxoKey *UtxoKey) *UtxoEntry {
	utxo := &TransactionOutput{
		OutputHash: &utxoKey.TxID,
		OutputIndex: utxoKey.Index,
		Spent: false,
	}

	err := postgres.db.Model(utxo).WherePK().Select()
	if err != nil {
		return nil
	}

	return &UtxoEntry {
		PublicKey: utxo.PublicKey,
		AmountNanos: utxo.AmountNanos,
		// TODO: Block height?
		UtxoType: utxo.OutputType,
		isSpent: utxo.Spent,
		UtxoKey: utxoKey,
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
	glog.Infof("flushUtxos: flushing %d mappings", len(view.UtxoKeyToUtxoEntry))

	var outputs []TransactionOutput
	for utxoKeyIter, utxoEntry := range view.UtxoKeyToUtxoEntry {
		// Make a copy of the iterator since it might change from under us.
		utxoKey := utxoKeyIter
		outputs = append(outputs, TransactionOutput{
			OutputHash: &utxoKey.TxID,
			OutputIndex: utxoKey.Index,
			PublicKey: utxoEntry.PublicKey,
			AmountNanos: utxoEntry.AmountNanos,
			Spent: utxoEntry.isSpent,
		})
	}

	result, err := tx.Model(&outputs).WherePK().OnConflict("(output_hash, output_index) DO UPDATE").Insert()
	if err != nil {
		return err
	}

	glog.Infof("flushUtxos: %d mappings affected %d rows", len(view.UtxoKeyToUtxoEntry), result.RowsAffected())

	return nil
}

//
// Chain Init
//

func (postgres *Postgres) InitGenesisBlock(params *BitCloutParams) error {
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

	// We apply seed transactions here. This step is useful for setting
	// up the blockchain with a particular set of transactions, e.g. when
	// hard forking the chain.
	utxoView, err := NewUtxoView(nil, params, nil, postgres)
	if err != nil {
		return fmt.Errorf("InitGenesisBlock: Error initializing UtxoView")
	}

	// Add the seed balances to the view.
	for index, txOutput := range params.SeedBalances {
		outputKey := UtxoKey{
			TxID:  BlockHash{},
			Index: uint32(index),
		}
		utxoEntry := UtxoEntry{
			AmountNanos: txOutput.AmountNanos,
			PublicKey:   txOutput.PublicKey,
			BlockHeight: 0,
			UtxoType: UtxoTypeOutput,
			UtxoKey:  &outputKey,
		}

		_, err := utxoView._addUtxo(&utxoEntry)
		if err != nil {
			return fmt.Errorf("InitGenesisBlock: Error adding seed balance: %v", err)
		}
	}

	// Add the seed txns to the view
	for _, txnHex := range params.SeedTxns {
		txnBytes, err := hex.DecodeString(txnHex)
		if err != nil {
			return fmt.Errorf("InitGenesisBlock: Error decoding seed: %v", err)
		}

		txn := &MsgBitCloutTxn{}
		if err := txn.FromBytes(txnBytes); err != nil {
			return fmt.Errorf("InitGenesisBlock: Error decoding seed: %v", err)
		}

		// Important: ignoreUtxos makes it so that the inputs/outputs aren't processed, which is important.
		// Set txnSizeBytes to 0 here as the minimum network fee is 0 at genesis block, so there is no need to serialize
		// these transactions to check if they meet the minimum network fee requirement.
		_, _, _, _, err = utxoView.ConnectTransaction(txn, txn.Hash(), 0, 0, false, true)
		if err != nil {
			return fmt.Errorf("InitGenesisBlock: Error connecting transaction: %v: ", err)
		}
	}

	// Flush all the data in the view.
	err = utxoView.FlushToDb()
	if err != nil {
		return fmt.Errorf("InitGenesisBlock: Error flushing seed txns to DB: %v", err)
	}

	return nil
}
