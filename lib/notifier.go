package lib

import (
	"fmt"
	"github.com/dgraph-io/badger/v3"
	"github.com/go-pg/pg/v10"
	"reflect"
	"time"

	"github.com/golang/glog"
)

type Notifier struct {
	coreChain *Blockchain
	postgres  *Postgres

	// Shortcut to postgres.db
	db *pg.DB

	// Shortcut to coreChain.db
	badger *badger.DB
}

func NewNotifier(coreChain *Blockchain, postgres *Postgres) *Notifier {
	return &Notifier{
		coreChain: coreChain,
		postgres:  postgres,
		db:        postgres.db,
		badger:    coreChain.db,
	}
}

func (notifier *Notifier) Update() error {
	var blocks []*Block
	err := notifier.db.Model(&blocks).Where("notified = false").Limit(10_000).Select()
	if err != nil {
		return err
	}

	for _, block := range blocks {
		var notifications []*Notification
		var transactions []*Transaction
		err = notifier.db.Model(&transactions).Where("block_hash = ?", block.Hash).
			Relation("Outputs").Relation("MetadataLike").Relation("MetadataFollow").Select()
		if err != nil {
			return err
		}

		glog.Infof("Notifier: Found %d transactions in block %v at height %d", len(transactions), block.Hash, block.Height)

		for _, transaction := range transactions {
			if transaction.Type == TxnTypeBasicTransfer {
				for _, output := range transaction.Outputs {
					if !reflect.DeepEqual(output.PublicKey, transaction.PublicKey) {
						notifications = append(notifications, &Notification{
							Transaction: transaction.Hash,
							Mined:       true,
							ToUser:      output.PublicKey,
							FromUser:    transaction.PublicKey,
							Action:      "SendClout",
							Amount:      output.AmountNanos,
							Timestamp:   block.Timestamp,
						})
					}
				}
			} else if transaction.Type == TxnTypeLike {
				postHash := transaction.MetadataLike.LikedPostHash
				post := DBGetPostEntryByPostHash(notifier.badger, postHash)
				if post != nil {
					notifications = append(notifications, &Notification{
						Transaction: transaction.Hash,
						Mined:       true,
						ToUser:      post.PosterPublicKey,
						FromUser:    transaction.PublicKey,
						Action:      "Like",
						PostHash:    postHash,
						Timestamp:   block.Timestamp,
					})
				}
			} else if transaction.Type == TxnTypeFollow {
				if !transaction.MetadataFollow.IsUnfollow {
					notifications = append(notifications, &Notification{
						Transaction: transaction.Hash,
						Mined:       true,
						ToUser:      transaction.MetadataFollow.FollowedPublicKey,
						FromUser:    transaction.PublicKey,
						Action:      "Follow",
						Timestamp:   block.Timestamp,
					})
				}
			}
		}

		// Insert the new notifications if we created any
		if len(notifications) > 0 {
			_, err = notifier.db.Model(&notifications).OnConflict("DO NOTHING").Returning("NULL").Insert()
			if err != nil {
				return err
			}
		}

		// Mark the block as notified
		block.Notified = true
		_, err = notifier.db.Model(block).WherePK().Column("notified").Returning("NULL").Update()
		if err != nil {
			return err
		}
	}

	return nil
}

func (notifier *Notifier) notifyBasicTransfers() {

}

func (notifier *Notifier) Start() {
	glog.Info("Notifier: Starting update thread")

	// Run a loop to continuously process notifications
	go func() {
		for {
			//if notifier.coreChain.ChainState() == SyncStateFullyCurrent {
			//	// If the node is fully synced, then try an update.
			//	err := notifier.Update()
			//	if err != nil {
			//		glog.Error(fmt.Errorf("Notifier: Problem running update: %v", err))
			//	}
			//} else {
			//	glog.Debugf("Notifier: Waiting for node to sync before updating")
			//}

			err := notifier.Update()
			if err != nil {
				glog.Error(fmt.Errorf("Notifier: Problem running update: %v", err))
			}
			time.Sleep(1 * time.Second)
		}
	}()

}
