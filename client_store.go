package oauth2gorm

import (
	"encoding/json"

	"github.com/jinzhu/gorm"
	"gopkg.in/oauth2.v3"
	"gopkg.in/oauth2.v3/models"
)

type ClientStore struct {
	db *gorm.DB

	tableName         string
	initTableDisabled bool
}

type clientStoreItem struct {
	ID     string `gorm:"primary_key;size:255"`
	Secret string `gorm:"size:255;not null"`
	Domain string `gorm:"size:255;not null"`
	Data   string `gorm:"size:1024"`
}

// NewClientStore creates client store instance
func NewClientStore(db *gorm.DB, options ...ClientStoreOption) (*ClientStore, error) {
	store := &ClientStore{
		db:        db,
		tableName: "oauth2_clients",
	}

	for _, option := range options {
		option(store)
	}

	if !store.initTableDisabled {
		if err := db.Table(store.tableName).AutoMigrate(&clientStoreItem{}).Error; err != nil {
			return nil, err
		}
	}

	return store, nil
}

func (s *ClientStore) toClientInfo(data string) (oauth2.ClientInfo, error) {
	var ci models.Client
	err := json.Unmarshal([]byte(data), &ci)
	if err != nil {
		return nil, err
	}
	return &ci, nil
}

// GetByID retrieves and returns client information by id
func (s *ClientStore) GetByID(id string) (oauth2.ClientInfo, error) {
	if id == "" {
		return nil, nil
	}

	var item clientStoreItem
	err := s.db.Table(s.tableName).Where("id = ?", id).First(&item).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}

	return s.toClientInfo(item.Data)
}

// Create creates and stores the new client information
func (s *ClientStore) Create(info oauth2.ClientInfo) error {
	data, err := json.Marshal(info)
	if err != nil {
		return err
	}

	item := &clientStoreItem{
		ID:     info.GetID(),
		Secret: info.GetSecret(),
		Domain: info.GetDomain(),
		Data:   string(data),
	}

	return s.db.Table(s.tableName).Create(item).Error
}
