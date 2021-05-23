package oauth2gorm

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/jinzhu/gorm"
	"gopkg.in/oauth2.v3"
	"gopkg.in/oauth2.v3/models"
)

type TokenStore struct {
	db *gorm.DB

	tableName         string
	initTableDisabled bool
	gcDisabled        bool
	gcInterval        time.Duration

	ticker *time.Ticker
}

type tokenStoreItem struct {
	ID        int64  `gorm:"primary_key;auto_increment"`
	ExpiredAt int64  `gorm:"index;not null"`
	Code      string `gorm:"index;size:255;not null"`
	Access    string `gorm:"index;size:3072;not null"`
	Refresh   string `gorm:"index;size:1024;not null"`
	Data      string `gorm:"size:-1"`
}

// NewTokenStore creates token store instance
func NewTokenStore(db *gorm.DB, options ...TokenStoreOption) (*TokenStore, error) {
	store := &TokenStore{
		db:         db,
		tableName:  "oauth2_tokens",
		gcInterval: 10 * time.Minute,
	}

	for _, option := range options {
		option(store)
	}

	if !store.initTableDisabled {
		if err := db.Table(store.tableName).AutoMigrate(&tokenStoreItem{}).Error; err != nil {
			return nil, err
		}
	}

	if !store.gcDisabled {
		store.ticker = time.NewTicker(store.gcInterval)
		go store.gc()
	}

	return store, nil
}

// Close close the store
func (s *TokenStore) Close() error {
	if !s.gcDisabled {
		s.ticker.Stop()
	}
	return nil
}

func (s *TokenStore) gc() {
	for range s.ticker.C {
		s.clean()
	}
}

func (s *TokenStore) clean() {
	now := time.Now().Unix()

	query1 := "expired_at <= ?"
	query2 := "code = '' AND access = '' AND refresh = ''"

	var err error
	var count int64
	err = s.db.Table(s.tableName).Where(query1, now).Or(query2).Count(&count).Error
	if err != nil || count == 0 {
		if err != nil {
			log.Println(err.Error())
		}
		return
	}

	err = s.db.Table(s.tableName).Unscoped().Where(query1, now).Or(query2).Delete(&tokenStoreItem{}).Error
	if err != nil {
		log.Println(err.Error())
	}
}

// Create create and store the new token information
func (s *TokenStore) Create(info oauth2.TokenInfo) error {
	data, err := json.Marshal(info)
	if err != nil {
		return err
	}

	item := &tokenStoreItem{
		Data: string(data),
	}

	if code := info.GetCode(); code != "" {
		item.Code = code
		item.ExpiredAt = info.GetCodeCreateAt().Add(info.GetCodeExpiresIn()).Unix()
	} else {
		item.Access = info.GetAccess()
		item.ExpiredAt = info.GetAccessCreateAt().Add(info.GetAccessExpiresIn()).Unix()

		if refresh := info.GetRefresh(); refresh != "" {
			item.Refresh = info.GetRefresh()
			item.ExpiredAt = info.GetRefreshCreateAt().Add(info.GetRefreshExpiresIn()).Unix()
		}
	}

	return s.db.Table(s.tableName).Create(item).Error
}

func (s *TokenStore) removeBy(key string, value string) error {
	query := fmt.Sprintf("%s = ?", key)
	// err := s.db.Table(s.tableName).Unscoped().Where(query, value).Delete(&tokenStoreItem{}).Error
	err := s.db.Table(s.tableName).Where(query, value).Update(key, "").Error
	if err != nil && err == gorm.ErrRecordNotFound {
		return nil
	}
	return err
}

// RemoveByCode delete the authorization code
func (s *TokenStore) RemoveByCode(code string) error {
	return s.removeBy("code", code)
}

// RemoveByAccess use the access token to delete the token information
func (s *TokenStore) RemoveByAccess(access string) error {
	return s.removeBy("access", access)
}

// RemoveByRefresh use the refresh token to delete the token information
func (s *TokenStore) RemoveByRefresh(refresh string) error {
	return s.removeBy("refresh", refresh)
}

func (s *TokenStore) toTokenInfo(data string) (oauth2.TokenInfo, error) {
	var ti models.Token
	err := json.Unmarshal([]byte(data), &ti)
	if err != nil {
		return nil, err
	}
	return &ti, nil
}

func (s *TokenStore) getBy(key string, value string) (oauth2.TokenInfo, error) {
	if value == "" {
		return nil, nil
	}

	query := fmt.Sprintf("%s = ?", key)

	var item tokenStoreItem
	err := s.db.Table(s.tableName).Where(query, value).First(&item).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}

	return s.toTokenInfo(item.Data)
}

// GetByCode use the authorization code for token information data
func (s *TokenStore) GetByCode(code string) (oauth2.TokenInfo, error) {
	return s.getBy("code", code)
}

// GetByAccess use the access token for token information data
func (s *TokenStore) GetByAccess(access string) (oauth2.TokenInfo, error) {
	return s.getBy("access", access)
}

// GetByRefresh use the refresh token for token information data
func (s *TokenStore) GetByRefresh(refresh string) (oauth2.TokenInfo, error) {
	return s.getBy("refresh", refresh)
}
