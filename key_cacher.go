package auth0

import (
	"errors"
	"time"

	jose "gopkg.in/square/go-jose.v2"
)

var (
	ErrNoKeyFound  = errors.New("no Keys has been found")
	ErrKeyExpired  = errors.New("key exists but is expired")
	MaxAgeNoCheck  = time.Duration(-1)
	MaxSizeNoCheck = -1
)

type KeyCacher interface {
	Get(keyID string) (*jose.JSONWebKey, error)
	Add(keyID string, webKeys []jose.JSONWebKey) (*jose.JSONWebKey, error)
}

type memoryKeyCacher struct {
	entries map[string]keyCacherEntry
	maxAge  time.Duration
	maxSize int
}

type keyCacherEntry struct {
	addedAt time.Time
	jose.JSONWebKey
}

func NewMemoryKeyCacher(maxAge time.Duration, maxSize int) KeyCacher {
	return &memoryKeyCacher{
		entries: map[string]keyCacherEntry{},
		maxAge:  maxAge,
		maxSize: maxSize,
	}
}

func newMemoryPersistentKeyCacher() KeyCacher {
	return &memoryKeyCacher{
		entries: map[string]keyCacherEntry{},
		maxAge:  MaxAgeNoCheck,
		maxSize: MaxSizeNoCheck,
	}
}

func (mkc *memoryKeyCacher) Get(keyID string) (*jose.JSONWebKey, error) {
	searchKey, ok := mkc.entries[keyID]
	if ok {
		if mkc.maxAge == MaxAgeNoCheck || !isExpired(mkc, keyID) {
			return &searchKey.JSONWebKey, nil
		}
		return nil, ErrKeyExpired
	}
	return nil, ErrNoKeyFound
}

func (mkc *memoryKeyCacher) Add(keyID string, downloadedKeys []jose.JSONWebKey) (*jose.JSONWebKey, error) {
	var addingKey jose.JSONWebKey

	for _, key := range downloadedKeys {
		if key.KeyID == keyID {
			addingKey = key
		}
		if mkc.maxSize == -1 {
			mkc.entries[key.KeyID] = keyCacherEntry{
				addedAt:    time.Now(),
				JSONWebKey: key,
			}
		}
	}
	if addingKey.Key != nil {
		if mkc.maxSize != -1 {
			mkc.entries[addingKey.KeyID] = keyCacherEntry{
				addedAt:    time.Now(),
				JSONWebKey: addingKey,
			}
			handleOverflow(mkc)
		}
		return &addingKey, nil
	}
	return nil, ErrNoKeyFound
}

func isExpired(mkc *memoryKeyCacher, keyID string) bool {
	if time.Now().After(mkc.entries[keyID].addedAt.Add(mkc.maxAge)) {
		delete(mkc.entries, keyID)
		return true
	}
	return false
}

//delete oldest element if overflowed
func handleOverflow(mkc *memoryKeyCacher) {
	if mkc.maxSize < len(mkc.entries) {
		var oldestEntryKeyID string
		var latestAddedTime = time.Now()
		for entryKeyID, entry := range mkc.entries {
			if entry.addedAt.Before(latestAddedTime) {
				latestAddedTime = entry.addedAt
				oldestEntryKeyID = entryKeyID
			}
		}
		delete(mkc.entries, oldestEntryKeyID)
	}
}
