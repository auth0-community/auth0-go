package auth0

import (
	"errors"
	"time"

	jose "gopkg.in/square/go-jose.v2"
)

var (
	ErrNoKeyFound  = errors.New("no Keys has been found")
	ErrKeyExpired  = errors.New("key exists but is expired")

	// Configuring with MaxAgeNoCheck will skip key expiry check
	MaxAgeNoCheck  = time.Duration(-1)
	// Configuring with MaxSizeNoCheck will skip key cache size check
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

// NewMemoryKeyCacher creates a new Keycacher interface with option
// to set max age of cached keys and max size of the cache.
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

// Get obtains a key from the cache, and checks if the key is expired
func (mkc *memoryKeyCacher) Get(keyID string) (*jose.JSONWebKey, error) {
	searchKey, ok := mkc.entries[keyID]
	if ok {
		if mkc.maxAge == MaxAgeNoCheck || !mkc.keyIsExpired(keyID) {
			return &searchKey.JSONWebKey, nil
		}
		return nil, ErrKeyExpired
	}
	return nil, ErrNoKeyFound
}

// Add adds a key into the cache and handles overflow
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
			mkc.handleOverflow()
		}
		return &addingKey, nil
	}
	return nil, ErrNoKeyFound
}

// keyIsExpired deletes the key from cache if it is expired
func (mkc *memoryKeyCacher) keyIsExpired(keyID string) bool {
	if time.Now().After(mkc.entries[keyID].addedAt.Add(mkc.maxAge)) {
		delete(mkc.entries, keyID)
		return true
	}
	return false
}

// handleOverflow deletes the oldest key from the cache if overflowed
func (mkc *memoryKeyCacher) handleOverflow() {
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
