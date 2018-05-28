package auth0

import (
	"errors"
	"time"

	jose "gopkg.in/square/go-jose.v2"
)

var (
	ErrNoKeyFound = errors.New("No Keys has been found")
	ErrKeyExpired = errors.New("Key exists but is expired")
)

type KeyCacher interface {
	Get(keyID string) (jose.JSONWebKey, error)
	Add(keyID string, webKeys []jose.JSONWebKey) (jose.JSONWebKey, error)
}

type memoryKeyCacher struct {
	entries map[string]keyCacherEntry
	maxAge  int
	size    int
}

type keyCacherEntry struct {
	addedAt time.Time
	jose.JSONWebKey
}

func NewMemoryKeyCacher(maxAge int, size int) KeyCacher {
	return &memoryKeyCacher{
		entries: map[string]keyCacherEntry{},
		maxAge:  maxAge,
		size:    size,
	}
}

func newMemoryPersistentKeyCacher() KeyCacher {
	return &memoryKeyCacher{
		entries: map[string]keyCacherEntry{},
		maxAge:  -1,
		size:    -1,
	}
}

func (mkc *memoryKeyCacher) Get(keyID string) (jose.JSONWebKey, error) {
	if mkc.size == 0 {
		return jose.JSONWebKey{}, ErrNoKeyFound
	}

	searchKey, exist := mkc.entries[keyID]

	if exist {
		if mkc.size == -1 {
			return searchKey.JSONWebKey, nil
		}

		expiringTime := mkc.entries[keyID].addedAt.Add(time.Second * time.Duration(mkc.maxAge))
		expired := time.Now().After(expiringTime)
		if expired {
			delete(mkc.entries, keyID)
			return jose.JSONWebKey{}, ErrKeyExpired
		}
		return searchKey.JSONWebKey, nil
	}
	return searchKey.JSONWebKey, ErrNoKeyFound
}

func (mkc *memoryKeyCacher) Add(keyID string, downloadedKeys []jose.JSONWebKey) (jose.JSONWebKey, error) {
	addingKey, success := jose.JSONWebKey{}, false

	for _, key := range downloadedKeys {

		if key.KeyID == keyID {
			addingKey = key
			success = true
		}

		if mkc.size == -1 {
			mkc.entries[key.KeyID] = keyCacherEntry{
				addedAt:    time.Now(),
				JSONWebKey: key,
			}
		}
	}
	if success {
		if mkc.size != 0 {
			mkc.entries[addingKey.KeyID] = keyCacherEntry{
				addedAt:    time.Now(),
				JSONWebKey: addingKey,
			}
			if mkc.size < len(mkc.entries) {
				mkc.replaceEntry(addingKey)
			}
		}
		return addingKey, nil
	}
	return addingKey, ErrNoKeyFound
}

//delete oldest element and store new in
func (mkc *memoryKeyCacher) replaceEntry(newKey jose.JSONWebKey) {
	var oldestEntryKeyID string
	var latestAddedTime = time.Now()
	for entryKeyID, entry := range mkc.entries {
		if entry.addedAt.Before(latestAddedTime) {
			latestAddedTime = entry.addedAt
			oldestEntryKeyID = entryKeyID
		}
	}
	delete(mkc.entries, oldestEntryKeyID)
	mkc.entries[newKey.KeyID] = keyCacherEntry{time.Now(), newKey}
}
