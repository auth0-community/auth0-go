package auth0

import (
	"time"

	jose "gopkg.in/square/go-jose.v2"
)

type KeyCacher interface {
	Get(keyID string) (jose.JSONWebKey, bool)
	Add(keyID string, webKeys []jose.JSONWebKey) (jose.JSONWebKey, bool)
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

func (mkc *memoryKeyCacher) Get(keyID string) (jose.JSONWebKey, bool) {
	if mkc.size == -1 {
		searchKey, exist := mkc.entries[keyID]
		return searchKey.JSONWebKey, exist
	}
	if mkc.size == 0 {
		return jose.JSONWebKey{}, false
	}
	searchKey, exist := mkc.entries[keyID]
	if exist {
		expiringTime := mkc.entries[keyID].addedAt.Add(time.Second * time.Duration(mkc.maxAge))
		expired := time.Now().After(expiringTime)
		if expired {
			delete(mkc.entries, keyID)
			return jose.JSONWebKey{}, false
		}
	}
	return searchKey.JSONWebKey, exist
}

func (mkc *memoryKeyCacher) Add(keyID string, downloadedKeys []jose.JSONWebKey) (jose.JSONWebKey, bool) {

	addedKey, success := jose.JSONWebKey{}, false

	if mkc.size == -1 {
		for _, key := range downloadedKeys {
			mkc.entries[key.KeyID] = keyCacherEntry{time.Now(), key}

			if key.KeyID == keyID {
				addedKey = key
				success = true
			}
		}
	} else {
		for _, key := range downloadedKeys {
			if key.KeyID == keyID {
				addedKey = key
				success = true
			}
		}
		if success && mkc.size != 0 {
			if mkc.size-len(mkc.entries) < 1 {
				//delete oldest element and store new in
				var oldestEntryKeyID string
				var latestAddedTime = time.Now()
				for entryKeyID, entry := range mkc.entries {
					if entry.addedAt.Before(latestAddedTime) {
						latestAddedTime = entry.addedAt
						oldestEntryKeyID = entryKeyID
					}
				}
				delete(mkc.entries, oldestEntryKeyID)
				mkc.entries[addedKey.KeyID] = keyCacherEntry{time.Now(), addedKey}
			} else {
				mkc.entries[addedKey.KeyID] = keyCacherEntry{time.Now(), addedKey}
			}
		}

	}
	return addedKey, success
}
