package auth0

import (
	"testing"
	"time"

	"gopkg.in/square/go-jose.v2"

	"github.com/stretchr/testify/assert"
)

func TestPersistentKeyCacherGettingKey(t *testing.T) {
	mpkc := newMemoryPersistentKeyCacher()
	webKey, exist := mpkc.Get("key")
	assert.Empty(t, webKey)
	assert.False(t, exist)
}

func TestPersistentKeyCacherAddingKey(t *testing.T) {
	mpkc := newMemoryPersistentKeyCacher()
	downloadedKeys := []jose.JSONWebKey{{KeyID: "test1"}, {KeyID: "test2"}, {KeyID: "test3"}}
	webKey, exist := mpkc.Add("test1", downloadedKeys)
	assert.Equal(t, webKey.KeyID, "test1")
	assert.True(t, exist)
}

func TestPersistentKeyCacherAddingInvalidKey(t *testing.T) {
	mpkc := newMemoryPersistentKeyCacher()
	downloadedKeys := []jose.JSONWebKey{{KeyID: "test1"}, {KeyID: "test2"}, {KeyID: "test3"}}
	webKey, exist := mpkc.Add("invalidKey", downloadedKeys)
	assert.Empty(t, webKey)
	assert.False(t, exist)
}

func TestKeyCacherWithZeroSizeGettingKey(t *testing.T) {
	mkc := NewMemoryKeyCacher(0, 0)
	webKey, exist := mkc.Get("key")
	assert.Empty(t, webKey)
	assert.False(t, exist)
}

func TestKeyCacherWithZeroSizeAddingKey(t *testing.T) {
	mkc := NewMemoryKeyCacher(0, 0)
	downloadedKeys := []jose.JSONWebKey{{KeyID: "test1"}, {KeyID: "test2"}, {KeyID: "test3"}}
	addedKey, success := mkc.Add("test1", downloadedKeys)
	assert.NotEmpty(t, addedKey)
	assert.True(t, success)
}

func TestKeyCacherWithSpecificSizeGettingKey(t *testing.T) {
	mkc := NewMemoryKeyCacher(600, 3)
	downloadedKeys := []jose.JSONWebKey{{KeyID: "test1"}, {KeyID: "test2"}, {KeyID: "test3"}}
	mkc.Add("test1", downloadedKeys)
	webKey, exist := mkc.Get("test1")
	assert.Equal(t, webKey.KeyID, "test1")
	assert.True(t, exist)
}

func TestKeyCacherWithSpecificSizeGettingExpiredKey(t *testing.T) {
	entry := make(map[string]keyCacherEntry)
	entry["key"] = keyCacherEntry{
		addedAt:    time.Now().Add(time.Second * -700),
		JSONWebKey: jose.JSONWebKey{KeyID: "test1"},
	}
	mkc := &memoryKeyCacher{entry, 600, 3}
	webKey, exist := mkc.Get("key")
	assert.Empty(t, webKey)
	assert.False(t, exist)
}

func TestKeyCacherWithSpecificSizeDeletingOldKeyAndAddingKey(t *testing.T) {
	mkc := NewMemoryKeyCacher(600, 2)
	downloadedKeys := []jose.JSONWebKey{{KeyID: "test1"}, {KeyID: "test2"}, {KeyID: "test3"}}
	mkc.Add("test1", downloadedKeys)
	mkc.Add("test2", downloadedKeys)
	addedKey, success := mkc.Add("test3", downloadedKeys)
	assert.Equal(t, addedKey.KeyID, "test3")
	assert.True(t, success)
}
