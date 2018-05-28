package auth0

import (
	"testing"
	"time"

	"gopkg.in/square/go-jose.v2"

	"github.com/stretchr/testify/assert"
)

func TestPersistentKeyCacherGettingKey(t *testing.T) {
	mpkc := newMemoryPersistentKeyCacher()
	webKey, err := mpkc.Get("key")
	assert.Empty(t, webKey)
	assert.Error(t, err)
}

func TestPersistentKeyCacherGettingExistedKey(t *testing.T) {
	mpkc := newMemoryPersistentKeyCacher()
	downloadedKeys := []jose.JSONWebKey{{KeyID: "test1"}, {KeyID: "test2"}, {KeyID: "test3"}}
	mpkc.Add("test1", downloadedKeys)
	webKey, err := mpkc.Get("test1")
	assert.Equal(t, webKey.KeyID, "test1")
	assert.Nil(t, err)
}

func TestPersistentKeyCacherAddingKey(t *testing.T) {
	mpkc := newMemoryPersistentKeyCacher()
	downloadedKeys := []jose.JSONWebKey{{KeyID: "test1"}, {KeyID: "test2"}, {KeyID: "test3"}}
	webKey, err := mpkc.Add("test1", downloadedKeys)
	assert.Equal(t, webKey.KeyID, "test1")
	assert.Nil(t, err)
}

func TestPersistentKeyCacherAddingInvalidKey(t *testing.T) {
	mpkc := newMemoryPersistentKeyCacher()
	downloadedKeys := []jose.JSONWebKey{{KeyID: "test1"}, {KeyID: "test2"}, {KeyID: "test3"}}
	webKey, err := mpkc.Add("invalidKey", downloadedKeys)
	assert.Empty(t, webKey)
	assert.Error(t, err)
}

func TestKeyCacherWithZeroSizeGettingKey(t *testing.T) {
	mkc := NewMemoryKeyCacher(0, 0)
	webKey, err := mkc.Get("key")
	assert.Empty(t, webKey)
	assert.Error(t, err)
}

func TestKeyCacherWithZeroSizeAddingKey(t *testing.T) {
	mkc := NewMemoryKeyCacher(0, 0)
	downloadedKeys := []jose.JSONWebKey{{KeyID: "test1"}, {KeyID: "test2"}, {KeyID: "test3"}}
	addedKey, err := mkc.Add("test1", downloadedKeys)
	assert.NotEmpty(t, addedKey)
	assert.Nil(t, err)
}

func TestKeyCacherWithSpecificSizeGettingKey(t *testing.T) {
	mkc := NewMemoryKeyCacher(600, 3)
	downloadedKeys := []jose.JSONWebKey{{KeyID: "test1"}, {KeyID: "test2"}, {KeyID: "test3"}}
	mkc.Add("test1", downloadedKeys)
	webKey, err := mkc.Get("test1")
	assert.Equal(t, webKey.KeyID, "test1")
	assert.Nil(t, err)
}

func TestKeyCacherWithSpecificSizeGettingExpiredKey(t *testing.T) {
	entry := make(map[string]keyCacherEntry)
	entry["key"] = keyCacherEntry{
		addedAt:    time.Now().Add(time.Second * -700),
		JSONWebKey: jose.JSONWebKey{KeyID: "test1"},
	}
	mkc := &memoryKeyCacher{entry, 600, 3}
	webKey, err := mkc.Get("key")
	assert.Empty(t, webKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Key exists but is expired")
}

func TestKeyCacherWithSpecificSizeReplacingOldKey(t *testing.T) {
	mkc := NewMemoryKeyCacher(600, 2)
	downloadedKeys := []jose.JSONWebKey{{KeyID: "test1"}, {KeyID: "test2"}, {KeyID: "test3"}}
	mkc.Add("test1", downloadedKeys)
	mkc.Add("test2", downloadedKeys)
	addedKey, err := mkc.Add("test3", downloadedKeys)
	assert.Equal(t, addedKey.KeyID, "test3")
	assert.Nil(t, err)
}
