package auth0

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"gopkg.in/square/go-jose.v2"
)

func TestGet(t *testing.T) {
	tests := []struct {
		name             string
		mkc              *memoryKeyCacher
		key              string
		expectedErrorMsg string
	}{
		{
			name: "pass - persistent cacher",
			mkc: &memoryKeyCacher{
				entries:      make(map[string]keyCacherEntry),
				maxKeyAge:    MaxKeyAgeNoCheck,
				maxCacheSize: MaxCacheSizeNoCheck,
			},
			key:              "key1",
			expectedErrorMsg: "",
		},
		{
			name: "fail - invalid key",
			mkc: &memoryKeyCacher{
				entries:      make(map[string]keyCacherEntry),
				maxKeyAge:    MaxKeyAgeNoCheck,
				maxCacheSize: MaxCacheSizeNoCheck,
			},
			key:              "invalid key",
			expectedErrorMsg: "no Keys has been found",
		},
		{
			name: "fail - persistent cacher get immediately expired key",
			mkc: &memoryKeyCacher{
				entries:      make(map[string]keyCacherEntry),
				maxKeyAge:    time.Duration(0),
				maxCacheSize: MaxCacheSizeNoCheck,
			},
			key:              "key1",
			expectedErrorMsg: "key exists but is expired",
		},
		{
			name: "pass - persistent cacher get not expired key",
			mkc: &memoryKeyCacher{
				entries:      make(map[string]keyCacherEntry),
				maxKeyAge:    time.Duration(10) * time.Second,
				maxCacheSize: MaxCacheSizeNoCheck,
			},
			key:              "key1",
			expectedErrorMsg: "",
		},
		{
			name: "fail - no cacher with -1 maxKeyAge",
			mkc: &memoryKeyCacher{
				entries:      nil,
				maxKeyAge:    MaxKeyAgeNoCheck,
				maxCacheSize: 0,
			},
			key:              "key1",
			expectedErrorMsg: "no Keys has been found",
		},
		{
			name: "fail - no cacher",
			mkc: &memoryKeyCacher{
				entries:      nil,
				maxKeyAge:    time.Duration(0),
				maxCacheSize: 0,
			},
			key:              "key1",
			expectedErrorMsg: "no Keys has been found",
		},
		{
			name: "fail - no cacher with 10sec max age",
			mkc: &memoryKeyCacher{
				entries:      nil,
				maxKeyAge:    time.Duration(10) * time.Second,
				maxCacheSize: 0,
			},
			key:              "key1",
			expectedErrorMsg: "no Keys has been found",
		},
		{
			name: "pass - custom cacher with -1 max age",
			mkc: &memoryKeyCacher{
				entries:      make(map[string]keyCacherEntry),
				maxKeyAge:    MaxKeyAgeNoCheck,
				maxCacheSize: 1,
			},
			key:              "key1",
			expectedErrorMsg: "",
		},
		{
			name: "fail - custom cacher get immediately expired key",
			mkc: &memoryKeyCacher{
				entries:      make(map[string]keyCacherEntry),
				maxKeyAge:    time.Duration(0),
				maxCacheSize: 1,
			},
			key:              "key1",
			expectedErrorMsg: "key exists but is expired",
		},
		{
			name: "pass - custom cacher not expired",
			mkc: &memoryKeyCacher{
				entries:      make(map[string]keyCacherEntry),
				maxKeyAge:    time.Duration(100) * time.Second,
				maxCacheSize: 1,
			},
			key:              "key1",
			expectedErrorMsg: "",
		},
		{
			name: "fail - custom cacher with expired key",
			mkc: &memoryKeyCacher{
				entries:      make(map[string]keyCacherEntry),
				maxKeyAge:    time.Duration(-100) * time.Second, // setting max age negavtive time duration is equivalent to expired keys
				maxCacheSize: 1,
			},
			key:              "key1",
			expectedErrorMsg: "key exists but is expired",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.mkc.entries != nil {
				test.mkc.entries["key1"] = keyCacherEntry{time.Now(), jose.JSONWebKey{KeyID: "test1"}}
			}

			_, err := test.mkc.Get(test.key)

			if test.expectedErrorMsg != "" {
				if err == nil {
					t.Errorf("Validation should have failed with error with substring: " + test.expectedErrorMsg)
				} else if !strings.Contains(err.Error(), test.expectedErrorMsg) {
					t.Errorf("Validation should have failed with error with substring: " + test.expectedErrorMsg + ", but got: " + err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Validation should not have failed with error, but got: " + err.Error())
				}
			}
		})
	}
}

func TestAdd(t *testing.T) {
	downloadedKeys := []jose.JSONWebKey{
		{Key: jose.JSONWebKey{}, KeyID: "test1"},
		{Key: jose.JSONWebKey{}, KeyID: "test2"},
		{Key: jose.JSONWebKey{}, KeyID: "test3"},
	}

	tests := []struct {
		name             string
		mkc              *memoryKeyCacher
		addingKey        string
		gettingKey       string
		expectedFoundKey bool
		expectedErrorMsg string
	}{
		{
			name: "pass - persistent cacher",
			mkc: &memoryKeyCacher{
				entries:      make(map[string]keyCacherEntry),
				maxKeyAge:    MaxKeyAgeNoCheck,
				maxCacheSize: MaxCacheSizeNoCheck,
			},
			addingKey:        "test1",
			gettingKey:       "test1",
			expectedFoundKey: true,
			expectedErrorMsg: "",
		},
		{
			name: "fail - invalid key",
			mkc: &memoryKeyCacher{
				entries:      make(map[string]keyCacherEntry),
				maxKeyAge:    MaxKeyAgeNoCheck,
				maxCacheSize: MaxCacheSizeNoCheck,
			},
			addingKey:        "invalid key",
			gettingKey:       "invalid key",
			expectedFoundKey: false,
			expectedErrorMsg: "no Keys has been found",
		},
		{
			name: "pass - add key for persistent cacher",
			mkc: &memoryKeyCacher{
				entries:      make(map[string]keyCacherEntry),
				maxKeyAge:    time.Duration(0),
				maxCacheSize: MaxCacheSizeNoCheck,
			},
			addingKey:        "test1",
			gettingKey:       "test1",
			expectedFoundKey: true,
			expectedErrorMsg: "",
		},
		{
			name: "pass - add key for persistent cacher",
			mkc: &memoryKeyCacher{
				entries:      make(map[string]keyCacherEntry),
				maxKeyAge:    time.Duration(10) * time.Second,
				maxCacheSize: MaxCacheSizeNoCheck,
			},
			addingKey:        "test1",
			gettingKey:       "test1",
			expectedFoundKey: true,
			expectedErrorMsg: "",
		},
		{
			name: "fail - no cacher with -1 max age",
			mkc: &memoryKeyCacher{
				entries:      make(map[string]keyCacherEntry),
				maxKeyAge:    MaxKeyAgeNoCheck,
				maxCacheSize: 0,
			},
			addingKey:        "test1",
			gettingKey:       "test1",
			expectedFoundKey: false,
			expectedErrorMsg: "",
		},
		{
			name: "fail - no cacher",
			mkc: &memoryKeyCacher{
				entries:      make(map[string]keyCacherEntry),
				maxKeyAge:    time.Duration(0),
				maxCacheSize: 0,
			},
			addingKey:        "test1",
			gettingKey:       "test1",
			expectedFoundKey: false,
			expectedErrorMsg: "",
		},
		{
			name: "fail - no cacher with 10sec max age",
			mkc: &memoryKeyCacher{
				entries:      make(map[string]keyCacherEntry),
				maxKeyAge:    time.Duration(10) * time.Second,
				maxCacheSize: 0,
			},
			addingKey:        "test1",
			gettingKey:       "test1",
			expectedFoundKey: false,
			expectedErrorMsg: "",
		},
		{
			name: "pass - custom cacher with -1 max age",
			mkc: &memoryKeyCacher{
				entries:      make(map[string]keyCacherEntry),
				maxKeyAge:    MaxKeyAgeNoCheck,
				maxCacheSize: 1,
			},
			addingKey:        "test1",
			gettingKey:       "test1",
			expectedFoundKey: true,
			expectedErrorMsg: "",
		},
		{
			name: "pass - custom cacher with 0 max age",
			mkc: &memoryKeyCacher{
				entries:      make(map[string]keyCacherEntry),
				maxKeyAge:    time.Duration(0),
				maxCacheSize: 1,
			},
			addingKey:        "test1",
			gettingKey:       "test1",
			expectedFoundKey: true,
			expectedErrorMsg: "",
		},
		{
			name: "pass - custom cacher get latest added key",
			mkc: &memoryKeyCacher{
				entries:      make(map[string]keyCacherEntry),
				maxKeyAge:    time.Duration(100) * time.Second,
				maxCacheSize: 1,
			},
			gettingKey:       "test3",
			expectedFoundKey: true,
			expectedErrorMsg: "",
		},
		{
			name: "fail - custom cacher add invalid key",
			mkc: &memoryKeyCacher{
				entries:      make(map[string]keyCacherEntry),
				maxKeyAge:    time.Duration(100) * time.Second,
				maxCacheSize: 1,
			},
			addingKey:        "invalid key",
			gettingKey:       "test1",
			expectedFoundKey: false,
			expectedErrorMsg: "no Keys has been found",
		},
		{
			name: "fail - custom cacher get key not in cache",
			mkc: &memoryKeyCacher{
				entries:      make(map[string]keyCacherEntry),
				maxKeyAge:    time.Duration(100) * time.Second,
				maxCacheSize: 1,
			},
			gettingKey:       "test1",
			expectedFoundKey: false,
			expectedErrorMsg: "",
		},
		{
			name: "pass - custom cacher with capacity 3",
			mkc: &memoryKeyCacher{
				entries:      make(map[string]keyCacherEntry),
				maxKeyAge:    time.Duration(100) * time.Second,
				maxCacheSize: 3,
			},
			gettingKey:       "test2",
			expectedFoundKey: true,
			expectedErrorMsg: "",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var err error
			if test.addingKey == "" {
				for i := 0; i < 3; i++ {
					_, err = test.mkc.Add(downloadedKeys[i].KeyID, downloadedKeys)
				}
			} else {
				_, err = test.mkc.Add(test.addingKey, downloadedKeys)
			}
			_, ok := test.mkc.entries[test.gettingKey]
			assert.Equal(t, test.expectedFoundKey, ok)

			if test.expectedErrorMsg != "" {
				if err == nil {
					t.Errorf("Validation should have failed with error with substring: " + test.expectedErrorMsg)
				} else if !strings.Contains(err.Error(), test.expectedErrorMsg) {
					t.Errorf("Validation should have failed with error with substring: " + test.expectedErrorMsg + ", but got: " + err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Validation should not have failed with error, but got: " + err.Error())
				}
			}
		})
	}
}

func TestKeyIsExpired(t *testing.T) {
	tests := []struct {
		name         string
		mkc          *memoryKeyCacher
		sleepingTime int
		expectedBool bool
	}{
		{
			name: "true - key is expired",
			mkc: &memoryKeyCacher{
				entries:      map[string]keyCacherEntry{},
				maxKeyAge:    time.Duration(1) * time.Second,
				maxCacheSize: 1,
			},
			expectedBool: true,
		},
		{
			name: "false - key not expired",
			mkc: &memoryKeyCacher{
				entries:      map[string]keyCacherEntry{},
				maxKeyAge:    time.Duration(10) * time.Second,
				maxCacheSize: 1,
			},
			expectedBool: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.expectedBool {
				test.mkc.entries["test1"] = keyCacherEntry{time.Now().Add(time.Duration(-10) * time.Second), jose.JSONWebKey{KeyID: "test1"}}
			} else {
				test.mkc.entries["test1"] = keyCacherEntry{time.Now(), jose.JSONWebKey{KeyID: "test1"}}
			}
			if test.mkc.keyIsExpired("test1") != test.expectedBool {
				t.Errorf("Should have been " + strconv.FormatBool(test.expectedBool) + " but got different")
			}
		})
	}
}

func TestHandleOverflow(t *testing.T) {
	downloadedKeys := []jose.JSONWebKey{{KeyID: "test1"}, {KeyID: "test2"}, {KeyID: "test3"}}

	tests := []struct {
		name           string
		mkc            *memoryKeyCacher
		expectedLength int
	}{
		{
			name: "true - overflowed and delete 1 key",
			mkc: &memoryKeyCacher{
				entries:      map[string]keyCacherEntry{},
				maxKeyAge:    time.Duration(2) * time.Second,
				maxCacheSize: 1,
			},
			expectedLength: 1,
		},
		{
			name: "false - no overflow",
			mkc: &memoryKeyCacher{
				entries:      map[string]keyCacherEntry{},
				maxKeyAge:    time.Duration(2) * time.Second,
				maxCacheSize: 2,
			},
			expectedLength: 2,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.mkc.entries["first"] = keyCacherEntry{JSONWebKey: downloadedKeys[0]}
			test.mkc.entries["second"] = keyCacherEntry{JSONWebKey: downloadedKeys[1]}
			test.mkc.handleOverflow()
			if len(test.mkc.entries) != test.expectedLength {
				t.Errorf("Should have been " + strconv.Itoa(test.expectedLength) + "but got different")
			}
		})
	}
}
