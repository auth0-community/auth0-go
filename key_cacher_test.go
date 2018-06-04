package auth0

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"gopkg.in/square/go-jose.v2"
)

var (
	downloadedKeys = []jose.JSONWebKey{{KeyID: "test1"}, {KeyID: "test2"}, {KeyID: "test3"}}
)

func TestGet(t *testing.T) {
	tests := []struct {
		name             string
		mkc              KeyCacher
		key              string
		expectedErrorMsg string
	}{
		{
			name:             "pass - persistent cacher",
			mkc:              newMemoryPersistentKeyCacher(),
			key:              "test1",
			expectedErrorMsg: "",
		},
		{
			name:             "fail - invalid key",
			mkc:              newMemoryPersistentKeyCacher(),
			key:              "invalid key",
			expectedErrorMsg: "no Keys has been found",
		},
		{
			name:             "pass - get key for persistent cacher",
			mkc:              NewMemoryKeyCacher(time.Duration(0), -1),
			key:              "test1",
			expectedErrorMsg: "",
		},
		{
			name:             "fail - no cacher with -1 maxAge",
			mkc:              NewMemoryKeyCacher(time.Duration(-1), 0),
			key:              "test1",
			expectedErrorMsg: "no Keys has been found",
		},
		{
			name:             "fail - no cacher",
			mkc:              NewMemoryKeyCacher(time.Duration(0), 0),
			key:              "test1",
			expectedErrorMsg: "no Keys has been found",
		},
		{
			name:             "pass - custom cacher not expired",
			mkc:              NewMemoryKeyCacher(time.Duration(100)*time.Second, 1),
			key:              "test1",
			expectedErrorMsg: "",
		},
		{
			name:             "fail - custom cacher with expired key",
			mkc:              NewMemoryKeyCacher(time.Duration(-100)*time.Second, 1),
			key:              "test1",
			expectedErrorMsg: "key exists but is expired",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			test.mkc.Add("test1", downloadedKeys)
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
	tests := []struct {
		name             string
		mkc              KeyCacher
		addingKey        string
		gettingKey       string
		expectedErrorMsg string
	}{
		{
			name:             "pass - persistent cacher",
			mkc:              newMemoryPersistentKeyCacher(),
			addingKey:        "test1",
			gettingKey:       "test1",
			expectedErrorMsg: "",
		},
		{
			name:             "fail - invalid key",
			mkc:              newMemoryPersistentKeyCacher(),
			addingKey:        "invalid key",
			gettingKey:       "invalid key",
			expectedErrorMsg: "no Keys has been found",
		},
		{
			name:             "pass - add key for persistent cacher",
			mkc:              NewMemoryKeyCacher(time.Duration(0), -1),
			addingKey:        "test1",
			gettingKey:       "test1",
			expectedErrorMsg: "",
		},
		{
			name:             "fail - no cacher",
			mkc:              NewMemoryKeyCacher(time.Duration(0), 0),
			addingKey:        "test1",
			gettingKey:       "test1",
			expectedErrorMsg: "no Keys has been found",
		},
		{
			name:             "pass - custom cacher add 3 keys",
			mkc:              NewMemoryKeyCacher(time.Duration(100)*time.Second, 1),
			gettingKey:       "test3",
			expectedErrorMsg: "",
		},
		{
			name:             "fail - custom cacher add invalid key",
			mkc:              NewMemoryKeyCacher(time.Duration(100)*time.Second, 1),
			addingKey:        "invalid key",
			gettingKey:       "test1",
			expectedErrorMsg: "no Keys has been found",
		},
		{
			name:             "fail - custom cacher get key not in cache",
			mkc:              NewMemoryKeyCacher(time.Duration(100)*time.Second, 1),
			gettingKey:       "test1",
			expectedErrorMsg: "no Keys has been found",
		},
		{
			name:             "pass - custom cacher with capacity 3",
			mkc:              NewMemoryKeyCacher(time.Duration(100)*time.Second, 3),
			gettingKey:       "test2",
			expectedErrorMsg: "",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.addingKey == "" {
				for i := 0; i < 3; i++ {
					test.mkc.Add(downloadedKeys[i].KeyID, downloadedKeys)
				}
			} else {
				test.mkc.Add(test.addingKey, downloadedKeys)
			}
			_, err := test.mkc.Get(test.gettingKey)

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

func TestIsExpired(t *testing.T) {
	tests := []struct {
		name         string
		mkc          *memoryKeyCacher
		sleepingTime int
		expectedBool bool
	}{
		{
			name: "true - key is expired",
			mkc: &memoryKeyCacher{
				entries: map[string]keyCacherEntry{},
				maxAge:  time.Duration(1) * time.Second,
				size:    1,
			},
			sleepingTime: 2,
			expectedBool: true,
		},
		{
			name: "false - key not expired",
			mkc: &memoryKeyCacher{
				entries: map[string]keyCacherEntry{},
				maxAge:  time.Duration(2) * time.Second,
				size:    1,
			},
			sleepingTime: 1,
			expectedBool: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.mkc.Add("test1", downloadedKeys)
			time.Sleep(time.Duration(test.sleepingTime) * time.Second)
			if isExpired(test.mkc, "test1") != test.expectedBool {
				t.Errorf("Should have been " + strconv.FormatBool(test.expectedBool) + " but got different")
			}
		})
	}
}

func TestHandleOverflow(t *testing.T) {
	tests := []struct {
		name           string
		mkc            *memoryKeyCacher
		expectedLength int
	}{
		{
			name: "true - overflowed and delete 1 key",
			mkc: &memoryKeyCacher{
				entries: map[string]keyCacherEntry{},
				maxAge:  time.Duration(2) * time.Second,
				size:    1,
			},
			expectedLength: 1,
		},
		{
			name: "false - no overflow",
			mkc: &memoryKeyCacher{
				entries: map[string]keyCacherEntry{},
				maxAge:  time.Duration(2) * time.Second,
				size:    2,
			},
			expectedLength: 2,
		},
	}
	downloadedKeys := []jose.JSONWebKey{{KeyID: "testAddthenGet"}, {KeyID: "test2"}, {KeyID: "test3"}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.mkc.entries["first"] = keyCacherEntry{JSONWebKey: downloadedKeys[0]}
			test.mkc.entries["second"] = keyCacherEntry{JSONWebKey: downloadedKeys[1]}
			handleOverflow(test.mkc)
			if len(test.mkc.entries) != test.expectedLength {
				t.Errorf("Should have been " + strconv.Itoa(test.expectedLength) + "but got different")
			}
		})
	}
}
