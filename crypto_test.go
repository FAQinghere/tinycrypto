package tinycrypto

import (
	"log"
	"testing"
	"time"
)

func TestCrypto(t *testing.T) {
	rawSecretKey := "SECRET THAT NEVER APPEARS AS A LITERAL IN THE CODE"
	valueToProtect := []byte("this is my secret value that I must protect")
	secretKey := HashForString(rawSecretKey)
	encrypted, err := Encrypt(valueToProtect, secretKey)
	if err != nil {
		t.Errorf(
			"the encryption process failed: %s",
			err.Error(),
		)
	}
	decrypted, err := Decrypt(encrypted, secretKey)
	if err != nil {
		t.Errorf(
			"the decryption process failed: %s",
			err.Error(),
		)
	}
	actual, expected := string(decrypted), string(valueToProtect)
	if expected != actual {
		t.Errorf(
			"expected decrypted to be %s, but found %s",
			expected,
			actual,
		)
	}
	log.Print("ok")
}

func TestCryptoKeyset(t *testing.T) {
	plaintext := []byte("this is my secret value that I must protect")
	key, _ := NewRandomKey()
	ks := &Keyset{Keys: []*Key{key}}
	cipherText, err := ks.Encrypt(plaintext)
	if err != nil {
		t.Errorf(
			"the encryption process failed: %s",
			err.Error(),
		)
	}
	decrypted, err := ks.Decrypt(cipherText)
	if err != nil {
		t.Errorf(
			"the decryption process failed: %s",
			err.Error(),
		)
	}
	actual, expected := string(decrypted), string(plaintext)
	if expected != actual {
		t.Errorf(
			"expected decrypted to be %s, but found %s",
			expected,
			actual,
		)
	}
	log.Print("ok")
}

func TestKeyset_RotateIn(t *testing.T) {
	k1, _ := NewRandomKey()
	k2, _ := NewRandomKey()
	timeErrMargin := int64(time.Second * 5)

	type fields struct {
		Keys   []*Key
		TypeID int
	}
	type args struct {
		key         *Key
		expireAfter time.Duration
	}
	tests := []struct {
		name        string
		fields      fields
		args        args
		cnt         int
		expirations []int64
	}{
		{
			name: "basic rotation works",
			fields: fields{
				Keys: []*Key{k1},
			},
			args: args{k2, time.Hour},
			expirations: []int64{
				0,
				time.Now().Add(time.Hour).Unix(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ks := &Keyset{
				Keys:   tt.fields.Keys,
				TypeID: tt.fields.TypeID,
			}
			ks.RotateIn(tt.args.key, tt.args.expireAfter)
			preKeys := len(tt.fields.Keys)
			postKeys := len(ks.Keys)
			if postKeys != preKeys+1 {
				t.Fatalf("expected %d keys; got %d keys", postKeys, preKeys+1)
			}
			for i, k := range ks.Keys {
				diff := k.ExpiresUnix - tt.expirations[i]
				if diff < 0 {
					diff = -1 * diff
				}
				if diff > timeErrMargin {
					t.Fatalf(
						"key %d, expected expiration ~ %d, got %d",
						i,
						tt.expirations[i],
						k.ExpiresUnix,
					)
				}
			}

		})
	}
}
