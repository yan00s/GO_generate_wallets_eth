package main

import (
	"crypto/ecdsa"
	"crypto/sha512"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/1makarov/gen-prv-keys/file"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/umahmood/mnemonic"
	"golang.org/x/crypto/pbkdf2"
)

func create_mnemonic() string {
	m, err := mnemonic.New(mnemonic.DefaultConfig) // default 128 bits
	if err != nil {
		log.Fatal(err)
	}
	words, err := m.Words()
	if err != nil {
		log.Fatal(err)
	}
	result := strings.Join(words, " ")
	return result
}

func get_result_time(bef_time int64) string {
	result_time := time.Now().UnixMilli()
	result_second := (result_time - bef_time) / 1000
	result_milisec := (result_time - bef_time) % 1000
	result := fmt.Sprintf("result: %v.%v seconds", result_second, result_milisec)
	return result
}

func write_result(mnemonics string) {
	name_file := "result_wallets.txt"
	file, err := file.New(name_file, os.O_APPEND|os.O_WRONLY|os.O_CREATE)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	if err := file.Write(mnemonics); err != nil {
		log.Fatal(err)
	}

}

func NewSeed(mnemonic, password string) []byte {
	return pbkdf2.Key([]byte(mnemonic), []byte("mnemonic"+password), 2048, 64, sha512.New)
}

func MustParseDerivationPath(path string) (accounts.DerivationPath, error) {
	return accounts.ParseDerivationPath(path)
}

func SeedPathToECDSA(seed []byte, path accounts.DerivationPath) (*ecdsa.PrivateKey, error) {
	key, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, err
	}

	for _, n := range path {
		key, err = key.Derive(n)
		if err != nil {
			return nil, err
		}
	}

	keyEC, err := key.ECPrivKey()
	if err != nil {
		return nil, err
	}

	return keyEC.ToECDSA(), nil
}

func MnemonicPathToECDSA(mnemonic, password, pathRaw string) (*ecdsa.PrivateKey, error) {
	seed := NewSeed(mnemonic, password)

	path, err := MustParseDerivationPath(pathRaw)
	if err != nil {
		return nil, err
	}

	return SeedPathToECDSA(seed, path)
}

func main() {
	results_wallets := []string{}
	count_mnemon := 0

	fmt.Printf("How many wallets to create? ")
	fmt.Scanf("%v", &count_mnemon)
	bef_time := time.Now().UnixMilli()
	for i := count_mnemon; i > 0; i-- {
		mnemonic := create_mnemonic()
		privateKey, err := MnemonicPathToECDSA(mnemonic, "", "m/44'/60'/0'/0/0")
		if err != nil {
			log.Fatalln(err)
		}
		privateKeyBytes := crypto.FromECDSA(privateKey)
		addr := crypto.PubkeyToAddress(privateKey.PublicKey)
		privateKeyHex := hexutil.Encode(privateKeyBytes)

		result := fmt.Sprintf("Mnemonic: %v\nAddressEth: %v\nPrivateKey: %v\n", mnemonic, addr, privateKeyHex)
		results_wallets = append(results_wallets, result)

	}
	fmt.Println(get_result_time(bef_time))
	write_result(strings.Join(results_wallets, "\n"))
	fmt.Println(len(results_wallets))
}

// on python:
// count wallet: 100000
// time = 528.6071674823761

// on go:
// How many mnemonic to create? 100000
// result: 137.678 seconds
