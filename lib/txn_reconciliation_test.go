package lib

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
)

type Transaction struct {
	TransactionIDBase58Check string `json:"TransactionIDBase58Check"`
	TransactionHashHex       string `json:"TransactionHashHex"`
	// Add other fields as necessary
}

type TransactionFile struct {
	Error        string        `json:"Error"`
	Transactions []Transaction `json:"Transactions"`
}

func loadTransactions(filePath string) (*TransactionFile, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	bytes, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}

	var transactions TransactionFile
	if err := json.Unmarshal(bytes, &transactions); err != nil {
		return nil, err
	}

	return &transactions, nil
}

func findUniqueTransactions(transactions1, transactions2 []Transaction) []Transaction {
	transactionMap := make(map[string]Transaction)
	for _, tx := range transactions2 {
		transactionMap[tx.TransactionHashHex] = tx
	}

	fmt.Printf("Test: %+v\n", transactionMap["a2bfab455c31f8ed418c9aa66edb40749c308cb29f232ff6a3882340520d422f"])

	uniqueTransactions := []Transaction{}
	for _, tx := range transactions1 {
		if _, found := transactionMap[tx.TransactionHashHex]; !found {
			uniqueTransactions = append(uniqueTransactions, tx)
		}
	}

	return uniqueTransactions
}

func TestReconcileTransactions(t *testing.T) {
	blueTxnJsonPath := "/Users/zordon/Library/Application Support/JetBrains/GoLand2022.2/scratches/blue_transactions.json"
	greenTxnJsonPath := "/Users/zordon/Library/Application Support/JetBrains/GoLand2022.2/scratches/green_transactions.json"

	blueTxns, err := loadTransactions(blueTxnJsonPath)
	if err != nil {
		fmt.Println("Error loading transactions from blue file:", err)
		return
	}

	greenTxns, err := loadTransactions(greenTxnJsonPath)
	if err != nil {
		fmt.Println("Error loading transactions from green file:", err)
		return
	}

	fmt.Println("Loaded", len(blueTxns.Transactions), "transactions from blue file")

	blueUniqueTxns := findUniqueTransactions(blueTxns.Transactions, greenTxns.Transactions)
	greenUniqueTxns := findUniqueTransactions(greenTxns.Transactions, blueTxns.Transactions)

	fmt.Println("Transactions unique to blue:")
	for _, tx := range blueUniqueTxns {
		txJson, _ := json.MarshalIndent(tx, "", "  ")
		fmt.Println(string(txJson))
	}

	fmt.Println("Transactions unique to green:")
	for _, tx := range greenUniqueTxns {
		txJson, _ := json.MarshalIndent(tx, "", "  ")
		fmt.Println(string(txJson))
	}
}
