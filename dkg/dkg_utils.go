package dkg

import (
	"encoding/json"
	"fmt"
	"os"
)

type dkgParams struct {
	N int `json:"n"`
	T int `json:"t"`
}

type dkgData struct {
	Sks          []string      `json:"encSks"`
	Pks          [][2]string   `json:"encPks"`
	Coefs        [][]string    `json:"coefs"`
	PubCommitG1  [][][2]string `json:"pubCommitG1"`
	PubCommitG2  [][][4]string `json:"pubCommitG2"`
	PrvCommit    [][]string    `json:"prvCommit"`
	PrvCommitEnc [][]string    `json:"prvCommitEnc"`
	MerkleCommit []string      `json:"merkleCommit"`
}

type postDkgData struct {
	Pks     [][4]string `json:"pks"`
	Sks     []string    `json:"sks"`
	GroupPK [4]string   `json:"groupPK"`
	GroupSK string      `json:"groupSK"`
}

type schemeData struct {
	Params  dkgParams   `json:"params"`
	DkgData dkgData     `json:"dkgData"`
	PostDkg postDkgData `json:"postDkg"`
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func WriteJsonToFile(data schemeData) {

	js, _ := json.MarshalIndent(data, "", "    ")
	_ = js
	f, err := os.Create("happyFlowData.js")

	check(err)

	defer f.Close()

	n3, err := f.WriteString("module.exports = " + string(js))
	fmt.Printf("wrote %d bytes\n", n3)
	f.Sync()
}
