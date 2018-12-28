package dkg

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
	"time"

	. "github.com/orbs-network/bgls/bgls"
	. "github.com/orbs-network/bgls/curves"
	"github.com/stretchr/testify/assert"
)

var curves = []CurveSystem{Altbn128}
var threshold = 20
var n = 40

func TestDKGTime(t *testing.T) {
	for _, curve := range curves {

		// == Commit phase ==
		skEncAll := make([]*big.Int, n)
		pkEncAll := make([]Point, n)

		// Generate sks and pks for all participants for encryption/decryption purposes
		for participant := 0; participant < n; participant++ {
			skEncAll[participant], pkEncAll[participant], _, _ = CoefficientGen(curve)
			// fmt.Printf("sk[%v]:  %v\n", participant, skEncAll[participant].String())
			// fmt.Printf("pk-x:  %v\n", pkEncAll[participant].ToAffineCoords()[0].String())
			// fmt.Printf("pk-y:  %v\n", pkEncAll[participant].ToAffineCoords()[1].String())
		}

		coefsAll := make([][]*big.Int, n)
		commitG1All := make([][]Point, n)
		commitG2All := make([][]Point, n)
		commitPrvAll := make([][]*big.Int, n) // private commit of participant to all
		// commitPrvAllEnc := make([][]*big.Int, n) // encrypted version of the above

		// Generate coefficients and public commitments for each participant
		for participant := 0; participant < n; participant++ {
			// fmt.Printf("\n")
			// fmt.Printf("participant:  %v\n", participant)

			coefs := make([]*big.Int, threshold+1)
			commitG1 := make([]Point, threshold+1)
			commitG2 := make([]Point, threshold+1)
			commitPrv := make([]*big.Int, n)
			// commitPrvEnc := make([]*big.Int, n)

			for i := 0; i < threshold+1; i++ {
				var err error
				coefs[i], commitG1[i], commitG2[i], err = CoefficientGen(curve)
				// fmt.Printf("coef[%v]:  %v\n", i, coefs[i].String())
				// fmt.Printf("commitG1-x[%v]:  %v\n", i, commitG1[i].ToAffineCoords()[0].String())
				// fmt.Printf("commitG1-y[%v]:  %v\n", i, commitG1[i].ToAffineCoords()[1].String())
				// fmt.Printf("commitG2-x[%v]:  %v\n", i, commitG2[i].ToAffineCoords()[0].String())
				// fmt.Printf("commitG2-y[%v]:  %v\n", i, commitG2[i].ToAffineCoords()[1].String())
				// fmt.Printf("commitG2-z[%v]:  %v\n", i, commitG2[i].ToAffineCoords()[2].String())
				// fmt.Printf("commitG2-w[%v]:  %v\n", i, commitG2[i].ToAffineCoords()[3].String())

				assert.Nil(t, err, "test data generation failed")
				// assert.True(t, VerifyPublicCommitment(curve, commitG1[i], commitG2[i]), "commit G1 and G2 fail")
			}

			// sk := skEncAll[participant]
			j := big.NewInt(1)
			for i := 0; i < n; i++ {
				commitPrv[i] = GetPrivateCommitment(curve, j, coefs)
				// fmt.Printf("commitPrv[%v]:  %v\n", i, commitPrv[i].String())
				if i != participant { // skip own commitments
					// commitPrvEnc[i] = Encrypt(curve, sk, pkEncAll[i], big.NewInt(0).Set(commitPrv[i]))
					// fmt.Printf("commitPrvEnc[%v]:  %v\n", i, commitPrvEnc[i].String())

				}
				j.Add(j, big.NewInt(1))

			}

			coefsAll[participant] = coefs
			commitG1All[participant] = commitG1
			commitG2All[participant] = commitG2
			commitPrvAll[participant] = commitPrv
			// commitPrvAllEnc[participant] = commitPrvEnc
		}

		// == Verify phase ==

		// fmt.Printf("n=%v    t=%v \n", n, threshold)
		// j := big.NewInt(1)
		// for participant := 0; participant < n; participant++ {
		// 	fmt.Printf("Verify private for index: %v\n", j)
		// 	elapsed := time.Duration(0)
		// 	for commitParticipant := 0; commitParticipant < n; commitParticipant++ {
		// 		if participant != commitParticipant {
		// 			prv := commitPrvAll[commitParticipant][participant]
		// 			pub := commitG1All[commitParticipant]

		// 			start := time.Now()
		// 			VerifyPrivateCommitment(curve, j, prv, pub)
		// 			end := time.Now()
		// 			elapsed = elapsed + end.Sub(start)
		// 		}
		// 	}
		// 	fmt.Printf("time passed:  %v\n", elapsed/time.Duration(n-1))
		// 	j.Add(j, big.NewInt(1))
		// }

		// END OF DKG

		// == Calculate SK, Pks and group PK ==
		skAll := make([]*big.Int, n)
		pubCommitG2Zero := make([]Point, n)
		for participant := 0; participant < n; participant++ {
			pubCommitG2Zero[participant] = commitG2All[participant][0]
			prvCommit := make([]*big.Int, n)
			for commitParticipant := 0; commitParticipant < n; commitParticipant++ {
				prvCommit[commitParticipant] = commitPrvAll[commitParticipant][participant]
			}
			skAll[participant] = GetSecretKey(prvCommit)
		}

		groupPk := GetGroupPublicKey(curve, pubCommitG2Zero)

		// == Sign and reconstruct ==
		d := make([]byte, 64)
		var err error
		_, err = rand.Read(d)
		assert.Nil(t, err, "msg data generation failed")
		sigs := make([]Point, n)
		for participant := 0; participant < n; participant++ {
			sigs[participant] = Sign(curve, skAll[participant], d)
			// assert.True(t, VerifySingleSignature(curve, sigs[participant], pkAll[0][participant], d),
			// 	"signature invalid")
		}

		indices := make([]*big.Int, n)
		index := big.NewInt(0)
		for participant := 0; participant < n; participant++ {
			index.Add(index, big.NewInt(1))
			indices[participant] = big.NewInt(0).Set(index)
		}

		elapsed := time.Duration(0)
		start := time.Now()
		groupSig1, err := SignatureReconstruction(
			curve, sigs[:threshold+1], indices[:threshold+1])
		end := time.Now()
		elapsed = elapsed + end.Sub(start)

		assert.Nil(t, err, "group signature reconstruction fail")
		assert.True(t, VerifySingleSignature(curve, groupSig1, groupPk, d),
			"group signature invalid")

		start = time.Now()
		groupSig2, err := SignatureReconstruction(
			curve, sigs[n-(threshold+1):], indices[n-(threshold+1):])
		end = time.Now()
		elapsed = elapsed + end.Sub(start)

		assert.Nil(t, err, "group signature reconstruction fail")
		assert.True(t, VerifySingleSignature(curve, groupSig2, groupPk, d),
			"group signature invalid")
		assert.True(t, groupSig1.Equals(groupSig2), "group signatures are not equal")

		fmt.Printf("n=%v    t=%v \n", n, threshold)
		fmt.Printf("time passed:  %v\n", elapsed/2)
	}
}

func TestDKGHappyFlow(t *testing.T) {
	for _, curve := range curves {

		// == Commit phase ==
		skEncAll := make([]*big.Int, n)
		pkEncAll := make([]Point, n)

		// Generate sks and pks for all participants for encryption/decryption purposes
		for participant := 0; participant < n; participant++ {
			skEncAll[participant], pkEncAll[participant], _, _ = CoefficientGen(curve)
			// fmt.Printf("sk[%v]:  %v\n", participant, skEncAll[participant].String())
			// fmt.Printf("pk-x:  %v\n", pkEncAll[participant].ToAffineCoords()[0].String())
			// fmt.Printf("pk-y:  %v\n", pkEncAll[participant].ToAffineCoords()[1].String())
		}

		coefsAll := make([][]*big.Int, n)
		commitG1All := make([][]Point, n)
		commitG2All := make([][]Point, n)
		commitPrvAll := make([][]*big.Int, n)    // private commit of participant to all
		commitPrvAllEnc := make([][]*big.Int, n) // encrypted version of the above

		// Generate coefficients and public commitments for each participant
		for participant := 0; participant < n; participant++ {
			// fmt.Printf("\n")
			// fmt.Printf("participant:  %v\n", participant)

			coefs := make([]*big.Int, threshold+1)
			commitG1 := make([]Point, threshold+1)
			commitG2 := make([]Point, threshold+1)
			commitPrv := make([]*big.Int, n)
			commitPrvEnc := make([]*big.Int, n)

			for i := 0; i < threshold+1; i++ {
				var err error
				coefs[i], commitG1[i], commitG2[i], err = CoefficientGen(curve)
				// fmt.Printf("coef[%v]:  %v\n", i, coefs[i].String())
				// fmt.Printf("commitG1-x[%v]:  %v\n", i, commitG1[i].ToAffineCoords()[0].String())
				// fmt.Printf("commitG1-y[%v]:  %v\n", i, commitG1[i].ToAffineCoords()[1].String())
				// fmt.Printf("commitG2-x[%v]:  %v\n", i, commitG2[i].ToAffineCoords()[0].String())
				// fmt.Printf("commitG2-y[%v]:  %v\n", i, commitG2[i].ToAffineCoords()[1].String())
				// fmt.Printf("commitG2-z[%v]:  %v\n", i, commitG2[i].ToAffineCoords()[2].String())
				// fmt.Printf("commitG2-w[%v]:  %v\n", i, commitG2[i].ToAffineCoords()[3].String())

				assert.Nil(t, err, "test data generation failed")
				assert.True(t, VerifyPublicCommitment(curve, commitG1[i], commitG2[i]), "commit G1 and G2 fail")
			}

			sk := skEncAll[participant]
			j := big.NewInt(1)
			for i := 0; i < n; i++ {
				commitPrv[i] = GetPrivateCommitment(curve, j, coefs)
				// fmt.Printf("commitPrv[%v]:  %v\n", i, commitPrv[i].String())
				if i != participant { // skip own commitments
					commitPrvEnc[i] = Encrypt(curve, sk, pkEncAll[i], big.NewInt(0).Set(commitPrv[i]))
					// fmt.Printf("commitPrvEnc[%v]:  %v\n", i, commitPrvEnc[i].String())

				}
				j.Add(j, big.NewInt(1))

			}

			coefsAll[participant] = coefs
			commitG1All[participant] = commitG1
			commitG2All[participant] = commitG2
			commitPrvAll[participant] = commitPrv
			commitPrvAllEnc[participant] = commitPrvEnc
		}

		// == Verify phase ==

		commitPrvAllDec := make([][]*big.Int, n)
		// First decrypt
		for committedParticipant := 0; committedParticipant < n; committedParticipant++ {
			pk := pkEncAll[committedParticipant]
			commitPrvDec := make([]*big.Int, n)
			for participant := 0; participant < n; participant++ {
				if committedParticipant != participant {
					sk := skEncAll[participant]
					enc := big.NewInt(0).Set(commitPrvAllEnc[committedParticipant][participant])
					commitPrvDec[participant] =
						Decrypt(curve, sk, pk, enc)
					assert.True(t,
						commitPrvDec[participant].Cmp(commitPrvAll[committedParticipant][participant]) == 0,
						"commitment is not the same after decryption")
				} else {
					commitPrvDec[participant] = commitPrvAll[committedParticipant][participant] // personal data
				}
			}
			commitPrvAllDec[committedParticipant] = commitPrvDec
		}

		j := big.NewInt(1)
		for participant := 0; participant < n; participant++ {
			for commitParticipant := 0; commitParticipant < n; commitParticipant++ {
				if participant != commitParticipant {
					prv := commitPrvAllDec[commitParticipant][participant]
					pub := commitG1All[commitParticipant]
					assert.True(t, VerifyPrivateCommitment(curve, j, prv, pub), "private commit doesnt match public commit")
				}
			}
			j.Add(j, big.NewInt(1))
		}

		// END OF DKG

		// == Calculate SK, Pks and group PK ==
		skAll := make([]*big.Int, n)
		pkAll := make([][]Point, n)
		pubCommitG2Zero := make([]Point, n)
		for participant := 0; participant < n; participant++ {
			pkAll[participant] = GetAllPublicKey(curve, threshold, commitG2All)
			pubCommitG2Zero[participant] = commitG2All[participant][0]
			prvCommit := make([]*big.Int, n)
			for commitParticipant := 0; commitParticipant < n; commitParticipant++ {
				prvCommit[commitParticipant] = commitPrvAllDec[commitParticipant][participant]
			}
			skAll[participant] = GetSecretKey(prvCommit)
		}

		//Verify pkAll are the same for all
		for participant := 0; participant < n; participant++ {
			pks := pkAll[participant]
			for otherParticipant := 0; otherParticipant < n; otherParticipant++ {
				assert.True(t, pks[participant].Equals(pkAll[otherParticipant][participant]),
					"pk for the same participant is different among other paricipants")
			}
		}

		groupPk := GetGroupPublicKey(curve, pubCommitG2Zero)
		//Verify the secret key matches the public key
		coefsZero := make([]*big.Int, n)
		for participant := 0; participant < n; participant++ {
			coefsZero[participant] = coefsAll[participant][0]
		}
		groupSk := GetPrivateCommitment(curve, big.NewInt(1), coefsZero)
		assert.True(t, groupPk.Equals(LoadPublicKey(curve, groupSk)),
			"groupPK doesnt match to groupSK")

		// == Sign and reconstruct ==
		d := make([]byte, 64)
		var err error
		_, err = rand.Read(d)
		assert.Nil(t, err, "msg data generation failed")
		sigs := make([]Point, n)
		for participant := 0; participant < n; participant++ {
			sigs[participant] = Sign(curve, skAll[participant], d)
			assert.True(t, VerifySingleSignature(curve, sigs[participant], pkAll[0][participant], d),
				"signature invalid")
		}

		indices := make([]*big.Int, n)
		index := big.NewInt(0)
		for participant := 0; participant < n; participant++ {
			index.Add(index, big.NewInt(1))
			indices[participant] = big.NewInt(0).Set(index)
		}

		groupSig1, err := SignatureReconstruction(
			curve, sigs[:threshold+1], indices[:threshold+1])
		assert.Nil(t, err, "group signature reconstruction fail")
		assert.True(t, VerifySingleSignature(curve, groupSig1, groupPk, d),
			"group signature invalid")

		groupSig2, err := SignatureReconstruction(
			curve, sigs[n-(threshold+1):], indices[n-(threshold+1):])
		assert.Nil(t, err, "group signature reconstruction fail")
		assert.True(t, VerifySingleSignature(curve, groupSig2, groupPk, d),
			"group signature invalid")
		assert.True(t, groupSig1.Equals(groupSig2), "group signatures are not equal")

		// TODO add all possible groups
	}
}

func TestEncryptionDecryption(t *testing.T) {
	for _, curve := range curves {

		skEnc, pkEnc, _, _ := CoefficientGen(curve)
		skDec, pkDec, _, _ := CoefficientGen(curve)
		// skEnc, _ := big.NewInt(0).SetString("18610072907578664086425012814666268156600950923827965278715156011465869905829", 10)
		// skDec, _ := big.NewInt(0).SetString("16542974903199856854664432573832058605725269393297901304228908912128894141418", 10)
		// pkEnc := LoadPublicKeyG1(curve, skEnc)
		// pkDec := LoadPublicKeyG1(curve, skDec)
		// fmt.Printf("pkEnc x:  %v\n", pkEnc.ToAffineCoords()[0])
		// fmt.Printf("pkEnc y:  %v\n", pkEnc.ToAffineCoords()[1])
		// fmt.Printf("pkEnc x:  %v\n", pkEnc.ToAffineCoords()[0].Text(16))
		// fmt.Printf("pkEnc y:  %v\n", pkEnc.ToAffineCoords()[1].Text(16))
		// fmt.Printf("pkDec x:  %v\n", pkDec.ToAffineCoords()[0])
		// fmt.Printf("pkDec y:  %v\n", pkDec.ToAffineCoords()[1])
		// fmt.Printf("pkDec x:  %v\n", pkDec.ToAffineCoords()[0].Text(16))
		// fmt.Printf("pkDec y:  %v\n", pkDec.ToAffineCoords()[1].Text(16))
		// coef := big.NewInt(102280324260302)
		// coef, _ := big.NewInt(0).SetString("12158372077063275544310937594012092228806352391176103039110713600257896419805", 10)
		coef, _ := rand.Int(rand.Reader, curve.GetG1Order())
		enc := Encrypt(curve, skEnc, pkDec, coef)
		// fmt.Printf("Enc data:  %v\n", enc.Text(10))
		dec := Decrypt(curve, skDec, pkEnc, enc)
		assert.True(t, dec.Cmp(coef) == 0, "decryption did not return the same encrypted data")
	}
}

func TestGenerateFile(t *testing.T) {
	params := &dkgParams{
		N: n,
		T: threshold,
	}

	for _, curve := range curves {

		// == Commit phase ==
		skEncAll := make([]*big.Int, n)
		skEncAllStr := make([]string, n)
		pkEncAll := make([]Point, n)
		pkEncAllStr := make([][2]string, n)

		// Generate sks and pks for all participants for encryption/decryption purposes
		for participant := 0; participant < n; participant++ {
			skEncAll[participant], pkEncAll[participant], _, _ = CoefficientGen(curve)

			skEncAllStr[participant] = skEncAll[participant].String()
			pkEncAllStr[participant][0] = pkEncAll[participant].ToAffineCoords()[0].String()
			pkEncAllStr[participant][1] = pkEncAll[participant].ToAffineCoords()[1].String()
		}

		coefsAll := make([][]*big.Int, n)
		coefsAllStr := make([][]string, n)
		commitG1All := make([][]Point, n)
		commitG1AllStr := make([][][2]string, n)
		commitG2All := make([][]Point, n)
		commitG2AllStr := make([][][4]string, n)
		commitPrvAll := make([][]*big.Int, n) // private commit of participant to all
		commitPrvAllStr := make([][]string, n)
		commitPrvAllEnc := make([][]*big.Int, n) // encrypted version of the above
		commitPrvAllEncStr := make([][]string, n)

		// Generate coefficients and public commitments for each participant
		for participant := 0; participant < n; participant++ {

			coefs := make([]*big.Int, threshold+1)
			coefsStr := make([]string, threshold+1)
			commitG1 := make([]Point, threshold+1)
			commitG1Str := make([][2]string, threshold+1)
			commitG2 := make([]Point, threshold+1)
			commitG2Str := make([][4]string, threshold+1)
			commitPrv := make([]*big.Int, n)
			commitPrvStr := make([]string, n)
			commitPrvEnc := make([]*big.Int, n)
			commitPrvEncStr := make([]string, n)

			for i := 0; i < threshold+1; i++ {
				var err error
				coefs[i], commitG1[i], commitG2[i], err = CoefficientGen(curve)

				assert.Nil(t, err, "test data generation failed")
				assert.True(t, VerifyPublicCommitment(curve, commitG1[i], commitG2[i]), "commit G1 and G2 fail")

				coefsStr[i] = coefs[i].String()
				commitG1Str[i][0] = commitG1[i].ToAffineCoords()[0].String()
				commitG1Str[i][1] = commitG1[i].ToAffineCoords()[1].String()
				commitG2Str[i][0] = commitG2[i].ToAffineCoords()[0].String()
				commitG2Str[i][1] = commitG2[i].ToAffineCoords()[1].String()
				commitG2Str[i][2] = commitG2[i].ToAffineCoords()[2].String()
				commitG2Str[i][3] = commitG2[i].ToAffineCoords()[3].String()
			}

			sk := skEncAll[participant]
			j := big.NewInt(1)
			for i := 0; i < n; i++ {
				commitPrv[i] = GetPrivateCommitment(curve, j, coefs)
				commitPrvStr[i] = commitPrv[i].String()
				// fmt.Printf("commitPrv[%v]:  %v\n", i, commitPrv[i].String())
				if i != participant { // skip own commitments
					commitPrvEnc[i] = Encrypt(curve, sk, pkEncAll[i], big.NewInt(0).Set(commitPrv[i]))
					// fmt.Printf("commitPrvEnc[%v]:  %v\n", i, commitPrvEnc[i].String())
					commitPrvEncStr[i] = commitPrvEnc[i].String()

				}
				j.Add(j, big.NewInt(1))

			}

			coefsAll[participant] = coefs
			coefsAllStr[participant] = coefsStr
			commitG1All[participant] = commitG1
			commitG1AllStr[participant] = commitG1Str
			commitG2All[participant] = commitG2
			commitG2AllStr[participant] = commitG2Str
			commitPrvAll[participant] = commitPrv
			commitPrvAllStr[participant] = commitPrvStr
			commitPrvAllEnc[participant] = commitPrvEnc
			commitPrvAllEncStr[participant] = commitPrvEncStr
		}

		merkleCommitmentsAll := make([][]byte, n)
		merkleCommitmentsAllStr := make([]string, n)
		// // Build merkle tree
		for participant := 0; participant < n; participant++ {
			merkleCommitmentsAll[participant] = CreateMerkleCommitment(commitG1All[participant], commitG2All[participant])
			merkleCommitmentsAllStr[participant] = "0x" + hex.EncodeToString(merkleCommitmentsAll[participant])
		}

		jsonDkgData := &dkgData{
			Sks:          skEncAllStr,
			Pks:          pkEncAllStr,
			Coefs:        coefsAllStr,
			PrvCommit:    commitPrvAllStr,
			PrvCommitEnc: commitPrvAllEncStr,
			PubCommitG1:  commitG1AllStr,
			PubCommitG2:  commitG2AllStr,
			MerkleCommit: merkleCommitmentsAllStr,
		}

		// == Verify phase ==

		commitPrvAllDec := make([][]*big.Int, n)
		// First decrypt
		for committedParticipant := 0; committedParticipant < n; committedParticipant++ {
			pk := pkEncAll[committedParticipant]
			commitPrvDec := make([]*big.Int, n)
			for participant := 0; participant < n; participant++ {
				if committedParticipant != participant {
					sk := skEncAll[participant]
					enc := big.NewInt(0).Set(commitPrvAllEnc[committedParticipant][participant])
					commitPrvDec[participant] =
						Decrypt(curve, sk, pk, enc)
					assert.True(t,
						commitPrvDec[participant].Cmp(commitPrvAll[committedParticipant][participant]) == 0,
						"commitment is not the same after decryption")
				} else {
					commitPrvDec[participant] = commitPrvAll[committedParticipant][participant] // personal data
				}
			}
			commitPrvAllDec[committedParticipant] = commitPrvDec
		}

		j := big.NewInt(1)
		for participant := 0; participant < n; participant++ {
			for commitParticipant := 0; commitParticipant < n; commitParticipant++ {
				if participant != commitParticipant {
					prv := commitPrvAllDec[commitParticipant][participant]
					pub := commitG1All[commitParticipant]
					assert.True(t, VerifyPrivateCommitment(curve, j, prv, pub), "private commit doesnt match public commit")
				}
			}
			j.Add(j, big.NewInt(1))
		}

		// END OF DKG

		// == Calculate SK, Pks and group PK ==
		skAll := make([]*big.Int, n)
		skAllStr := make([]string, n)
		pkAll := make([][]Point, n)
		pkStr := make([][4]string, n)
		pubCommitG2Zero := make([]Point, n)

		for participant := 0; participant < n; participant++ {
			pkAll[participant] = GetAllPublicKey(curve, threshold, commitG2All)
			pubCommitG2Zero[participant] = commitG2All[participant][0]
			prvCommit := make([]*big.Int, n)
			for commitParticipant := 0; commitParticipant < n; commitParticipant++ {
				prvCommit[commitParticipant] = commitPrvAllDec[commitParticipant][participant]
			}
			skAll[participant] = GetSecretKey(prvCommit)

			pkStr[participant][0] = pkAll[0][participant].ToAffineCoords()[0].String()
			pkStr[participant][1] = pkAll[0][participant].ToAffineCoords()[1].String()
			pkStr[participant][2] = pkAll[0][participant].ToAffineCoords()[2].String()
			pkStr[participant][3] = pkAll[0][participant].ToAffineCoords()[3].String()
			skAllStr[participant] = skAll[participant].String()
		}

		//Verify pkAll are the same for all
		for participant := 0; participant < n; participant++ {
			pks := pkAll[participant]
			for otherParticipant := 0; otherParticipant < n; otherParticipant++ {
				assert.True(t, pks[participant].Equals(pkAll[otherParticipant][participant]),
					"pk for the same participant is different among other paricipants")
			}
		}

		groupPk := GetGroupPublicKey(curve, pubCommitG2Zero)
		//Verify the secret key matches the public key
		coefsZero := make([]*big.Int, n)
		for participant := 0; participant < n; participant++ {
			coefsZero[participant] = coefsAll[participant][0]
		}
		groupSk := GetPrivateCommitment(curve, big.NewInt(1), coefsZero)
		assert.True(t, groupPk.Equals(LoadPublicKey(curve, groupSk)),
			"groupPK doesnt match to groupSK")

		jsonPostDkgData := &postDkgData{
			Pks: pkStr,
			Sks: skAllStr,
			GroupPK: [4]string{groupPk.ToAffineCoords()[0].String(), groupPk.ToAffineCoords()[1].String(),
				groupPk.ToAffineCoords()[2].String(), groupPk.ToAffineCoords()[3].String()},
			GroupSK: groupSk.String(),
		}

		// == Sign and reconstruct ==
		d := make([]byte, 64)
		var err error
		_, err = rand.Read(d)
		assert.Nil(t, err, "msg data generation failed")
		sigs := make([]Point, n)
		for participant := 0; participant < n; participant++ {
			sigs[participant] = Sign(curve, skAll[participant], d)
			assert.True(t, VerifySingleSignature(curve, sigs[participant], pkAll[0][participant], d),
				"signature invalid")
		}

		indices := make([]*big.Int, n)
		index := big.NewInt(0)
		for participant := 0; participant < n; participant++ {
			index.Add(index, big.NewInt(1))
			indices[participant] = big.NewInt(0).Set(index)
		}

		groupSig1, err := SignatureReconstruction(
			curve, sigs[:threshold+1], indices[:threshold+1])
		assert.Nil(t, err, "group signature reconstruction fail")
		assert.True(t, VerifySingleSignature(curve, groupSig1, groupPk, d),
			"group signature invalid")

		groupSig2, err := SignatureReconstruction(
			curve, sigs[n-(threshold+1):], indices[n-(threshold+1):])
		assert.Nil(t, err, "group signature reconstruction fail")
		assert.True(t, VerifySingleSignature(curve, groupSig2, groupPk, d),
			"group signature invalid")
		assert.True(t, groupSig1.Equals(groupSig2), "group signatures are not equal")

		// TODO add all possible groups

		scheme := schemeData{
			Params:  *params,
			DkgData: *jsonDkgData,
			PostDkg: *jsonPostDkgData,
		}

		WriteJsonToFile(scheme)
	}
}

func TestAdjustFile(t *testing.T) {
	data := ReadFileToJson()

	threshold = data.Params.T
	n = data.Params.N
	for _, curve := range curves {

		commitG1AggAll := make([]aggCommit, n)
		// commitG1AggAllStr := make([][][][2]string, n)

		for participant := 0; participant < n; participant++ {

			commitG1AggPar := make([][]Point, n)
			commitG1AggParStr := make([][][2]string, n)

			for committedParticipant := 0; committedParticipant < n; committedParticipant++ {

				index := big.NewInt(int64(committedParticipant + 1))

				commitG1Agg := make([]Point, threshold+1)
				commitG1AggStr := make([][2]string, threshold+1)

				if committedParticipant == participant {
					continue
				}

				for i := 0; i < threshold+1; i++ {

					x, _ := big.NewInt(0).SetString(data.DkgData.PubCommitG1[participant][i][0], 10)
					y, _ := big.NewInt(0).SetString(data.DkgData.PubCommitG1[participant][i][1], 10)

					commitG1Agg[i], _ = curve.MakeG1Point([]*big.Int{x, y}, true)

				}
				commitG1Agg = CalculateExponentiatedPoints(curve, index, commitG1Agg)
				for i := 0; i < threshold+1; i++ {
					if i > 0 {
						commitG1Agg[i], _ = commitG1Agg[i-1].Add(commitG1Agg[i])
					}

					commitG1AggStr[i][0] = commitG1Agg[i].ToAffineCoords()[0].String()
					commitG1AggStr[i][1] = commitG1Agg[i].ToAffineCoords()[1].String()
				}
				commitG1AggPar[committedParticipant] = commitG1Agg
				commitG1AggParStr[committedParticipant] = commitG1AggStr
			}
			jsonAggCommit := aggCommit{
				Index:     participant + 1,
				AggCommit: commitG1AggParStr,
			}
			commitG1AggAll[participant] = jsonAggCommit
			// commitG1AggAll[participant] = commitG1AggPar
			// commitG1AggAllStr[participant] = commitG1AggParStr
		}

		jsonCalc := &calculations{
			PrvCommitCalc: commitG1AggAll,
		}

		jsonComp := &complaint{
			Calculations: *jsonCalc,
		}

		data.Complaint = *jsonComp

		WriteJsonToFile(data)
	}

}
