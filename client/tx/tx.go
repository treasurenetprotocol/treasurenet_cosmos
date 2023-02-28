package tx

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	gogogrpc "github.com/gogo/protobuf/grpc"
	"github.com/spf13/pflag"

	//"github.com/treasurenet/crypto/ethsecp256k1"
	//"github.com/evmos/ethermint/crypto/ethsecp256k1"
	"github.com/treasurenetprotocol/treasurenet/crypto/ethsecp256k1"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/client/input"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/bech32"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/cosmos/cosmos-sdk/types/rest"
	"github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
)

// GenerateOrBroadcastTxCLI will either generate and print and unsigned transaction
// or sign it and broadcast it returning an error upon failure.
func GenerateOrBroadcastTxCLI(clientCtx client.Context, flagSet *pflag.FlagSet, msgs ...sdk.Msg) error {
	txf := NewFactoryCLI(clientCtx, flagSet)
	return GenerateOrBroadcastTxWithFactory(clientCtx, txf, msgs...)
}

// GenerateOrBroadcastTxWithFactory will either generate and print and unsigned transaction
// or sign it and broadcast it returning an error upon failure.
func GenerateOrBroadcastTxWithFactory(clientCtx client.Context, txf Factory, msgs ...sdk.Msg) error {
	// Validate all msgs before generating or broadcasting the tx.
	// We were calling ValidateBasic separately in each CLI handler before.
	// Right now, we're factorizing that call inside this function.
	// ref: https://github.com/cosmos/cosmos-sdk/pull/9236#discussion_r623803504
	for _, msg := range msgs {
		if err := msg.ValidateBasic(); err != nil {
			return err
		}
	}

	if clientCtx.GenerateOnly {
		return GenerateTx(clientCtx, txf, msgs...)
	}

	return BroadcastTx(clientCtx, txf, msgs...)
}

// GenerateTx will generate an unsigned transaction and print it to the writer
// specified by ctx.Output. If simulation was requested, the gas will be
// simulated and also printed to the same writer before the transaction is
// printed.
func GenerateTx(clientCtx client.Context, txf Factory, msgs ...sdk.Msg) error {
	if txf.SimulateAndExecute() {
		if clientCtx.Offline {
			return errors.New("cannot estimate gas in offline mode")
		}

		_, adjusted, err := CalculateGas(clientCtx, txf, msgs...)
		if err != nil {
			return err
		}

		txf = txf.WithGas(adjusted)
		_, _ = fmt.Fprintf(os.Stderr, "%s\n", GasEstimateResponse{GasEstimate: txf.Gas()})
	}

	tx, err := BuildUnsignedTx(txf, msgs...)
	if err != nil {
		return err
	}

	json, err := clientCtx.TxConfig.TxJSONEncoder()(tx.GetTx())
	if err != nil {
		return err
	}

	return clientCtx.PrintString(fmt.Sprintf("%s\n", json))
}

// BroadcastTx attempts to generate, sign and broadcast a transaction with the
// given set of messages. It will also simulate gas requirements if necessary.
// It will return an error upon failure.
func BroadcastTx(clientCtx client.Context, txf Factory, msgs ...sdk.Msg) error {
	txf, err := prepareFactory(clientCtx, txf)
	if err != nil {
		return err
	}

	if txf.SimulateAndExecute() || clientCtx.Simulate {
		_, adjusted, err := CalculateGas(clientCtx, txf, msgs...)
		if err != nil {
			return err
		}

		txf = txf.WithGas(adjusted)
		_, _ = fmt.Fprintf(os.Stderr, "%s\n", GasEstimateResponse{GasEstimate: txf.Gas()})
	}

	if clientCtx.Simulate {
		return nil
	}

	tx, err := BuildUnsignedTx(txf, msgs...)
	if err != nil {
		return err
	}

	if !clientCtx.SkipConfirm {
		out, err := clientCtx.TxConfig.TxJSONEncoder()(tx.GetTx())
		if err != nil {
			return err
		}

		_, _ = fmt.Fprintf(os.Stderr, "%s\n\n", out)

		buf := bufio.NewReader(os.Stdin)
		ok, err := input.GetConfirmation("confirm transaction before signing and broadcasting", buf, os.Stderr)

		if err != nil || !ok {
			_, _ = fmt.Fprintf(os.Stderr, "%s\n", "cancelled transaction")
			return err
		}
	}

	tx.SetFeeGranter(clientCtx.GetFeeGranterAddress())
	err = Sign(txf, clientCtx.GetFromName(), tx, true)
	if err != nil {
		return err
	}

	txBytes, err := clientCtx.TxConfig.TxEncoder()(tx.GetTx())
	if err != nil {
		return err
	}

	// broadcast to a Tendermint node
	res, err := clientCtx.BroadcastTx(txBytes)
	if err != nil {
		return err
	}

	return clientCtx.PrintProto(res)
}

func WritePubkeyTxResponse(
	clientCtx client.Context, w http.ResponseWriter, br rest.BaseReq, dr sdk.AccAddress, msgs ...sdk.Msg,
) {
	gasAdj, ok := rest.ParseFloat64OrReturnBadRequest(w, br.GasAdjustment, flags.DefaultGasAdjustment)
	if !ok {
		return
	}

	gasSetting, err := flags.ParseGasSetting(br.Gas)
	if rest.CheckBadRequestError(w, err) {
		return
	}

	txf := Factory{fees: br.Fees, gasPrices: br.GasPrices}.
		WithAccountNumber(br.AccountNumber).
		WithSequence(br.Sequence).
		WithGas(gasSetting.Gas).
		WithGasAdjustment(gasAdj).
		WithMemo(br.Memo).
		WithChainID(br.ChainID).
		WithSimulateAndExecute(br.Simulate).
		WithTxConfig(clientCtx.TxConfig).
		WithTimeoutHeight(br.TimeoutHeight)

	if br.Simulate || gasSetting.Simulate {
		if gasAdj < 0 {
			rest.WriteErrorResponse(w, http.StatusBadRequest, sdkerrors.ErrorInvalidGasAdjustment.Error())
			return
		}

		_, adjusted, err := CalculateGas(clientCtx, txf, msgs...)
		if rest.CheckInternalServerError(w, err) {
			return
		}

		txf = txf.WithGas(adjusted)

		if br.Simulate {
			rest.WriteSimulationResponse(w, clientCtx.LegacyAmino, txf.Gas())
			return
		}
	}
	tx1, err := BuildUnsignedTx(txf, msgs...)
	if rest.CheckBadRequestError(w, err) {
		return
	}

	tmpKey := make([]byte, ethsecp256k1.PubKeySize)
	//tmpKey := make([]byte, secp256k1.PubKeySize)
	hexPK1 := "02"
	pubbyte := []byte(br.From)
	//accbyte := []byte(msgs.AccountAddress)
	pubhex := string(pubbyte[2:])
	//accaddr := string(accbyte[2:])
	hexPK1 += pubhex
	//AccAddr := strings.ToUpper(accaddr)
	bz, _ := hex.DecodeString(hexPK1)
	copy(tmpKey[:], bz)
	PubKey_Hex := hex.EncodeToString(tmpKey)
	fmt.Printf("PubKey_Hex=%+v\n", PubKey_Hex)
	pubB := &ethsecp256k1.PubKey{Key: tmpKey}
	//pubB := &secp256k1.PubKey{Key: tmpKey}
	fmt.Printf("pubB=%+v\n", pubB)
	fmt.Printf("pubB_address:=%+v\n", pubB.Address())
	NewAddress, _ := sdk.AccAddressFromHex(pubB.Address().String())
	address := NewAddress.String()
	//address, _ := sdk.AccAddressFromBech32(pubB.Address())
	fmt.Printf("address is :%+v\n", address)
	fmt.Printf("delegaor_address is :%+v\ntype:%T\n", dr.String(), dr.String())
	if dr.String() != address {
		hexPK2 := "03"
		tmpKey2 := make([]byte, ethsecp256k1.PubKeySize)
		pubbyte2 := []byte(br.From)
		pubhex2 := string(pubbyte2[2:])
		hexPK2 += pubhex2
		bz, _ := hex.DecodeString(hexPK2)
		copy(tmpKey2[:], bz)
		PubKey_Hex2 := hex.EncodeToString(tmpKey2)
		fmt.Printf("PubKey_Hex=%+v\n", PubKey_Hex2)
		pubB = &ethsecp256k1.PubKey{Key: tmpKey2}
		//pubB = &secp256k1.PubKey{Key: tmpKey2}
		// NewAddress, _ := sdk.AccAddressFromHex(pubB.Address().String())
		// address := NewAddress.String()
		// //address, _ := sdk.AccAddressFromBech32(pubB.Address())
		// fmt.Printf("address is :%+v\n", address)
	}
	ptr, _ := clientCtx.Codec.MarshalInterfaceJSON(pubB)
	fmt.Println("ptr=\n", ptr)
	//fmt.Println("ptr2=\n", pubB.GetKey())
	var pk cryptotypes.PubKey
	_ = clientCtx.Codec.UnmarshalInterfaceJSON(ptr, &pk)
	fmt.Println("pk=\n", pk)
	signMode := txf.txConfig.SignModeHandler().DefaultMode()
	fmt.Printf("signMode:=%+v\n", signMode)
	// signerData := authsigning.SignerData{
	// 	ChainID:       txf.chainID,
	// 	AccountNumber: txf.accountNumber,
	// 	Sequence:      txf.sequence,
	// }
	sigData := signing.SingleSignatureData{
		SignMode:  signMode,
		Signature: nil,
	}
	fmt.Printf("tx1.GetTx()1=%+v\n", tx1.GetTx())
	sig := signing.SignatureV2{
		PubKey:   pk,
		Data:     &sigData,
		Sequence: txf.Sequence(),
	}

	if err := tx1.SetSignatures(sig); err != nil {
		return
	}
	txJSONBytes1, err := clientCtx.TxConfig.TxJSONEncoder()(tx1.GetTx())
	if err != nil {
		return
	}
	fmt.Printf("txJSONBytesNew1=%+v\ntype:%T\n", txJSONBytes1, txJSONBytes1)
	txJSON1 := string(txJSONBytes1)
	fmt.Println("txJSONBytesNew2=\n", txJSON1)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(txJSONBytes1)
}

// WriteGeneratedTxResponse writes a generated unsigned transaction to the
// provided http.ResponseWriter. It will simulate gas costs if requested by the
// BaseReq. Upon any error, the error will be written to the http.ResponseWriter.
// Note that this function returns the legacy StdTx Amino JSON format for compatibility
// with legacy clients.
// Deprecated: We are removing Amino soon.
/*
func WriteGeneratedTxResponse(
	clientCtx client.Context, w http.ResponseWriter, br rest.BaseReq, msgs ...sdk.Msg,
) {
	gasAdj, ok := rest.ParseFloat64OrReturnBadRequest(w, br.GasAdjustment, flags.DefaultGasAdjustment)
	if !ok {
		return
	}

	gasSetting, err := flags.ParseGasSetting(br.Gas)
	if rest.CheckBadRequestError(w, err) {
		return
	}

	txf := Factory{fees: br.Fees, gasPrices: br.GasPrices}.
		WithAccountNumber(br.AccountNumber).
		WithSequence(br.Sequence).
		WithGas(gasSetting.Gas).
		WithGasAdjustment(gasAdj).
		WithMemo(br.Memo).
		WithChainID(br.ChainID).
		WithSimulateAndExecute(br.Simulate).
		WithTxConfig(clientCtx.TxConfig).
		WithTimeoutHeight(br.TimeoutHeight)

	if br.Simulate || gasSetting.Simulate {
		if gasAdj < 0 {
			rest.WriteErrorResponse(w, http.StatusBadRequest, sdkerrors.ErrorInvalidGasAdjustment.Error())
			return
		}

		_, adjusted, err := CalculateGas(clientCtx, txf, msgs...)
		if rest.CheckInternalServerError(w, err) {
			return
		}

		txf = txf.WithGas(adjusted)

		if br.Simulate {
			rest.WriteSimulationResponse(w, clientCtx.LegacyAmino, txf.Gas())
			return
		}
	}
	tx1, err := BuildUnsignedTx(txf, msgs...)
	if rest.CheckBadRequestError(w, err) {
		return
	}

	tmpKey := make([]byte, ethsecp256k1.PubKeySize)
	tmpKey2 := make([]byte, ethsecp256k1.PubKeySize)
	hexPK1 := "02a4e25bf79363ee85960b88455fe9985fa4372002cd1844ed3d7c1a6b214d01bb885672484a360b98ff8db39f2e88dc6beab3a507d253e320aa7f80ba0b3105aa"
	hexPK := "029ee6f3e5891a5db6fa76f16eb5463c050c4f0edf5d70d13a7162de29e7cf63ad23253e452873da3cf40bf5050f0cbeac5bf9bebbd3ef46b6e3f806474c8b2c5a"
	bz, _ := hex.DecodeString(hexPK)
	bz2, _ := hex.DecodeString(hexPK1)
	copy(tmpKey[:], bz)
	copy(tmpKey2[:], bz2)
	PubKey_Hex := hex.EncodeToString(tmpKey)
	PubKey_Hex2 := hex.EncodeToString(tmpKey2)
	fmt.Printf("PubKey_Hex=%+v\n", PubKey_Hex)
	fmt.Printf("PubKey_Hex2=%+v\n", PubKey_Hex2)
	pubB := &ethsecp256k1.PubKey{Key: tmpKey}
	pubB2 := &ethsecp256k1.PubKey{Key: tmpKey2}
	fmt.Printf("pubB=%+v\n", pubB)
	fmt.Println("pubB_address:=\n", pubB.Address())
	fmt.Println("pubB_type:=\n", pubB.Type())
	fmt.Println("pubB_string=\n", pubB.String())
	fmt.Printf("pubB2=%+v\n", pubB2)
	fmt.Println("pubB_address2:=\n", pubB2.Address())
	fmt.Println("pubB_type2:=\n", pubB2.Type())
	fmt.Println("pubB_string2=\n", pubB2.String())
	ptr, _ := clientCtx.Codec.MarshalInterfaceJSON(pubB)
	fmt.Println("ptr=\n", ptr)
	var pk cryptotypes.PubKey
	_ = clientCtx.Codec.UnmarshalInterfaceJSON(ptr, &pk)
	fmt.Println("pk=\n", pk)
	ss, int1 := pubB.Descriptor()
	fmt.Printf("pubB_Descriptor=%+v\n", ss)
	fmt.Printf("pubB_int1=%+v\n", int1)
	//sdkPK, _ := cryptocodec.FromTmPubKeyInterface(pubB)
	//bz, _ := clientCtx.Codec.MarshalInterfaceJSON(sdkPK)
	//fmt.Println("bz is pubkey:", string(bz))
	// lInfo := newLedgerInfo("some_name", &secp256k1.PubKey{Key: tmpKey}, *hd.NewFundraiserParams(5, sdk.CoinType, 1), hd.Secp256k1Type)
	// require.Equal(t, TypeLedger, lInfo.GetType())

	// path, err := lInfo.GetPath()
	// require.NoError(t, err)
	// require.Equal(t, "m/44'/118'/5'/0/1", path.String())
	// require.Equal(t,
	// fmt.Sprintf("PubKeySecp256k1{%s}", hexPK),
	// lInfo.GetPubKey().String())

	//pubB, _ := hex.DecodeString("ee8d6d0f64d859d548b26f16c86423d58608467b7cdbc56ee10127ac99a973daa1eac4a60ef579155b8a96a2ea5132b8bfcf69bbf3e0daa6fdecf2d290781ff2")
	//&secp256k1.PubKey{Key: pubB}
	//测试签署交易以下
	var info keyring.Info
	if addr, err := sdk.AccAddressFromBech32(br.From); err == nil {
		_, _ = w.Write([]byte(br.From))
		info, err = clientCtx.Keyring.KeyByAddress(addr)
		_, _ = w.Write([]byte("ceshi1"))
		if err != nil {
			return
		}
	} else {
		info, err = clientCtx.Keyring.Key(br.From)
		if err != nil {
			return
		}
	}
	//以下
	pubKey := info.GetPubKey()
	fmt.Println("pubkey:=", pubKey)
	fmt.Printf("pubkey2:=%+v\n", pubKey)
	fmt.Printf("pubkey3:=%+v\n", hex.EncodeToString(pubKey.Bytes()))
	//pubKey2 := &secp256k1.PubKey{Key: pubB}
	//ss := pubKey2.Address()
	// fmt.Println("pubkey:=", pubKey2)
	signMode := txf.txConfig.SignModeHandler().DefaultMode()
	fmt.Printf("signMode:=%+v\n", signMode)
	signerData := authsigning.SignerData{
		ChainID:       txf.chainID,
		AccountNumber: txf.accountNumber,
		Sequence:      txf.sequence,
	}
	sigData := signing.SingleSignatureData{
		SignMode:  signMode,
		Signature: nil,
	}
	fmt.Printf("tx1.GetTx()1=%+v\n", tx1.GetTx())
	sig := signing.SignatureV2{
		PubKey:   pk,
		Data:     &sigData,
		Sequence: txf.Sequence(),
	}

	if err := tx1.SetSignatures(sig); err != nil {
		return
	}

	fmt.Printf("tx1.GetTx()2=%+v\n", tx1.GetTx())
	txJSONBytes1, err := clientCtx.TxConfig.TxJSONEncoder()(tx1.GetTx())
	if err != nil {
		return
	}
	fmt.Printf("txJSONBytesNew1=%+v\ntype:%T\n", txJSONBytes1, txJSONBytes1)
	txJSON1 := string(txJSONBytes1)
	fmt.Println("txJSONBytesNew2=\n", txJSON1)
	rs := []rune(txJSON1)
	fmt.Printf("rs is txjson1 byte:%+v\n", rs)
	var prevSignatures []signing.SignatureV2
	//签署交易以上
	// type StdSignDoc struct {
	// 	AccountNumber uint64            `json:"account_number" yaml:"account_number"`
	// 	Sequence      uint64            `json:"sequence" yaml:"sequence"`
	// 	TimeoutHeight uint64            `json:"timeout_height,omitempty" yaml:"timeout_height"`
	// 	ChainID       string            `json:"chain_id" yaml:"chain_id"`
	// 	Memo          string            `json:"memo" yaml:"memo"`
	// 	Fee           json.RawMessage   `json:"fee" yaml:"fee"`
	// 	Msgs          []json.RawMessage `json:"msgs" yaml:"msgs"`
	// }

	// var StdSign StdSignDoc
	//var c interface{}

	// Generate the bytes to be signed.
	// txCfg := clientCtx.TxConfig
	// jsonbyte, _ := txCfg.TxJSONEncoder()(tx1.GetTx())
	// fmt.Printf("bytesToSign=%+v\n", string(jsonbyte))
	// jsonTx, _ := txCfg.TxJSONDecoder()(jsonbyte)
	//fmt.Printf("jsonTx=%+v\n", &jsonTx.tx)
	bytesToSign, err := txf.txConfig.SignModeHandler().GetSignBytes(signMode, signerData, tx1.GetTx())
	// signDoc := &tx.SignDoc{}
	// err = signDoc.Unmarshal(bytesToSign)
	// if err != nil {
	// 	fmt.Println("signDoc反序列化失败")
	// }
	// fmt.Printf("signDoc反序列化后:%+v\n", signDoc)
	// pex2 := fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(bytesToSign))
	// sigBytes5 := append([]byte(pex2), bytesToSign...)
	// fmt.Printf("stringmgs5=%x\n", string(sigBytes5))
	// //json, err = marshalSignatureJSON(txCfg, tx, false)
	// fmt.Printf("bytesToSign=%+v\n", bytesToSign)
	// fmt.Printf("bytesSign=%+v\n", string(bytesToSign))
	// 编码结果暂存到 buffer
	// str2 := bytesToSign.String()
	// fmt.Println("byteTostring 的string:", str2)
	// err = json.NewDecoder(strings.NewReader(str2)).Decode(&c)
	// err = json.Unmarshal(bytesToSign, &c)
	// if err != nil {
	// 	fmt.Println("byteTostring 的解码结果:", c)
	// }
	// fmt.Printf("bytesToSign1=%+v\n", c)
	// err = clientCtx.LegacyAmino.UnmarshalJSON(bytesToSign, &StdSign)
	// if err != nil {
	// 	return
	// }
	// fmt.Printf("bytesToSign2=%+v\n", StdSign)
	// hex_bytesToSign := hex.EncodeToString(bytesToSign)
	// hex_bytesToSign2 := hex.EncodeToString(sigBytes5)
	// fmt.Printf("bytesToSign=%+v\n", hex_bytesToSign)
	// fmt.Println("hex_bytesToSign", hex_bytesToSign)
	// fmt.Println("hex_bytesToSign2", hex_bytesToSign2)
	if err != nil {
		return
	}
	// Sign those bytes
	addr, _ := sdk.AccAddressFromBech32(br.From)
	//pex := fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(bytesToSign))
	//newbyte1 := []byte(pex)
	//sigBytes2 := append(newbyte1, bytesToSign...)

	sigBytes, _, err := clientCtx.Keyring.SignByAddress(addr, bytesToSign)
	//sigBytes4, _, err := clientCtx.Keyring.SignByAddress(addr, sigBytes5)

	fmt.Printf("sigBytes=%+v\n", sigBytes)
	fmt.Printf("sigBytes详细输出=%x\n", sigBytes)

	sigBytes2 := []byte("01c4b22539db1e8db516735bc34d6b3b0a495b44e7d91e90dbb474eeb45db62750ec380e3dfd82ad01dd78d89c6506fff07437fa4b6900ddca082d454b7fdbfb1b")
	fmt.Printf("sigBytes2=%+v\n", sigBytes2)
	if err != nil {
		return
	}
	// Construct the SignatureV2 struct
	sigData = signing.SingleSignatureData{
		SignMode:  signMode,
		Signature: sigBytes,
	}
	sig = signing.SignatureV2{
		PubKey:   pk,
		Data:     &sigData,
		Sequence: txf.Sequence(),
	}

	// if overwriteSig {
	// 	return txBuilder.SetSignatures(sig)
	// }
	prevSignatures = append(prevSignatures, sig)
	err = tx1.SetSignatures(prevSignatures...)
	if err != nil {
		return
	}
	// fmt.Printf("tx1.GetTx()3=%+v\n", tx1.GetTx())
	// jsonbyte2, _ := txCfg.TxJSONEncoder()(tx1.GetTx())
	// fmt.Printf("jsonbyte2=%+v\n", string(jsonbyte2))
	txBytes, err := clientCtx.TxConfig.TxEncoder()(tx1.GetTx())
	fmt.Println("txBytes1=", txBytes)
	fmt.Printf("txBytes=%+v\ntype:%T\n", txBytes, txBytes)
	fmt.Printf("txBytes2=%x\n", txBytes)
	txJSONBytes, err := clientCtx.TxConfig.TxJSONEncoder()(tx1.GetTx())
	_, _ = w.Write(txJSONBytes)
	if err != nil {
		return
	}
	fmt.Printf("txJSONBytes1=%+v\ntype:%T\n", txJSONBytes, txJSONBytes)
	txJSON := string(txJSONBytes)
	fmt.Println("txJSONBytes2=\n", txJSON)
	stdTx, err := ConvertTxToStdTx(clientCtx.LegacyAmino, tx1.GetTx())
	if err != nil {
		return
	}
	//fmt.Printf("stdTx=%+v\n", stdTx)
	//mgs := stdTx.Msgs
	//fmt.Printf("mgs=%+v\n", mgs)
	//b, _ := json.Marshal(mgs[0])
	//string2 := string(b)
	//fmt.Printf("stringmgs=%+v\n", string2)
	//pex2 := fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(string2))
	//newbyte2 := []byte(pex2)
	//sigBytes5 := append(newbyte2, b...)
	//fmt.Printf("stringmgs5=%x\n", string(sigBytes5))
	//sigBytes6, _, err := clientCtx.Keyring.SignByAddress(addr, sigBytes5)

	//fmt.Printf("sigBytes5=%x\n", sigBytes5)
	//fmt.Printf("sigBytes6=%x\n", sigBytes6)
	// broadcast to a Tendermint node
	res, err := clientCtx.BroadcastTx(txBytes)
	if err != nil {
		return
	}
	res2, err := clientCtx.LegacyAmino.MarshalJSON(res)
	_, _ = w.Write(res2)
	//stdTx, err := ConvertTxToStdTx(clientCtx.LegacyAmino, tx1.GetTx())
	// if rest.CheckInternalServerError(w, err) {
	// 	return
	// }

	output, err := clientCtx.LegacyAmino.MarshalJSON(stdTx)
	if rest.CheckInternalServerError(w, err) {
		return
	}
	fmt.Printf("output:%x\n", output)
	//message := "hello world"
	//byte_data := []byte(message)
	// hex_string_data := hex.EncodeToString(byte_data)
	//message1 := "0x"
	//message = fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message)
	//hrp, _, err := bech32.DecodeAndConvert(message)
	//if err != nil {
	//	return
	//}
	//fmt.Println("hex_string_data is:", hex_string_data)
	//message1 += hex_string_data
	//fmt.Println("message1 is:", message1)
	//byte1 := []byte(hex_string_data)
	//message2 := fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(message))
	//newbyte := []byte(message2)
	// hex_string_data2 := hex.EncodeToString(newbyte)
	// hex_string_data2 += hex_string_data
	//data := append(newbyte, byte_data...)
	//fmt.Println("message3:", string(data))
	//fmt.Println("message3-byte:", data)
	//data := []byte(hex_string_data2)
	//data := []byte(message)
	// 数据签名
	//data1 := []byte("0x2268656c6c6f20776f726c6422")
	//encodedData := ethcrypto.Keccak256(data)
	//encodedData2 := hex.EncodeToString(encodedData)
	//rrr := crypto.Sha256(data)
	//rrr2 := hex.EncodeToString(rrr)
	//eee := ethcrypto.Keccak256Hash(data).Bytes()
	//sigBytes3, _, err := clientCtx.Keyring.SignByAddress(addr, data)
	// fmt.Printf("signBytes2=%x\n", sigBytes3)
	// fmt.Printf("%x\n", encodedData)
	// fmt.Printf("%x\n", rrr)
	// fmt.Printf("%x\n", eee)
	// fmt.Println("测试1", eee)
	// fmt.Println("测试2", encodedData)
	// fmt.Println("测试3", rrr)
	// fmt.Println("测试路径")
	// signature, err := crypto.Sign(encodedData, privateKey)
	// if err != nil {
	// 	return err
	// }
	// fmt.Println("以太坊哈希:", signature)
	//mss := outbut["value"]["msg"]

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(output)
}
*/

func WriteGeneratedTxResponse(
	clientCtx client.Context, w http.ResponseWriter, br rest.BaseReq, msgs ...sdk.Msg,
) {
	gasAdj, ok := rest.ParseFloat64OrReturnBadRequest(w, br.GasAdjustment, flags.DefaultGasAdjustment)
	if !ok {
		return
	}

	gasSetting, err := flags.ParseGasSetting(br.Gas)
	if rest.CheckBadRequestError(w, err) {
		return
	}

	txf := Factory{fees: br.Fees, gasPrices: br.GasPrices}.
		WithAccountNumber(br.AccountNumber).
		WithSequence(br.Sequence).
		WithGas(gasSetting.Gas).
		WithGasAdjustment(gasAdj).
		WithMemo(br.Memo).
		WithChainID(br.ChainID).
		WithSimulateAndExecute(br.Simulate).
		WithTxConfig(clientCtx.TxConfig).
		WithTimeoutHeight(br.TimeoutHeight)

	if br.Simulate || gasSetting.Simulate {
		if gasAdj < 0 {
			rest.WriteErrorResponse(w, http.StatusBadRequest, sdkerrors.ErrorInvalidGasAdjustment.Error())
			return
		}
		_, adjusted, err := CalculateGas(clientCtx, txf, msgs...)
		if rest.CheckInternalServerError(w, err) {
			return
		}
		txf = txf.WithGas(adjusted)
		if br.Simulate {
			rest.WriteSimulationResponse(w, clientCtx.LegacyAmino, txf.Gas())
			return
		}
	}
	tx, err := BuildUnsignedTx(txf, msgs...)
	if rest.CheckBadRequestError(w, err) {
		return
	}

	stdTx, err := ConvertTxToStdTx(clientCtx.LegacyAmino, tx.GetTx())
	if rest.CheckInternalServerError(w, err) {
		return
	}

	output, err := clientCtx.LegacyAmino.MarshalJSON(stdTx)
	if rest.CheckInternalServerError(w, err) {
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(output)
}

func WriteGeneratedTxResponse2(
	clientCtx client.Context, w http.ResponseWriter, br rest.BaseReq, msgs ...sdk.Msg,
) {
	gasAdj, ok := rest.ParseFloat64OrReturnBadRequest(w, br.GasAdjustment, flags.DefaultGasAdjustment)
	if !ok {
		return
	}

	gasSetting, err := flags.ParseGasSetting(br.Gas)
	if rest.CheckBadRequestError(w, err) {
		return
	}

	txf := Factory{fees: br.Fees, gasPrices: br.GasPrices}.
		WithAccountNumber(br.AccountNumber).
		WithSequence(br.Sequence).
		WithGas(gasSetting.Gas).
		WithGasAdjustment(gasAdj).
		WithMemo(br.Memo).
		WithChainID(br.ChainID).
		WithSimulateAndExecute(br.Simulate).
		WithTxConfig(clientCtx.TxConfig).
		WithTimeoutHeight(br.TimeoutHeight)

	if br.Simulate || gasSetting.Simulate {
		if gasAdj < 0 {
			rest.WriteErrorResponse(w, http.StatusBadRequest, sdkerrors.ErrorInvalidGasAdjustment.Error())
			return
		}

		_, adjusted, err := CalculateGas(clientCtx, txf, msgs...)
		if rest.CheckInternalServerError(w, err) {
			return
		}

		txf = txf.WithGas(adjusted)

		if br.Simulate {
			rest.WriteSimulationResponse(w, clientCtx.LegacyAmino, txf.Gas())
			return
		}
	}
	tx, err := BuildUnsignedTx(txf, msgs...)
	if rest.CheckBadRequestError(w, err) {
		return
	}

	stdTx, err := ConvertTxToStdTx(clientCtx.LegacyAmino, tx.GetTx())
	if rest.CheckInternalServerError(w, err) {
		return
	}

	output, err := clientCtx.LegacyAmino.MarshalJSON(stdTx)
	if rest.CheckInternalServerError(w, err) {
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(output)
}

// func WriteGeneratedTxResponse3(
// 	clientCtx client.Context, w http.ResponseWriter, br rest.BaseReq, msgs ...sdk.Msg,
// ) {
// 	gasAdj, ok := rest.ParseFloat64OrReturnBadRequest(w, br.GasAdjustment, flags.DefaultGasAdjustment)
// 	if !ok {
// 		return
// 	}

// 	gasSetting, err := flags.ParseGasSetting(br.Gas)
// 	if rest.CheckBadRequestError(w, err) {
// 		return
// 	}

// 	txf := Factory{fees: br.Fees, gasPrices: br.GasPrices}.
// 		WithAccountNumber(br.AccountNumber).
// 		WithSequence(br.Sequence).
// 		WithGas(gasSetting.Gas).
// 		WithGasAdjustment(gasAdj).
// 		WithMemo(br.Memo).
// 		WithChainID(br.ChainID).
// 		WithSimulateAndExecute(br.Simulate).
// 		WithTxConfig(clientCtx.TxConfig).
// 		WithTimeoutHeight(br.TimeoutHeight)

// 	if br.Simulate || gasSetting.Simulate {
// 		if gasAdj < 0 {
// 			rest.WriteErrorResponse(w, http.StatusBadRequest, sdkerrors.ErrorInvalidGasAdjustment.Error())
// 			return
// 		}

// 		_, adjusted, err := CalculateGas(clientCtx, txf, msgs...)
// 		if rest.CheckInternalServerError(w, err) {
// 			return
// 		}

// 		txf = txf.WithGas(adjusted)

// 		if br.Simulate {
// 			rest.WriteSimulationResponse(w, clientCtx.LegacyAmino, txf.Gas())
// 			return
// 		}
// 	}
// 	tx, err := BuildUnsignedTx(txf, msgs...)
// 	if rest.CheckBadRequestError(w, err) {
// 		return
// 	}

// 	tmpKey := make([]byte, secp256k1.PubKeySize)
// 	hexPK := "ee8d6d0f64d859d548b26f16c86423d58608467b7cdbc56ee10127ac99a973daa1eac4a60ef579155b8a96a2ea5132b8bfcf69bbf3e0daa6fdecf2d290781ff2"
// 	bz, err := hex.DecodeString(hexPK)
// 	copy(tmpKey[:], bz)

// 	pubB := &ethsecp256k1.PubKey{Key: tmpKey}
// 	fmt.Printf("pubB=%+v", pubB)
// 	fmt.Println("pubB:=", pubB)
// 	var info keyring.Info
// 	if addr, err := sdk.AccAddressFromBech32(br.From); err == nil {
// 		_, _ = w.Write([]byte(br.From))
// 		info, err = clientCtx.Keyring.KeyByAddress(addr)
// 		_, _ = w.Write([]byte("ceshi1"))
// 		if err != nil {
// 			return
// 		}
// 	} else {
// 		info, err = clientCtx.Keyring.Key(br.From)
// 		if err != nil {
// 			return
// 		}
// 	}
// 	//以下
// 	pubKey := info.GetPubKey()
// 	fmt.Println("pubkey:=", pubKey)
// 	//pubKey := &secp256k1.PubKey{Key: pubB}
// 	signMode := txf.txConfig.SignModeHandler().DefaultMode()
// 	fmt.Printf("signMode:=%+v\n", signMode)
// 	signerData := authsigning.SignerData{
// 		ChainID:       txf.chainID,
// 		AccountNumber: txf.accountNumber,
// 		Sequence:      txf.sequence,
// 	}
// 	sigData := signing.SingleSignatureData{
// 		SignMode:  signMode,
// 		Signature: nil,
// 	}
// 	fmt.Printf("tx.GetTx()1=%+v\n", tx.GetTx())
// 	sig := signing.SignatureV2{
// 		PubKey:   pubKey,
// 		Data:     &sigData,
// 		Sequence: txf.Sequence(),
// 	}

// 	if err := tx.SetSignatures(sig); err != nil {
// 		return
// 	}

// 	fmt.Printf("tx.GetTx()2=%+v\n", tx.GetTx())
// 	var prevSignatures []signing.SignatureV2

// 	// Generate the bytes to be signed.
// 	bytesToSign, err := txf.txConfig.SignModeHandler().GetSignBytes(signMode, signerData, tx.GetTx())
// 	fmt.Printf("bytesToSign=%+v\n", bytesToSign)
// 	if err != nil {
// 		return
// 	}
// 	// Sign those bytes
// 	addr, _ := sdk.AccAddressFromBech32(br.From)
// 	//pex := fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(bytesToSign))
// 	//newbyte1 := []byte(pex)
// 	//sigBytes2 := append(newbyte1, bytesToSign...)

// 	sigBytes, _, err := clientCtx.Keyring.SignByAddress(addr, bytesToSign)
// 	//sigBytes4, _, err := clientCtx.Keyring.SignByAddress(addr, sigBytes2)

// 	//fmt.Printf("sigBytes=%x\n", sigBytes2)
// 	//fmt.Printf("sigBytes4=%x\n", sigBytes4)
// 	if err != nil {
// 		return
// 	}
// 	// Construct the SignatureV2 struct
// 	sigData = signing.SingleSignatureData{
// 		SignMode:  signMode,
// 		Signature: sigBytes,
// 	}
// 	sig = signing.SignatureV2{
// 		PubKey:   pubKey,
// 		Data:     &sigData,
// 		Sequence: txf.Sequence(),
// 	}
// 	prevSignatures = append(prevSignatures, sig)
// 	err = tx.SetSignatures(prevSignatures...)
// 	if err != nil {
// 		return
// 	}
// 	fmt.Printf("tx.GetTx()3=%+v\n", tx.GetTx())
// 	txBytes, err := clientCtx.TxConfig.TxEncoder()(tx.GetTx())
// 	fmt.Printf("txBytes=%x\n", txBytes)
// 	stdTx, err := ConvertTxToStdTx(clientCtx.LegacyAmino, tx.GetTx())
// 	if err != nil {
// 		return
// 	}
// 	fmt.Printf("stdTx=%+v\n", stdTx)
// 	res, err := clientCtx.BroadcastTx(txBytes)
// 	if err != nil {
// 		return
// 	}
// 	res2, err := clientCtx.LegacyAmino.MarshalJSON(res)
// 	_, _ = w.Write(res2)
// 	// stdTx, err := ConvertTxToStdTx(clientCtx.LegacyAmino, tx.GetTx())
// 	if rest.CheckInternalServerError(w, err) {
// 		return
// 	}

// 	output, err := clientCtx.LegacyAmino.MarshalJSON(stdTx)
// 	if rest.CheckInternalServerError(w, err) {
// 		return
// 	}
// 	fmt.Printf("output:%x\n", output)
// 	//message := "hello world"
// 	//byte_data := []byte(message)
// 	// hex_string_data := hex.EncodeToString(byte_data)
// 	//message1 := "0x"
// 	//message = fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message)
// 	//hrp, _, err := bech32.DecodeAndConvert(message)
// 	//if err != nil {
// 	//	return
// 	//}
// 	//fmt.Println("hex_string_data is:", hex_string_data)
// 	//message1 += hex_string_data
// 	//fmt.Println("message1 is:", message1)
// 	//byte1 := []byte(hex_string_data)
// 	//message2 := fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(message))
// 	//newbyte := []byte(message2)
// 	// hex_string_data2 := hex.EncodeToString(newbyte)
// 	// hex_string_data2 += hex_string_data
// 	//data := append(newbyte, byte_data...)
// 	//fmt.Println("message3:", string(data))
// 	//fmt.Println("message3-byte:", data)
// 	//data := []byte(hex_string_data2)
// 	//data := []byte(message)
// 	// 数据签名
// 	//data1 := []byte("0x2268656c6c6f20776f726c6422")
// 	//encodedData := ethcrypto.Keccak256(data)
// 	//encodedData2 := hex.EncodeToString(encodedData)
// 	//rrr := crypto.Sha256(data)
// 	//rrr2 := hex.EncodeToString(rrr)
// 	//eee := ethcrypto.Keccak256Hash(data).Bytes()
// 	//sigBytes3, _, err := clientCtx.Keyring.SignByAddress(addr, data)
// 	// fmt.Printf("signBytes2=%x\n", sigBytes3)
// 	// fmt.Printf("%x\n", encodedData)
// 	// fmt.Printf("%x\n", rrr)
// 	// fmt.Printf("%x\n", eee)
// 	// fmt.Println("测试1", eee)
// 	// fmt.Println("测试2", encodedData)
// 	// fmt.Println("测试3", rrr)
// 	// fmt.Println("测试路径")
// 	// signature, err := crypto.Sign(encodedData, privateKey)
// 	// if err != nil {
// 	// 	return err
// 	// }
// 	// fmt.Println("以太坊哈希:", signature)
// 	//mss := outbut["value"]["msg"]

// 	w.Header().Set("Content-Type", "application/json")
// 	w.WriteHeader(http.StatusOK)
// 	_, _ = w.Write(output)
// }

// BuildUnsignedTx builds a transaction to be signed given a set of messages. The
// transaction is initially created via the provided factory's generator. Once
// created, the fee, memo, and messages are set.
func BuildUnsignedTx(txf Factory, msgs ...sdk.Msg) (client.TxBuilder, error) {
	if txf.chainID == "" {
		return nil, fmt.Errorf("chain ID required but not specified")
	}

	fees := txf.fees

	if !txf.gasPrices.IsZero() {
		if !fees.IsZero() {
			return nil, errors.New("cannot provide both fees and gas prices")
		}

		glDec := sdk.NewDec(int64(txf.gas))

		// Derive the fees based on the provided gas prices, where
		// fee = ceil(gasPrice * gasLimit).
		fees = make(sdk.Coins, len(txf.gasPrices))

		for i, gp := range txf.gasPrices {
			fee := gp.Amount.Mul(glDec)
			fees[i] = sdk.NewCoin(gp.Denom, fee.Ceil().RoundInt())
		}
	}

	tx := txf.txConfig.NewTxBuilder()

	if err := tx.SetMsgs(msgs...); err != nil {
		return nil, err
	}

	tx.SetMemo(txf.memo)
	tx.SetFeeAmount(fees)
	tx.SetGasLimit(txf.gas)
	tx.SetTimeoutHeight(txf.TimeoutHeight())

	return tx, nil
}

// BuildSimTx creates an unsigned tx with an empty single signature and returns
// the encoded transaction or an error if the unsigned transaction cannot be
// built.
func BuildSimTx(txf Factory, msgs ...sdk.Msg) ([]byte, error) {
	txb, err := BuildUnsignedTx(txf, msgs...)
	if err != nil {
		return nil, err
	}

	// Create an empty signature literal as the ante handler will populate with a
	// sentinel pubkey.
	sig := signing.SignatureV2{
		PubKey: &secp256k1.PubKey{},
		Data: &signing.SingleSignatureData{
			SignMode: txf.signMode,
		},
		Sequence: txf.Sequence(),
	}
	if err := txb.SetSignatures(sig); err != nil {
		return nil, err
	}

	return txf.txConfig.TxEncoder()(txb.GetTx())
}

// CalculateGas simulates the execution of a transaction and returns the
// simulation response obtained by the query and the adjusted gas amount.
func CalculateGas(
	clientCtx gogogrpc.ClientConn, txf Factory, msgs ...sdk.Msg,
) (*tx.SimulateResponse, uint64, error) {
	txBytes, err := BuildSimTx(txf, msgs...)
	//fmt.Printf("气体估算:%+v\n", txBytes)
	if err != nil {
		return nil, 0, err
	}
	//fmt.Println("测试777777")
	txSvcClient := tx.NewServiceClient(clientCtx)
	simRes, err := txSvcClient.Simulate(context.Background(), &tx.SimulateRequest{
		TxBytes: txBytes,
	})
	//fmt.Printf("gas used:= %+v\n", simRes.GasInfo.GasUsed)
	if err != nil {
		return nil, 0, err
	}

	return simRes, uint64(txf.GasAdjustment() * float64(simRes.GasInfo.GasUsed)), nil
}

// prepareFactory ensures the account defined by ctx.GetFromAddress() exists and
// if the account number and/or the account sequence number are zero (not set),
// they will be queried for and set on the provided Factory. A new Factory with
// the updated fields will be returned.
func prepareFactory(clientCtx client.Context, txf Factory) (Factory, error) {
	from := clientCtx.GetFromAddress()

	if err := txf.accountRetriever.EnsureExists(clientCtx, from); err != nil {
		return txf, err
	}

	initNum, initSeq := txf.accountNumber, txf.sequence
	if initNum == 0 || initSeq == 0 {
		num, seq, err := txf.accountRetriever.GetAccountNumberSequence(clientCtx, from)
		if err != nil {
			return txf, err
		}

		if initNum == 0 {
			txf = txf.WithAccountNumber(num)
		}

		if initSeq == 0 {
			txf = txf.WithSequence(seq)
		}
	}

	return txf, nil
}

// SignWithPrivKey signs a given tx with the given private key, and returns the
// corresponding SignatureV2 if the signing is successful.
func SignWithPrivKey(
	signMode signing.SignMode, signerData authsigning.SignerData,
	txBuilder client.TxBuilder, priv cryptotypes.PrivKey, txConfig client.TxConfig,
	accSeq uint64,
) (signing.SignatureV2, error) {
	var sigV2 signing.SignatureV2

	// Generate the bytes to be signed.
	signBytes, err := txConfig.SignModeHandler().GetSignBytes(signMode, signerData, txBuilder.GetTx())
	if err != nil {
		return sigV2, err
	}

	// Sign those bytes
	signature, err := priv.Sign(signBytes)
	if err != nil {
		return sigV2, err
	}

	// Construct the SignatureV2 struct
	sigData := signing.SingleSignatureData{
		SignMode:  signMode,
		Signature: signature,
	}

	sigV2 = signing.SignatureV2{
		PubKey:   priv.PubKey(),
		Data:     &sigData,
		Sequence: accSeq,
	}

	return sigV2, nil
}

func checkMultipleSigners(mode signing.SignMode, tx authsigning.Tx) error {
	if mode == signing.SignMode_SIGN_MODE_DIRECT &&
		len(tx.GetSigners()) > 1 {
		return sdkerrors.Wrap(sdkerrors.ErrNotSupported, "Signing in DIRECT mode is only supported for transactions with one signer only")
	}
	return nil
}

// Sign signs a given tx with a named key. The bytes signed over are canconical.
// The resulting signature will be added to the transaction builder overwriting the previous
// ones if overwrite=true (otherwise, the signature will be appended).
// Signing a transaction with mutltiple signers in the DIRECT mode is not supprted and will
// return an error.
// An error is returned upon failure.
func Sign(txf Factory, name string, txBuilder client.TxBuilder, overwriteSig bool) error {
	if txf.keybase == nil {
		return errors.New("keybase must be set prior to signing a transaction")
	}

	signMode := txf.signMode
	if signMode == signing.SignMode_SIGN_MODE_UNSPECIFIED {
		// use the SignModeHandler's default mode if unspecified
		signMode = txf.txConfig.SignModeHandler().DefaultMode()
	}
	if err := checkMultipleSigners(signMode, txBuilder.GetTx()); err != nil {
		return err
	}

	key, err := txf.keybase.Key(name)
	if err != nil {
		return err
	}
	pubKey := key.GetPubKey()
	signerData := authsigning.SignerData{
		ChainID:       txf.chainID,
		AccountNumber: txf.accountNumber,
		Sequence:      txf.sequence,
	}

	// For SIGN_MODE_DIRECT, calling SetSignatures calls setSignerInfos on
	// TxBuilder under the hood, and SignerInfos is needed to generated the
	// sign bytes. This is the reason for setting SetSignatures here, with a
	// nil signature.
	//
	// Note: this line is not needed for SIGN_MODE_LEGACY_AMINO, but putting it
	// also doesn't affect its generated sign bytes, so for code's simplicity
	// sake, we put it here.
	sigData := signing.SingleSignatureData{
		SignMode:  signMode,
		Signature: nil,
	}
	sig := signing.SignatureV2{
		PubKey:   pubKey,
		Data:     &sigData,
		Sequence: txf.Sequence(),
	}
	var prevSignatures []signing.SignatureV2
	if !overwriteSig {
		prevSignatures, err = txBuilder.GetTx().GetSignaturesV2()
		if err != nil {
			return err
		}
	}
	if err := txBuilder.SetSignatures(sig); err != nil {
		return err
	}

	// Generate the bytes to be signed.
	bytesToSign, err := txf.txConfig.SignModeHandler().GetSignBytes(signMode, signerData, txBuilder.GetTx())
	if err != nil {
		return err
	}

	// Sign those bytes
	sigBytes, _, err := txf.keybase.Sign(name, bytesToSign)
	if err != nil {
		return err
	}

	// Construct the SignatureV2 struct
	sigData = signing.SingleSignatureData{
		SignMode:  signMode,
		Signature: sigBytes,
	}
	sig = signing.SignatureV2{
		PubKey:   pubKey,
		Data:     &sigData,
		Sequence: txf.Sequence(),
	}

	if overwriteSig {
		return txBuilder.SetSignatures(sig)
	}
	prevSignatures = append(prevSignatures, sig)
	return txBuilder.SetSignatures(prevSignatures...)
}

// GasEstimateResponse defines a response definition for tx gas estimation.
type GasEstimateResponse struct {
	GasEstimate uint64 `json:"gas_estimate" yaml:"gas_estimate"`
}

func (gr GasEstimateResponse) String() string {
	return fmt.Sprintf("gas estimate: %d", gr.GasEstimate)
}

//Signing a Transaction

// func sendTx() error {
//     // --snip--

//     privs := []cryptotypes.PrivKey{priv1, priv2}
//     accNums:= []uint64{..., ...} // The accounts' account numbers
//     accSeqs:= []uint64{..., ...} // The accounts' sequence numbers

//     // First round: we gather all the signer infos. We use the "set empty
//     // signature" hack to do that.
//     var sigsV2 []signing.SignatureV2
//     for i, priv := range privs {
//         sigV2 := signing.SignatureV2{
//             PubKey: priv.PubKey(),
//             Data: &signing.SingleSignatureData{
//                 SignMode:  encCfg.TxConfig.SignModeHandler().DefaultMode(),
//                 Signature: nil,
//             },
//             Sequence: accSeqs[i],
//         }

//         sigsV2 = append(sigsV2, sigV2)
//     }
//     err := txBuilder.SetSignatures(sigsV2...)
//     if err != nil {
//         return err
//     }

//     // Second round: all signer infos are set, so each signer can sign.
//     sigsV2 = []signing.SignatureV2{}
//     for i, priv := range privs {
//         signerData := xauthsigning.SignerData{
//             ChainID:       chainID,
//             AccountNumber: accNums[i],
//             Sequence:      accSeqs[i],
//         }
//         sigV2, err := tx.SignWithPrivKey(
//             encCfg.TxConfig.SignModeHandler().DefaultMode(), signerData,
//             txBuilder, priv, encCfg.TxConfig, accSeqs[i])
//         if err != nil {
//             return nil, err
//         }

//         sigsV2 = append(sigsV2, sigV2)
//     }
//     err = txBuilder.SetSignatures(sigsV2...)
//     if err != nil {
//         return err
//     }
// }

type bech32Output struct {
	Formats []string `json:"formats"`
}

func newBech32Output(args string) bech32Output {
	bech32Prefixes := []string{"treasurenet", "treasurenetpub"}
	addr := strings.TrimSpace(args)
	bz, _ := hex.DecodeString(addr)
	out := bech32Output{Formats: make([]string, len(bech32Prefixes))}

	for i, prefix := range bech32Prefixes {
		bech32Addr, err := bech32.ConvertAndEncode(prefix, bz)
		if err != nil {
			panic(err)
		}

		out.Formats[i] = bech32Addr
	}

	return out
}
