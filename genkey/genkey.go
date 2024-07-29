package main

// this script will generate a new KEK.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"log"

	"github.com/gogo/protobuf/jsonpb"
	"google.golang.org/protobuf/proto"

	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

const (
	plainText = "Some text to encrypt"
	keyURI    = "gcp-kms://projects/mineral-minutia-820/locations/us-central1/keyRings/mykeyring/cryptoKeys/key1"
)

var ()

func main() {

	// Generate Key

	nkh, err := keyset.NewHandle(aead.AES128GCMKeyTemplate())
	if err != nil {
		log.Fatal(err)
	}

	ksw := &keyset.MemReaderWriter{}
	if err := insecurecleartextkeyset.Write(nkh, ksw); err != nil {
		log.Fatal(err)
	}

	//"github.com/golang/protobuf/proto"
	nks, err := proto.Marshal(ksw.Keyset)
	if err != nil {
		log.Fatal(err)
	}

	keySetString := base64.RawStdEncoding.EncodeToString(nks)
	log.Printf("KeySet: %s", keySetString)

	m := jsonpb.Marshaler{}
	result, err := m.MarshalToString(ksw.Keyset)
	if err != nil {
		log.Fatal(err)
	}
	buf := new(bytes.Buffer)
	err = json.Indent(buf, []byte(result), "", "  ")
	if err != nil {
		panic(err)
	}

	log.Printf("%s\n", buf)

	// for EncryptedKeySet

	// gcpClient, err := gcpkms.NewClient("gcp-kms://")
	// if err != nil {
	// 	panic(err)
	// }
	// registry.RegisterKMSClient(gcpClient)

	// // generate wrapping AEAD w/ KMS
	// a, err := gcpClient.GetAEAD(keyURI)
	// if err != nil {
	// 	log.Printf("Could not acquire KMS AEAD %v", err)
	// 	return
	// }

	// memKeyset := &keyset.MemReaderWriter{}

	// kh1, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	// if err != nil {
	// 	log.Printf("Could not create TINK keyHandle %v", err)
	// 	return
	// }

	// if err := kh1.Write(memKeyset, a); err != nil {
	// 	log.Printf("Could not serialize KeyHandle  %v", err)
	// 	return
	// }

	// buf = new(bytes.Buffer)
	// w := keyset.NewJSONWriter(buf)
	// if err := w.WriteEncrypted(memKeyset.EncryptedKeyset); err != nil {
	// 	log.Printf("Could not write encrypted keyhandle %v", err)
	// 	return
	// }
	// var prettyJSON bytes.Buffer
	// error := json.Indent(&prettyJSON, buf.Bytes(), "", "\t")
	// if error != nil {
	// 	log.Fatalf("JSON parse error: %v ", error)
	// }
	// log.Printf("Tink Keyset JSON:  \n%s\n", string(prettyJSON.Bytes()))

	// bw := keyset.NewBinaryWriter(buf)
	// if err := bw.WriteEncrypted(memKeyset.EncryptedKeyset); err != nil {
	// 	log.Printf("Could not write encrypted keyhandle %v", err)
	// 	return
	// }

	// log.Printf("Tink Keyset EncodedBinary:  \n%s\n", base64.RawStdEncoding.EncodeToString(buf.Bytes()))

	// nks, err = proto.Marshal(memKeyset.EncryptedKeyset)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// keySetString = base64.RawStdEncoding.EncodeToString(nks)
	// log.Printf("KeySet: %s", keySetString)

}
