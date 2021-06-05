package main

// this script will generate a new KEK.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"log"

	"github.com/gogo/protobuf/jsonpb"
	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
)

const (
	plainText = "Some text to encrypt"
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

}
