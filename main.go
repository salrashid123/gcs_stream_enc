package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"

	"context"

	"cloud.google.com/go/storage"
	"github.com/gogo/protobuf/jsonpb"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/streamingaead"
)

const ()

var (
	gcsBucket     = flag.String("gcsBucket", "mineral-minutia-820-enctest", "GCS Bucket")
	keySetString  = flag.String("keySetString", "CLDt99MHEnoKbgo9dHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVzR2NtSGtkZlN0cmVhbWluZ0tleRIrEgcIgCAQIBgDGiAKuLgp8pUCNGdrjdRVair5IwVB3aapACGbzVdbt7NCDxgBEAEYsO330wcgAw", "TinkKey String")
	projectID     = flag.String("projectID", "", "ProjectID")
	srcObjectFile = flag.String("srcObjectFile", "secrets.txt", "File to encrypt and upload")
)

func main() {
	flag.Parse()
	ctx := context.Background()
	gcsClient, err := storage.NewClient(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer gcsClient.Close()
	encBucket := gcsClient.Bucket(*gcsBucket)

	// Load KEK

	decoded, err := base64.RawStdEncoding.DecodeString(*keySetString)
	if err != nil {
		log.Fatal(err)
	}

	ksr := keyset.NewBinaryReader(bytes.NewBuffer(decoded))
	ks, err := ksr.Read()
	if err != nil {
		log.Fatal(err)
	}

	kh, err := insecurecleartextkeyset.Read(&keyset.MemReaderWriter{Keyset: ks})
	if err != nil {
		log.Fatal(err)
	}

	aeadKek, err := streamingaead.New(kh)
	if err != nil {
		log.Fatalf("Failed to create primitive: %v\n", err)
	}

	m := jsonpb.Marshaler{}
	result, err := m.MarshalToString(ks)
	if err != nil {
		log.Fatal(err)
	}

	buf := new(bytes.Buffer)
	err = json.Indent(buf, []byte(result), "", "  ")
	if err != nil {
		log.Fatal(err)
	}

	ksi := kh.KeysetInfo()
	if len(ksi.GetKeyInfo()) == 0 {
		log.Fatal(errors.New("unable to find KEK key"))
	}
	log.Printf("Using KEK ID: %d\n", ksi.GetKeyInfo()[0].GetKeyId())
	log.Printf("Using KEK: \n%s", buf)

	// Create DEK

	log.Println("Creating new DEK")
	nkh, err := keyset.NewHandle(streamingaead.AES256GCMHKDF4KBKeyTemplate())
	if err != nil {
		log.Fatal(err)
	}

	aeadDek, err := streamingaead.New(nkh)
	if err != nil {
		log.Fatalf("Failed to create DEK primitive: %v\n", err)
	}

	ksw := &keyset.MemReaderWriter{}
	if err := insecurecleartextkeyset.Write(nkh, ksw); err != nil {
		log.Fatal(err)
	}

	//"github.com/golang/protobuf/proto"
	// nks, err := proto.Marshal(ksw.Keyset)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// keySetString := base64.RawStdEncoding.EncodeToString(nks)
	// log.Printf("DEK String: %s", keySetString)

	m = jsonpb.Marshaler{}
	result, err = m.MarshalToString(ksw.Keyset)
	if err != nil {
		log.Fatal(err)
	}
	dekPlainText := new(bytes.Buffer)
	err = json.Indent(dekPlainText, []byte(result), "", "  ")
	if err != nil {
		panic(err)
	}

	log.Printf("New DEK \n%s", dekPlainText)

	// Encrypt DEK with KEK
	log.Println("Encrypting DEK with KEK")
	dekBufIn := bytes.NewBufferString(result)
	dekBufOut := new(bytes.Buffer)
	kekAd := []byte("")

	w, err := aeadKek.NewEncryptingWriter(dekBufOut, kekAd)
	if err != nil {
		log.Fatalf("Failed to create encrypt writer: %v", err)
	}
	if _, err := io.Copy(w, dekBufIn); err != nil {
		log.Fatalf("Failed to encrypt data: %v", err)
	}
	if err := w.Close(); err != nil {
		log.Fatalf("Failed to close encrypt writer: %v", err)
	}

	log.Printf("Encrypted DEK: \n%s", base64.RawStdEncoding.EncodeToString(dekBufOut.Bytes()))

	log.Println("Generating Hash of plainText file")
	// Encrypt File with DEK
	hasher := sha256.New()
	s, err := ioutil.ReadFile(*srcObjectFile)
	if err != nil {
		log.Fatal(err)
	}
	_, err = hasher.Write(s)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Plaintext file hash %s", hex.EncodeToString(hasher.Sum(nil)))

	file, err := os.Open(*srcObjectFile)
	if err != nil {
		log.Fatalf("Failed to open file %v\n", err)
	}

	fReader := bufio.NewReader(file)

	dekAd := []byte("")

	log.Println("Encrypting file with DEK")
	gcsDstObject := encBucket.Object(*srcObjectFile + ".enc")

	gcsDstWriter := gcsDstObject.NewWriter(ctx)

	gcsDstWriter.Metadata = map[string]string{
		"x-goog-meta-dek_enc": base64.RawStdEncoding.EncodeToString(dekBufOut.Bytes()),
		"x-goog-meta-kek_id":  fmt.Sprintf("%d", ksi.GetKeyInfo()[0].GetKeyId()),
	}

	pt, err := aeadDek.NewEncryptingWriter(gcsDstWriter, dekAd)
	if err != nil {
		log.Fatalf("Failed to create encrypt writer: %v", err)
	}

	if _, err := io.Copy(pt, fReader); err != nil {
		log.Fatalf("[Encrypter] Error io.Copy(pt, r.Body): (%s) ", err)
	}
	err = pt.Close()
	if err != nil {
		log.Fatalf("[Encrypter] Error gcsDstWriter.Close: (%s) ", err)
	}
	err = gcsDstWriter.Close()
	if err != nil {
		log.Fatalf("[Encrypter] Error gcsDstWriter.Close: (%s) ", err)
	}
	log.Println("File Uploaded")

	// Decrypt object
	log.Println("Downloading encrypted File")
	gcsSrcObject := encBucket.Object(*srcObjectFile + ".enc")

	// First retrieve the metadata for the object that contains the KEK and encrypted DEK
	attrs, err := gcsSrcObject.Attrs(ctx)
	if err != nil {
		log.Fatalf("[Decrypter] Error: (%s) ", err)
	}

	metaDekEnc := ""
	metaKekID := ""

	for key, value := range attrs.Metadata {
		log.Printf("\t%v = %v\n", key, value)
		if key == "x-goog-meta-dek_enc" {
			metaDekEnc = value
		}
		if key == "x-goog-meta-kek_id" {
			metaKekID = value
		}
	}

	if metaDekEnc == "" || metaKekID == "" {
		log.Fatal(errors.New("KEKID or Encrypted DEK not found in object metadata"))
	}

	log.Printf("Found object metadata KEK ID: %s", metaKekID)
	//log.Printf("Using Encrypted DEK: %s", metaDekEnc)

	// Decrypt the DEK using KEK:
	log.Println("Decrypting DEK with KEK")
	dstDec, err := base64.RawStdEncoding.DecodeString(metaDekEnc)
	if err != nil {
		log.Fatalf("[Decrypter] Error: (%s) ", err)
	}
	ddekBufIn := bytes.NewBuffer(dstDec)
	ddekBufOut := new(bytes.Buffer)

	rdec, err := aeadKek.NewDecryptingReader(ddekBufIn, kekAd)
	if err != nil {
		log.Fatalf("Failed to create decrypt reader: %v", err)
	}
	if _, err := io.Copy(ddekBufOut, rdec); err != nil {
		log.Fatalf("Failed to decrypt data: %v", err)
	}

	rdekPlainText := new(bytes.Buffer)
	err = json.Indent(rdekPlainText, ddekBufOut.Bytes(), "", "  ")
	if err != nil {
		panic(err)
	}

	log.Printf("Decrypted DEK %s\n", rdekPlainText)

	// decrypt the object using DEK
	log.Println("Using Decrypted DEK to decrypt object")
	dksr := keyset.NewJSONReader(ddekBufOut)
	dks, err := dksr.Read()
	if err != nil {
		log.Fatal(err)
	}

	dkh, err := insecurecleartextkeyset.Read(&keyset.MemReaderWriter{Keyset: dks})
	if err != nil {
		log.Fatal(err)
	}

	daeadDek, err := streamingaead.New(dkh)
	if err != nil {
		log.Fatalf("Failed to create primitive: %v\n", err)
	}

	gcsSrcReader, err := gcsSrcObject.NewReader(ctx)
	if err != nil {
		log.Fatalf("[Decrypter] Error: (%s) ", err)
	}
	defer gcsSrcReader.Close()

	bufout := new(bytes.Buffer)
	r, err := daeadDek.NewDecryptingReader(gcsSrcReader, dekAd)
	if err != nil {
		log.Fatalf("Failed to create decrypt reader: %v", err)
	}
	if _, err := io.Copy(bufout, r); err != nil {
		log.Fatalf("Failed to encrypt data: %v", err)
	}

	//log.Printf("%s", bufout.String())
	log.Println("Calculating hash of decrypted file")

	hasher = sha256.New()
	_, err = hasher.Write(bufout.Bytes())
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Decrypted file hash %s\n:", hex.EncodeToString(hasher.Sum(nil)))

}
