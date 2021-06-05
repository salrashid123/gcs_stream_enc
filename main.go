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
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/proto/tink_go_proto"
	"github.com/google/tink/go/streamingaead"

	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/integration/gcpkms"
)

const ()

var (
	gcsBucket = flag.String("gcsBucket", "mineral-minutia-820-enctest", "GCS Bucket")

	keySetString = flag.String("keySetString", "CLnwmtYGEmQKWAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVzR2NtS2V5EiIaIA7TocwCm37/3vReEGSRsoSp+a0KAq+KYEKqKH5dVqC4GAEQARi58JrWBiAB", "TinkKey String")
	//keySetString       = flag.String("keySetString", "Er8BCiUAmT+VVTTUqo1Zw+A30ucZRKy2p8pbH0NmBrHgR8KFQ2AQy2v/EpUBACsKZVK04jA5NAXx6X5sPUa9rCrOid/x2/DsTpPLiTHja33GzM8mxLoMBvr3bCbK4SHB3MCRhAUxikDt7ke9QufwEtZdNN+XT//uCk0LfZLgqMzIsVdzjnwfdbhvBcVDgXWfzsVioPISkFQfN6OTSTQ+c7eyeXWpusV6areF9GrqshyI8qGCmOqKmkH2BC0rZssHb48aRAjrtIfhAhI8CjB0eXBlLmdvb2dsZWFwaXMuY29tL2dvb2dsZS5jcnlwdG8udGluay5BZXNHY21LZXkQARjrtIfhAiAB", "TinkKey String")
	keyURI             = flag.String("keyURI", "gcp-kms://projects/mineral-minutia-820/locations/us-central1/keyRings/mykeyring/cryptoKeys/key1", "KEK Key URI")
	projectID          = flag.String("projectID", "", "ProjectID")
	srcObjectFile      = flag.String("srcObjectFile", "secrets.txt", "File to encrypt and upload")
	useEncryptedKeySet = flag.Bool("useEncryptedKeySet", false, "Use EncryptedKeyset")
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

	var kh *keyset.Handle
	// Load KEK

	decoded, err := base64.RawStdEncoding.DecodeString(*keySetString)
	if err != nil {
		log.Fatal(err)
	}

	var ks *tink_go_proto.Keyset

	ksr := keyset.NewBinaryReader(bytes.NewBuffer(decoded))

	if *useEncryptedKeySet {
		log.Println("Using EncryptedKeyset for KEK")
		gcpClient, err := gcpkms.NewClient("gcp-kms://")
		if err != nil {
			panic(err)
		}
		registry.RegisterKMSClient(gcpClient)

		backend, err := gcpClient.GetAEAD(*keyURI)
		if err != nil {
			panic(err)
		}

		kh, err = keyset.Read(ksr, backend)
		if err != nil {
			panic(err)
		}

	} else {
		log.Println("Using InsecureKeySet for KEK")

		ks, err = ksr.Read()
		if err != nil {
			panic(err)
		}

		kh, err = insecurecleartextkeyset.Read(&keyset.MemReaderWriter{Keyset: ks})
		if err != nil {
			log.Fatal(err)
		}
		m := jsonpb.Marshaler{}
		result, err := m.MarshalToString(ks)
		if err != nil {
			panic(err)
		}

		buf := new(bytes.Buffer)
		err = json.Indent(buf, []byte(result), "", "  ")
		if err != nil {
			panic(err)
		}

	}

	ksi := kh.KeysetInfo()
	if len(ksi.GetKeyInfo()) == 0 {
		log.Fatal(errors.New("unable to find KEK key"))
	}
	log.Printf("Using KEK ID: %d\n", ksi.GetKeyInfo()[0].GetKeyId())
	log.Printf("Using KEK TypeUrl: %s\n", ksi.GetKeyInfo()[0].TypeUrl)

	aeadKek, err := aead.New(kh)
	if err != nil {
		log.Fatalf("Failed to create primitive: %v\n", err)
	}

	// Create DEK
	m := jsonpb.Marshaler{}
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

	m = jsonpb.Marshaler{}
	result, err := m.MarshalToString(ksw.Keyset)
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

	kekAd := []byte("")

	// 5. Serialize the whole keyset

	dekBufOut, err := aeadKek.Encrypt(dekPlainText.Bytes(), kekAd)
	if err != nil {
		log.Fatalf("Failed to create encrypt writer: %v", err)
	}

	log.Printf("Encrypted DEK: \n%s", base64.RawStdEncoding.EncodeToString(dekBufOut))

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
		"x-goog-meta-dek_enc": base64.RawStdEncoding.EncodeToString(dekBufOut),
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
	dstDec, err := base64.RawStdEncoding.DecodeString(metaDekEnc)
	if err != nil {
		log.Fatalf("[Decrypter] Error: (%s) ", err)
	}

	log.Println("Decrypting DEK with KEK")
	rdec, err := aeadKek.Decrypt(dstDec, kekAd)
	if err != nil {
		log.Fatalf("Failed to create decrypt reader: %v", err)
	}

	rdekPlainText := new(bytes.Buffer)
	err = json.Indent(rdekPlainText, rdec, "", "  ")
	if err != nil {
		panic(err)
	}

	log.Printf("Decrypted DEK %s\n", rdekPlainText)

	// decrypt the object using DEK
	log.Println("Using Decrypted DEK to decrypt object")
	dksr := keyset.NewJSONReader(rdekPlainText)
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
