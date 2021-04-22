
### End-to-End Stream encryption with gsutil and TINK

Sample procedure that does local encryption of a file and then uploads that file to GCS.

Unlike GCS [Customer Managed Encryption Key](https://cloud.google.com/storage/docs/encryption/customer-managed-keys) and [Customer Supplied Encryption Key](https://cloud.google.com/storage/docs/encryption/customer-supplied-keys) for GCS, this procedure encrypts a file locally before uploading and then decrypts a file after download.  This way, not even Google will every know the contents of a file at anytime by any means (not via transit, not in memory,not via KMS).  With CSEK, the key is transferred over TLS to Google...with CMEK and google still retains indirect in-use access to key during KMS operations (meaning google could still view the raw key if its google-hosted KMS or apply crypto operations referencing external KMS). Either way, the raw data will be visible on GCP's network.

This procedure insteaddoes end-to-end encrytion where the contents are encrypted _before_ uploading and will remain encrypted at all times.  Only the user that has access to the decryption keys can decode the data.

Specifically, this procedure demonstrates how to use GCS streaming transfers with Envelope Encryption.  You can also extend a similar technique to other technologies like wrapping the [PubSub Message](https://github.com/salrashid123/gcp_pubsub_message_encryption).


This article essentially performs [Envelope Encryption](https://cloud.google.com/kms/docs/envelope-encryption):

Encryption:

- User has possession of a permanent Key Encryption Key (KEK)
- User generates a new data encryption key (DEK)
- User encrypts the GCS file using DEK
- User encrypts the DEK with the KEK
- User uploads the encrypted file and attaches the encrypted DEK as metadata


Decryption

- User has possession of a permanent Key Encryption Key (KEK)
- User downloads the encrypted object and its metadata
- User decrypts the DEK from the metadata using KEK
- User uses DEK to decrypt object contents


In this article, we will first use `openssl` and `gsutil`  and then [Tink](https://github.com/google/tink) and the `GCS SDK`.  In both cases the encryption/decryption and upload is done using streaming.



### gsutil Streaming Transfer client-side envelope encryption

gsutil already supports [Streaming Transfers](https://cloud.google.com/storage/docs/gsutil/commands/cp#streaming-transfers) so in this case, all we are going to do is generate a KEK, DEK, then encrypt the data with openssl and pipe to gsutil.


#### KEK: Symmetric DEK: Symmetric

```bash
export PROJECT_ID=`gcloud config get-value core/project`
export BUCKET_NAME=$PROJECT_ID-enctest
gsutil mb gs://$BUCKET_NAME

# create a sample file
openssl rand --base64 1000000 > secrets.txt
sha256sum secrets.txt
  
# generate kek and dek
openssl rand 32 > kek.key
openssl rand 32 > dek.key

# encrypt the dek with the kek
openssl enc -pbkdf2 -in dek.key -out dek.key.enc -aes-256-cbc --pass file:./kek.key
export dek_enc=`xxd -p -c 200 dek.key.enc`
export kek_hash=`sha256sum kek.key | cut -d " " -f 1`

# stream encrypt and upload the file...attach the encrypted dek as metadata
openssl enc -pbkdf2 -in secrets.txt -aes-256-cbc -pass file:./dek.key | gsutil  -h "x-goog-meta-dek:$dek_enc" -h "x-goog-meta-kek-hash:$kek_hash" cp - gs://$BUCKET_NAME/secrets.txt.enc

# view the encrypted file metadata which will include the encrypted DEK
gsutil stat gs://$BUCKET_NAME/secrets.txt.enc

# download the dek key (no, i don't know how to use gsutil stat to just get the dek)
export TOKEN=`gcloud auth print-access-token`
curl -s -H "Authorization: Bearer $TOKEN"   "https://storage.googleapis.com/storage/v1/b/$BUCKET_NAME/o/secrets.txt.enc" | jq -r '.metadata.dek' | xxd -r -p - dek.key.enc

# decrypt the dek with the kek
openssl enc -d -aes-256-cbc -pbkdf2 -in dek.key.enc -out dek.key.ptext  -pass file:./kek.key

# stream download the data, decrypt to file
gsutil cp  gs://$BUCKET_NAME/secrets.txt.enc - | openssl enc -d -aes-256-cbc -pbkdf2  -out secrets.txt.ptext  -pass file:./dek.key

sha256sum secrets.txt.ptext
 ```

#### KEK: Asymmetric  DEK: Symmetric

```bash
export PROJECT_ID=`gcloud config get-value core/project`
export BUCKET_NAME=$PROJECT_ID-enctest
gsutil mb gs://$BUCKET_NAME

# create a sample file
openssl rand --base64 1000000 > secrets.txt
sha256sum secrets.txt
  
# generate kek and dek
openssl genrsa -out kek.key 2048
openssl rsa -in kek.key -outform PEM -pubout -out kek_public.pem
openssl rand 32 > dek.key

# encrypt the dek with the kek public key
openssl rsautl -encrypt -inkey kek_public.pem -pubin -in dek.key -out dek.key.enc

export dek_enc=`xxd -p -c 800 dek.key.enc`
export kek_hash=`sha256sum kek_public.pem | cut -d " " -f 1`

# stream encrypt and upload the file...attach the encrypted dek as metadata
openssl enc -pbkdf2 -in secrets.txt -aes-256-cbc -pass file:./dek.key | gsutil  -h "x-goog-meta-dek:$dek_enc" -h "x-goog-meta-kek-hash:$kek_hash" cp - gs://$BUCKET_NAME/secrets.txt.enc

# view the encrypted file metadata which will include the encrypted DEK
gsutil stat gs://$BUCKET_NAME/secrets.txt.enc

# download the dek key (no, i don't know how to use gsutil stat to just get the dek)
export TOKEN=`gcloud auth print-access-token`
curl -s -H "Authorization: Bearer $TOKEN"   "https://storage.googleapis.com/storage/v1/b/$BUCKET_NAME/o/secrets.txt.enc" | jq -r '.metadata.dek' | xxd -r -p - dek.key.enc

# decrypt the dek with the kek private key
openssl rsautl -decrypt -inkey kek.key -in dek.key.enc -out dek.key.ptext

# stream download the data, decrypt to file
gsutil cp  gs://$BUCKET_NAME/secrets.txt.enc - | openssl enc -d -aes-256-cbc -pbkdf2  -out secrets.txt.ptext  -pass file:./dek.key

sha256sum secrets.txt.ptext
```

---

### TINK Streaming Transfer with GCS SDK


For TINK, we will specify a static KEK, then generate the DEK per object in [AEAD](https://pkg.go.dev/github.com/google/tink/go/aead
) mode.  THe encrypted DEK is attached into the GCS objects metadata.


The following shows the output of the KEK keyID, KEK itself  (NOTE: i'm showing the raw key here just for demo!)

THe flow then shows the DEK used and its internal key...then the raw hash value of the plaintext file.  The file is then encrypted and uploaded.

Upon download, the file's metadata DEK is decrypted and used to decrypt the file itself...finally the plaintext file's hash value is shown.

```log
$ go run main.go 
    2021/04/21 10:52:58 Using KEK ID: 2055075504
    2021/04/21 10:52:58 Using KEK: 
    {
    "primaryKeyId": 2055075504,
    "key": [
        {
        "keyData": {
            "typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey",
            "value": "EgcIgCAQIBgDGiAKuLgp8pUCNGdrjdRVair5IwVB3aapACGbzVdbt7NCDw==",
            "keyMaterialType": "SYMMETRIC"
        },
        "status": "ENABLED",
        "keyId": 2055075504,
        "outputPrefixType": "RAW"
        }
    ]
    }
    2021/04/21 10:52:58 Creating new DEK
    2021/04/21 10:52:58 New DEK 
    {
    "primaryKeyId": 3562865539,
    "key": [
        {
        "keyData": {
            "typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey",
            "value": "EgcIgCAQIBgDGiAXrs3E/ySOU7w+3TLTpDr4OL4x3mlLSax/s0a8RU/t0A==",
            "keyMaterialType": "SYMMETRIC"
        },
        "status": "ENABLED",
        "keyId": 3562865539,
        "outputPrefixType": "RAW"
        }
    ]
    }
    2021/04/21 10:52:58 Encrypting DEK with KEK
    2021/04/21 10:52:58 Encrypted DEK: 
    KKTMBa2PPqsxydzpfa7oMqAZCUXbyQvX+LWNqPA+VpfLCtZ4+2UBWlXc7OWdZ955ATmpmjpYeCu8wonNIKfWDUX2fEIpjPXVkQGJJrG372/GshSJ9Lgln1pVliz68Gv4YllPK6jiHw4YJDHrMxTDLDnHZkHA5t4RPMDpX06UfgmOJ8gj44qoWkhzLfCcMyE9S+Sc/sZN0MDEfmHIkhrFEtin3Pg0ahDQ7Yahq4yORupAvE35u+mWotmnTQ1ZbmrAp3e87CxIVWqdewTgdyYN0xYK4vn0bVmHBkledUcOJ2qHC+IzQKhO3zIiPjIFaf5XlTDQ3kam4o6dBhCnaCpiZsChPbgk4jDfPixtJq8SbM2joDzojBdSUesOYkg8cS2bMHtE1LXUrJRFO5N9NibkzX9KttEO4XmPCoBLa0y/WUUEJuuGzqvOGwP+1WoQGYRG0aEKyPBANA
    2021/04/21 10:52:58 Generating Hash of plainText file
    2021/04/21 10:52:58 Plaintext file hash 5da4ab591a203cbe9b322c68d8187b685a07d7fc0ebc9810bbdb7edab6a14a11
    2021/04/21 10:52:58 Encrypting file with DEK
    2021/04/21 10:52:59 File Uploaded
    2021/04/21 10:52:59 Downloading encrypted File
    2021/04/21 10:52:59 	x-goog-meta-dek_enc = KKTMBa2PPqsxydzpfa7oMqAZCUXbyQvX+LWNqPA+VpfLCtZ4+2UBWlXc7OWdZ955ATmpmjpYeCu8wonNIKfWDUX2fEIpjPXVkQGJJrG372/GshSJ9Lgln1pVliz68Gv4YllPK6jiHw4YJDHrMxTDLDnHZkHA5t4RPMDpX06UfgmOJ8gj44qoWkhzLfCcMyE9S+Sc/sZN0MDEfmHIkhrFEtin3Pg0ahDQ7Yahq4yORupAvE35u+mWotmnTQ1ZbmrAp3e87CxIVWqdewTgdyYN0xYK4vn0bVmHBkledUcOJ2qHC+IzQKhO3zIiPjIFaf5XlTDQ3kam4o6dBhCnaCpiZsChPbgk4jDfPixtJq8SbM2joDzojBdSUesOYkg8cS2bMHtE1LXUrJRFO5N9NibkzX9KttEO4XmPCoBLa0y/WUUEJuuGzqvOGwP+1WoQGYRG0aEKyPBANA
    2021/04/21 10:52:59 	x-goog-meta-kek_id = 2055075504
    2021/04/21 10:52:59 Found object metadata KEK ID: 2055075504
    2021/04/21 10:52:59 Decrypting DEK with KEK
    2021/04/21 10:52:59 Decrypted DEK {
    "primaryKeyId": 3562865539,
    "key": [
        {
        "keyData": {
            "typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey",
            "value": "EgcIgCAQIBgDGiAXrs3E/ySOU7w+3TLTpDr4OL4x3mlLSax/s0a8RU/t0A==",
            "keyMaterialType": "SYMMETRIC"
        },
        "status": "ENABLED",
        "keyId": 3562865539,
        "outputPrefixType": "RAW"
        }
    ]
    }
    2021/04/21 10:52:59 Using Decrypted DEK to decrypt object
    2021/04/21 10:52:59 Calculating hash of decrypted file
    2021/04/21 10:52:59 Decrypted file hash 5da4ab591a203cbe9b322c68d8187b685a07d7fc0ebc9810bbdb7edab6a14a11
```

```bash
$ gsutil stat gs://mineral-minutia-820-enctest/secrets.txt.enc
        gs://mineral-minutia-820-enctest/secrets.txt.enc:
            Creation time:          Wed, 21 Apr 2021 14:52:59 GMT
            Update time:            Wed, 21 Apr 2021 14:52:59 GMT
            Storage class:          STANDARD
            Content-Length:         1359522
            Content-Type:           application/octet-stream
            Metadata:               
                x-goog-meta-dek_enc:KKTMBa2PPqsxydzpfa7oMqAZCUXbyQvX+LWNqPA+VpfLCtZ4+2UBWlXc7OWdZ955ATmpmjpYeCu8wonNIKfWDUX2fEIpjPXVkQGJJrG372/GshSJ9Lgln1pVliz68Gv4YllPK6jiHw4YJDHrMxTDLDnHZkHA5t4RPMDpX06UfgmOJ8gj44qoWkhzLfCcMyE9S+Sc/sZN0MDEfmHIkhrFEtin3Pg0ahDQ7Yahq4yORupAvE35u+mWotmnTQ1ZbmrAp3e87CxIVWqdewTgdyYN0xYK4vn0bVmHBkledUcOJ2qHC+IzQKhO3zIiPjIFaf5XlTDQ3kam4o6dBhCnaCpiZsChPbgk4jDfPixtJq8SbM2joDzojBdSUesOYkg8cS2bMHtE1LXUrJRFO5N9NibkzX9KttEO4XmPCoBLa0y/WUUEJuuGzqvOGwP+1WoQGYRG0aEKyPBANA
                x-goog-meta-kek_id: 2055075504
            Hash (crc32c):          pYwnpQ==
            Hash (md5):             ZXnfa+qu5IPk6F/byB1VSw==
            ETag:                   CNm2hsDLj/ACEAE=
            Generation:             1619016779144025
            Metageneration:         1
```



#### Tink Envelope Encryption with KMS

Tink already supports KMS encrypted keysets where the data is wrapped with a KMS key.  The keyset looks like this:

```json
{
  "encryptedKeyset": "AAAAdAolAJk/lVWUyuHybpZtmhZ+bX7JWuAJ2umsTSbtGylE3UIJtv+P7RJLACsKZVKDg1DIkKlSNcd9yztu26HxqP8D3HB8MMx+BgKtMjSqGDZ9/CzZ9fcJSkn90hbtbtkVKvftIvnDh9JcAv52iXvqNrhAvaAHvyzDFVn6wrCD1HrTUKDYe71KLbAlynbZh3Q7XCzvToNNPL/UzlSrGGf/lSu0NYPERhTPvwBYniJj+WgGmKWcXmmyLNXbLtAlFAFWSG9ssvo4kKFwsWeNZcsqFu+5hrT8nXbKJ2Hw0NZIDytCtjmScRZoPCbZ3M+Z7pKL+XnHeUUnEIQd1lSYf709ssA665IDOOqaijIy2cXt6xMizPKpUorIuG53Sbax22AcDY9+tmyiF1yRC4n9PETwmXEIzf+Jq02N4SstqtAyIDwm420jiSdioYbJq+YWrDQTQtNXNnlF4xEow5NPF7rexRmw5jihi7yj8wlcwOUOZKjEcp6w1KQNPBhmXuze2VaT9PvBzYa/",
  "keysetInfo": {
    "primaryKeyId": 1049379665,
    "keyInfo": [
      {
        "typeUrl": "type.googleapis.com/google.crypto.tink.KmsEnvelopeAeadKey",
        "status": "ENABLED",
        "keyId": 1049379665,
        "outputPrefixType": "TINK"
      }
    ]
  }
}
```

Where you must specify the KEK to unwrap and use the key.   For more info see [TINK Key management](https://github.com/google/tink/blob/master/docs/KEY-MANAGEMENT.md)

While i could have used KMS-backed keysets, i wanted to demo this without dependencies on any specific KMS involved.  If you want to extend this sample with KMS keys,see 

- [salrashid123/tink_samples/tree/main/client_kms](https://github.com/salrashid123/tink_samples/tree/main/client_kms)


---

### Appendix

Plain Envelope Encryption Samples with openssl

```bash
echo "thepassword" > secrets.txt

KEK: Asymmetric
DEK: Symmetric
    openssl genrsa -out KEK.pem 2048
    openssl rsa -in KEK.pem -outform PEM -pubout -out KEK_PUBLIC.pem
    

    openssl rand 32 > DEK.key
    openssl enc -aes-256-cbc -salt -pbkdf2 -in secrets.txt -out secrets.txt.enc -pass file:./DEK.key

    openssl rsautl -encrypt -inkey KEK_PUBLIC.pem -pubin -in DEK.key -out DEK.key.enc

    openssl rsautl -decrypt -inkey KEK.pem -in DEK.key.enc -out DEK.key.ptext
    openssl enc -d -aes-256-cbc -pbkdf2 -in secrets.txt.enc -out secrets.txt.ptext  -pass file:./DEK.key.ptext
    more secrets.txt.ptext

KEK: Symmetric
DEK: Symmetric
    openssl rand 32 > kek.key
    openssl rand 32 > dek.key

    openssl enc -pbkdf2 -in secrets.txt -out secrets.txt.enc -aes-256-cbc -pass file:./dek.key
    openssl enc -pbkdf2 -in dek.key -out dek.key.enc -aes-256-cbc --pass file:./kek.key

    openssl enc -d -aes-256-cbc -pbkdf2 -in dek.key.enc -out dek.key.ptext  -pass file:./kek.key
    openssl enc -d -aes-256-cbc -pbkdf2 -in secrets.txt.enc -out secrets.txt.ptext  -pass file:./dek.key.ptext
```
