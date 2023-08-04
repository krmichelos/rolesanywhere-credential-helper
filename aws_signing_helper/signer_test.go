package aws_signing_helper

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go/aws/request"
)

const TestCredentialsFilePath = "/tmp/credentials"

func setup() error {
	generateCredentialProcessDataScript := exec.Command("/bin/sh", "../generate-credential-process-data.sh")
	_, err := generateCredentialProcessDataScript.Output()
	return err
}

func TestMain(m *testing.M) {
	err := setup()
	if err != nil {
		log.Println(err.Error())
		os.Exit(1)
	}
	code := m.Run()
	os.Exit(code)
}

// Simple struct to define fixtures
type CertData struct {
	CertPath string
	KeyType  string
}

// Certificate fixtures should be generated by the script ./generate-certs.sh
// if they do not exist, or need to be updated.
func TestReadCertificateData(t *testing.T) {
	fixtures := []CertData{
		{"../tst/certs/ec-prime256v1-sha256-cert.pem", "EC"},
		{"../tst/certs/rsa-2048-sha256-cert.pem", "RSA"},
	}
	for _, fixture := range fixtures {
		certData, err := ReadCertificateData(fixture.CertPath)

		if err != nil {
			t.Log("Failed to read certificate data")
			t.Fail()
		}

		if certData.KeyType != fixture.KeyType {
			t.Logf("Wrong key type. Expected %s, got %s", fixture.KeyType, certData.KeyType)
			t.Fail()
		}
	}
}

func TestReadInvalidCertificateData(t *testing.T) {
	_, err := ReadCertificateData("../tst/certs/invalid-rsa-cert.pem")
	if err == nil || !strings.Contains(err.Error(), "could not parse certificate") {
		t.Log("Failed to throw a handled error")
		t.Fail()
	}
}

func TestReadCertificateBundleData(t *testing.T) {
	_, err := ReadCertificateBundleData("../tst/certs/cert-bundle.pem")
	if err != nil {
		t.Log("Failed to read certificate bundle data")
		t.Fail()
	}
}

func TestReadPrivateKeyData(t *testing.T) {
	fixtures := []string{
		"../tst/certs/ec-prime256v1-key.pem",
		"../tst/certs/ec-prime256v1-key-pkcs8.pem",
		"../tst/certs/rsa-2048-key.pem",
		"../tst/certs/rsa-2048-key-pkcs8.pem",
	}

	for _, fixture := range fixtures {
		_, err := ReadPrivateKeyData(fixture)

		if err != nil {
			t.Log(fixture)
			t.Log(err)
			t.Log("Failed to read private key data")
			t.Fail()
		}
	}
}

func TestReadInvalidPrivateKeyData(t *testing.T) {
	_, err := ReadPrivateKeyData("../tst/certs/invalid-rsa-key.pem")
	if err == nil || !strings.Contains(err.Error(), "unable to parse private key") {
		t.Log("Failed to throw a handled error")
		t.Fail()
	}
}

func TestBuildAuthorizationHeader(t *testing.T) {
	testRequest, err := http.NewRequest("POST", "https://rolesanywhere.us-west-2.amazonaws.com", nil)
	if err != nil {
		t.Log(err)
		t.Fail()
	}

	certificateList, _ := ReadCertificateBundleData("../tst/certs/rsa-2048-sha256-cert.pem")
	certificate := certificateList[0]
	privateKey, _ := ReadPrivateKeyData("../tst/certs/rsa-2048-key.pem")

	awsRequest := request.Request{HTTPRequest: testRequest}
	signer, signingAlgorithm, err := GetFileSystemSigner(privateKey, certificate, nil)
	if err != nil {
		t.Log(err)
		t.Fail()
	}
	certificate, err = signer.Certificate()
	if err != nil {
		t.Log(err)
		t.Fail()
	}
	certificateChain, err := signer.CertificateChain()
	if err != nil {
		t.Log(err)
		t.Fail()
	}
	requestSignFunction := CreateRequestSignFunction(signer, signingAlgorithm, certificate, certificateChain)
	requestSignFunction(&awsRequest)
}

// Verify that the provided payload was signed correctly with the provided options.
// This function is specifically used for unit testing.
func Verify(payload []byte, publicKey crypto.PublicKey, digest crypto.Hash, sig []byte) (bool, error) {
	var hash []byte
	switch digest {
	case crypto.SHA256:
		sum := sha256.Sum256(payload)
		hash = sum[:]
	case crypto.SHA384:
		sum := sha512.Sum384(payload)
		hash = sum[:]
	case crypto.SHA512:
		sum := sha512.Sum512(payload)
		hash = sum[:]
	default:
		log.Fatal("unsupported digest")
		return false, errors.New("unsupported digest")
	}

	{
		publicKey, ok := publicKey.(*ecdsa.PublicKey)
		if ok {
			valid := ecdsa.VerifyASN1(publicKey, hash, sig)
			return valid, nil
		}
	}

	{
		publicKey, ok := publicKey.(*rsa.PublicKey)
		if ok {
			err := rsa.VerifyPKCS1v15(publicKey, digest, hash, sig)
			return err == nil, nil
		}
	}

	return false, nil
}

func TestSign(t *testing.T) {
	msg := "test message"
	testTable := []CredentialsOpts{}

	ec_digests := []string{"sha1", "sha256", "sha384", "sha512"}
	ec_curves := []string{"prime256v1", "secp384r1"}

	for _, digest := range ec_digests {
		for _, curve := range ec_curves {
			cert := fmt.Sprintf("../tst/certs/ec-%s-%s-cert.pem",
				curve, digest)
			key := fmt.Sprintf("../tst/certs/ec-%s-key.pem", curve)
			testTable = append(testTable, CredentialsOpts{
				CertificateId: cert,
				PrivateKeyId:  key,
			})

			key = fmt.Sprintf("../tst/certs/ec-%s-key-pkcs8.pem", curve)
			testTable = append(testTable, CredentialsOpts{
				CertificateId: cert,
				PrivateKeyId:  key,
			})

			cert = fmt.Sprintf("../tst/certs/ec-%s-%s.p12",
				curve, digest)
			testTable = append(testTable, CredentialsOpts{
				CertificateId: cert,
			})
		}
	}

	rsa_digests := []string{"md5", "sha1", "sha256", "sha384", "sha512"}
	rsa_key_lengths := []string{"1024", "2048", "4096"}

	for _, digest := range rsa_digests {
		for _, keylen := range rsa_key_lengths {
			cert := fmt.Sprintf("../tst/certs/rsa-%s-%s-cert.pem",
				keylen, digest)
			key := fmt.Sprintf("../tst/certs/rsa-%s-key.pem", keylen)
			testTable = append(testTable, CredentialsOpts{
				CertificateId: cert,
				PrivateKeyId:  key,
			})

			key = fmt.Sprintf("../tst/certs/rsa-%s-key-pkcs8.pem", keylen)
			testTable = append(testTable, CredentialsOpts{
				CertificateId: cert,
				PrivateKeyId:  key,
			})

			cert = fmt.Sprintf("../tst/certs/rsa-%s-%s.p12",
				keylen, digest)
			testTable = append(testTable, CredentialsOpts{
				CertificateId: cert,
			})

		}
	}

	digestList := []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512}

	for _, credOpts := range testTable {
		signer, _, err := GetSigner(&credOpts)
		if err != nil {
			var logMsg string
			if credOpts.CertificateId != "" || credOpts.PrivateKeyId != "" {
				logMsg = fmt.Sprintf("Failed to get signer for '%s'/'%s'",
					credOpts.CertificateId, credOpts.PrivateKeyId)
			} else {
				logMsg = fmt.Sprintf("Failed to get signer for '%s'",
					credOpts.CertIdentifier.Subject)
			}
			t.Log(logMsg)
			t.Fail()
			return
		}
		defer signer.Close()

		pubKey := signer.Public()
		if credOpts.CertificateId != "" && pubKey == nil {
			t.Log(fmt.Sprintf("Signer didn't provide public key for '%s'/'%s'",
				credOpts.CertificateId, credOpts.PrivateKeyId))
			t.Fail()
			return
		}

		for _, digest := range digestList {
			signatureBytes, err := signer.Sign(rand.Reader, []byte(msg), digest)
			if err != nil {
				t.Log("Failed to sign the input message")
				t.Fail()
				return
			}

			if pubKey != nil {
				valid, _ := Verify([]byte(msg), pubKey, digest, signatureBytes)
				if !valid {
					t.Log(fmt.Sprintf("Failed to verify the signature for '%s'/'%s'",
						credOpts.CertificateId, credOpts.PrivateKeyId))
					t.Fail()
					return
				}
			}
		}

		signer.Close()
	}
}

func TestCredentialProcess(t *testing.T) {
	testTable := []struct {
		name   string
		server *httptest.Server
	}{
		{
			name:   "create-session-server-response",
			server: GetMockedCreateSessionResponseServer(),
		},
	}
	for _, tc := range testTable {
		credentialsOpts := CredentialsOpts{
			PrivateKeyId:      "../credential-process-data/client-key.pem",
			CertificateId:     "../credential-process-data/client-cert.pem",
			RoleArn:           "arn:aws:iam::000000000000:role/ExampleS3WriteRole",
			ProfileArnStr:     "arn:aws:rolesanywhere:us-east-1:000000000000:profile/41cl0bae-6783-40d4-ab20-65dc5d922e45",
			TrustAnchorArnStr: "arn:aws:rolesanywhere:us-east-1:000000000000:trust-anchor/41cl0bae-6783-40d4-ab20-65dc5d922e45",
			Endpoint:          tc.server.URL,
			SessionDuration:   900,
		}
		t.Run(tc.name, func(t *testing.T) {
			defer tc.server.Close()
			signer, signatureAlgorithm, err := GetSigner(&credentialsOpts)
			if err != nil {
				t.Log("Failed to get signer")
				t.Fail()
				return
			}
			resp, err := GenerateCredentials(&credentialsOpts, signer, signatureAlgorithm)

			if err != nil {
				t.Log(err)
				t.Log("Unable to call credential-process")
				t.Fail()
			}

			if resp.AccessKeyId != "accessKeyId" {
				t.Log("Incorrect access key id")
				t.Fail()
			}
			if resp.SecretAccessKey != "secretAccessKey" {
				t.Log("Incorrect secret access key")
				t.Fail()
			}
			if resp.SessionToken != "sessionToken" {
				t.Log("Incorrect session token")
				t.Fail()
			}
		})
	}
}

func TestCertStoreSignerCreationFails(t *testing.T) {
	testTable := []CredentialsOpts{}

	randomLargeSerial := new(big.Int)
	randomLargeSerial.SetString("123456719012345678901234567890", 10)

	testTable = append(testTable, CredentialsOpts{
		CertIdentifier: CertIdentifier{
			Subject: "invalid-subject",
		},
	})
	testTable = append(testTable, CredentialsOpts{
		CertIdentifier: CertIdentifier{
			Issuer: "invalid-issuer",
		},
	})
	testTable = append(testTable, CredentialsOpts{
		CertIdentifier: CertIdentifier{
			SerialNumber: randomLargeSerial,
		},
	})
	testTable = append(testTable, CredentialsOpts{
		CertIdentifier: CertIdentifier{
			Subject:      "CN=roles-anywhere-rsa-2048-sha25",
			SerialNumber: randomLargeSerial,
		},
	})

	for _, credOpts := range testTable {
		_, _, err := GetSigner(&credOpts)
		if err == nil {
			t.Log("Expected failure when creating certificate store signer, but received none")
			t.Fail()
		}
	}
}

func TestUpdate(t *testing.T) {
	testTable := []struct {
		name                 string
		server               *httptest.Server
		inputFileContents    string
		profile              string
		expectedFileContents string
	}{
		{
			name:   "test-space-separated-keys",
			server: GetMockedCreateSessionResponseServer(),
			inputFileContents: `test
test
test
[test profile]
aws_access_key_id = test
[test]
aws_secret_access_key = test`,
			profile: "test profile",
			expectedFileContents: `test
test
test
[test profile]
aws_access_key_id = accessKeyId
aws_secret_access_key = secretAccessKey
aws_session_token = sessionToken
[test]
aws_secret_access_key = test`,
		},
		{
			name:   "test-profile-with-other-keys",
			server: GetMockedCreateSessionResponseServer(),
			inputFileContents: `test
test
test
[test profile]
aws_access_key_id = test
test_key = test
[test]
aws_secret_access_key = test`,
			profile: "test profile",
			expectedFileContents: `test
test
test
[test profile]
aws_access_key_id = accessKeyId
test_key = test
aws_secret_access_key = secretAccessKey
aws_session_token = sessionToken
[test]
aws_secret_access_key = test`,
		},
		{
			name:   "test-commented-profile",
			server: GetMockedCreateSessionResponseServer(),
			inputFileContents: `test
test
test
# [test profile]
aws_access_key_id = test
[test]
aws_secret_access_key = test`,
			profile: "test profile",
			expectedFileContents: `test
test
test
# [test profile]
aws_access_key_id = test
[test]
aws_secret_access_key = test
[test profile]
aws_access_key_id = accessKeyId
aws_secret_access_key = secretAccessKey
aws_session_token = sessionToken
`,
		},
		{
			name:   "test-profile-does-not-exist",
			server: GetMockedCreateSessionResponseServer(),
			inputFileContents: `test
test
test
[test]
aws_secret_access_key = test`,
			profile: "test profile",
			expectedFileContents: `test
test
test
[test]
aws_secret_access_key = test
[test profile]
aws_access_key_id = accessKeyId
aws_secret_access_key = secretAccessKey
aws_session_token = sessionToken
`,
		},
		{
			name:   "test-first-word-in-profile-matches",
			server: GetMockedCreateSessionResponseServer(),
			inputFileContents: `test
test
test
[test profile]
aws_access_key_id = test
[test]
aws_secret_access_key = test`,
			profile: "test",
			expectedFileContents: `test
test
test
[test profile]
aws_access_key_id = test
[test]
aws_access_key_id = accessKeyId
aws_secret_access_key = secretAccessKey
aws_session_token = sessionToken`,
		},
		{
			name:   "test-multiple-profiles-with-same-name",
			server: GetMockedCreateSessionResponseServer(),
			inputFileContents: `test
test
test
[test]
test_key = test
[test profile]
aws_access_key_id = test
[test]
aws_secret_access_key = test`,
			profile: "test",
			expectedFileContents: `test
test
test
[test]
test_key = test
aws_access_key_id = accessKeyId
aws_secret_access_key = secretAccessKey
aws_session_token = sessionToken
[test profile]
aws_access_key_id = test
[test]
aws_secret_access_key = test`,
		},
	}
	for _, tc := range testTable {
		credentialsOpts := CredentialsOpts{
			PrivateKeyId:      "../credential-process-data/client-key.pem",
			CertificateId:     "../credential-process-data/client-cert.pem",
			RoleArn:           "arn:aws:iam::000000000000:role/ExampleS3WriteRole",
			ProfileArnStr:     "arn:aws:rolesanywhere:us-east-1:000000000000:profile/41cl0bae-6783-40d4-ab20-65dc5d922e45",
			TrustAnchorArnStr: "arn:aws:rolesanywhere:us-east-1:000000000000:trust-anchor/41cl0bae-6783-40d4-ab20-65dc5d922e45",
			Endpoint:          tc.server.URL,
			SessionDuration:   900,
		}
		t.Run(tc.name, func(t *testing.T) {
			SetupTests()
			defer tc.server.Close()
			os.Setenv(AwsSharedCredentialsFileEnvVarName, TestCredentialsFilePath)
			_, err := GetCredentialsFileContents() // first create the credentials file with the appropriate permissions
			if err != nil {
				t.Log("unable to create credentials file for testing")
				t.Fail()
			}
			writeOnlyCredentialsFile, err := GetWriteOnlyCredentialsFile() // then obtain a handle to the credentials file to perform write operations
			if err != nil {
				t.Log("unable to write to credentials file for testing")
				t.Fail()
			}
			defer writeOnlyCredentialsFile.Close()
			writeOnlyCredentialsFile.WriteString(tc.inputFileContents)

			Update(credentialsOpts, tc.profile, true)

			fileByteContents, _ := ioutil.ReadFile(TestCredentialsFilePath)
			fileStringContents := trimLastChar(string(fileByteContents))
			if fileStringContents != tc.expectedFileContents {
				t.Log("unexpected file contents")
				t.Fail()
			}
		})
	}
}

func TestUpdateFilePermissions(t *testing.T) {
	testTable := []struct {
		name                 string
		server               *httptest.Server
		profile              string
		expectedFileContents string
	}{
		{
			name:    "test-space-separated-keys",
			server:  GetMockedCreateSessionResponseServer(),
			profile: "test profile",
			expectedFileContents: `[test profile]
aws_access_key_id = accessKeyId
aws_secret_access_key = secretAccessKey
aws_session_token = sessionToken
`,
		},
	}
	for _, tc := range testTable {
		credentialsOpts := CredentialsOpts{
			PrivateKeyId:      "../credential-process-data/client-key.pem",
			CertificateId:     "../credential-process-data/client-cert.pem",
			RoleArn:           "arn:aws:iam::000000000000:role/ExampleS3WriteRole",
			ProfileArnStr:     "arn:aws:rolesanywhere:us-east-1:000000000000:profile/41cl0bae-6783-40d4-ab20-65dc5d922e45",
			TrustAnchorArnStr: "arn:aws:rolesanywhere:us-east-1:000000000000:trust-anchor/41cl0bae-6783-40d4-ab20-65dc5d922e45",
			Endpoint:          tc.server.URL,
			SessionDuration:   900,
		}
		t.Run(tc.name, func(t *testing.T) {
			SetupTests()
			defer tc.server.Close()
			os.Setenv(AwsSharedCredentialsFileEnvVarName, TestCredentialsFilePath)

			Update(credentialsOpts, tc.profile, true)

			fileByteContents, _ := ioutil.ReadFile(TestCredentialsFilePath)
			fileStringContents := trimLastChar(string(fileByteContents))
			if fileStringContents != tc.expectedFileContents {
				t.Log("unexpected file contents")
				t.Fail()
			}

			info, _ := os.Stat(TestCredentialsFilePath)
			mode := info.Mode()
			if mode != ((1 << 8) | (1 << 7)) {
				t.Log("unexpected file mode")
				t.Fail()
			}
		})
	}
}

func TestGenerateLongToken(t *testing.T) {
	_, err := GenerateToken(150)
	if err == nil {
		t.Log("token generation should've failed since token size is too large")
		t.Fail()
	}
}

func TestGenerateToken(t *testing.T) {
	token1, err := GenerateToken(100)
	if err != nil {
		t.Log("unexpected failure in generating token")
		t.Fail()
	}

	token2, err := GenerateToken(100)
	if err != nil {
		t.Log("unexpected failure in generating token")
		t.Fail()
	}

	if token1 == token2 {
		t.Log("expected two randomly generated tokens to be different")
		t.Fail()
	}
}

func TestStoreValidToken(t *testing.T) {
	token, err := GenerateToken(100)
	if err != nil {
		t.Log("unexpected failure in generating token")
		t.Fail()
	}

	err = InsertToken(token, time.Now().Add(time.Second*time.Duration(100)))
	if err != nil {
		t.Log("unexpected failure when inserting token")
		t.Fail()
	}

	httpRequest, err := http.NewRequest("GET", "http://127.0.0.1", nil)
	if err != nil {
		t.Log("unable to create test http request")
		t.Fail()
	}
	httpRequest.Header.Add(EC2_METADATA_TOKEN_HEADER, token)

	err = CheckValidToken(nil, httpRequest)
	if err != nil {
		t.Log("expected previously inserted token to be valid")
		t.Fail()
	}
}

func Test(t *testing.T) {
	httpRequest, err := http.NewRequest("GET", "http://127.0.0.1", nil)
	if err != nil {
		t.Log("unable to create test http request")
		t.Fail()
	}
	httpRequest.Header.Add("test-header", "test-header-value")

	headerNames := [4]string{"Test-Header", "test-header", "TEST-HEADER", "tEST-hEadeR"}
	for _, header := range headerNames {
		testHeaderValue := httpRequest.Header.Get(header)
		if testHeaderValue != "test-header-value" {
			t.Log("header name canonicalization not working as expected")
			t.Fail()
		}
	}
}

func SetupTests() {
	os.Remove(TestCredentialsFilePath)
}

func trimLastChar(s string) string {
	r, size := utf8.DecodeLastRuneInString(s)
	if r == utf8.RuneError && (size == 0 || size == 1) {
		size = 0
	}
	return s[:len(s)-size]
}

func GetMockedCreateSessionResponseServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{
			"credentialSet":[
			  {
				"assumedRoleUser": {
				"arn": "arn:aws:sts::000000000000:assumed-role/ExampleS3WriteRole",
				"assumedRoleId": "assumedRoleId"
				},
				"credentials":{
				  "accessKeyId": "accessKeyId",
				  "expiration": "2022-07-27T04:36:55Z",
				  "secretAccessKey": "secretAccessKey",
				  "sessionToken": "sessionToken"
				},
				"packedPolicySize": 10,
				"roleArn": "arn:aws:iam::000000000000:role/ExampleS3WriteRole",
				"sourceIdentity": "sourceIdentity"
			  }
			],
			"subjectArn": "arn:aws:rolesanywhere:us-east-1:000000000000:subject/41cl0bae-6783-40d4-ab20-65dc5d922e45"
		  }`))
	}))
}
