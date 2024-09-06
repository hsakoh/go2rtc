package webrtc

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

type sigV4RequestSigner struct {
	region      string
	credentials aws.Credentials
	service     string
}

const DEFAULT_SERVICE string = "kinesisvideo"
const DEFAULT_ALGORITHM string = "AWS4-HMAC-SHA256"

func NewSigV4RequestSigner(region string, credentials aws.Credentials) *sigV4RequestSigner {
	return &sigV4RequestSigner{
		region:      region,
		credentials: credentials,
		service:     DEFAULT_SERVICE,
	}
}

func (s *sigV4RequestSigner) getSignedURL(endpoint string, queryParams url.Values, date time.Time) string {
	// Prepare date strings
	datetimeString := date.Format("20060102T150405Z")
	dateString := datetimeString[:8]
	protocol := "wss"
	urlProtocol := fmt.Sprintf("%s://", protocol)

	// Parse endpoint
	pathStartIndex := strings.Index(endpoint[len(urlProtocol):], "/")
	var host, path string
	if pathStartIndex < 0 {
		host = endpoint[len(urlProtocol):]
		path = "/"
	} else {
		host = endpoint[len(urlProtocol):pathStartIndex]
		path = endpoint[pathStartIndex:]
	}
	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", dateString, s.region, s.service)
	canonicalQueryParams := url.Values{}
	for k, v := range queryParams {
		canonicalQueryParams[k] = v
	}
	// Prepare method and host
	method := "GET"
	signedHeaders := "host"

	// Prepare canonical query string
	canonicalQueryParams.Add("X-Amz-Algorithm", DEFAULT_ALGORITHM)
	canonicalQueryParams.Add("X-Amz-Credential", fmt.Sprintf("%s/%s", s.credentials.AccessKeyID, credentialScope))
	canonicalQueryParams.Add("X-Amz-Date", datetimeString)
	canonicalQueryParams.Add("X-Amz-Expires", "299")
	canonicalQueryParams.Add("X-Amz-SignedHeaders", signedHeaders)
	if s.credentials.SessionToken != "" {
		canonicalQueryParams.Add("X-Amz-Security-Token", s.credentials.SessionToken)
	}
	canonicalQueryString := queryParamsToQueryString(canonicalQueryParams)

	// Prepare canonical headers
	canonicalHeadersString := fmt.Sprintf("host:%s\n", host)

	// Prepare payload hash
	payloadHash := hashSha256("")
	canonicalRequest := strings.Join([]string{method, path, canonicalQueryString, canonicalHeadersString, signedHeaders, payloadHash}, "\n")

	// Combine canonical request parts into a canonical request string and hash
	canonicalRequestHash := hashSha256(canonicalRequest)

	// Create signature
	stringToSign := strings.Join([]string{DEFAULT_ALGORITHM, datetimeString, credentialScope, canonicalRequestHash}, "\n")
	signingKey := s.getSignatureKey(dateString)
	signature := fmt.Sprintf("%x", signHmac(signingKey, []byte(stringToSign)))

	// Add signature to query params
	canonicalQueryParams.Add("X-Amz-Signature", signature)

	// Create signed URL
	return fmt.Sprintf("%s://%s%s?%s", protocol, host, path, queryParamsToQueryString(canonicalQueryParams))
}

func queryParamsToQueryString(queryParams url.Values) string {
	keys := make([]string, len(queryParams))
	index := 0
	for key := range queryParams {
		keys[index] = key
		index++
	}
	sort.Strings(keys)

	var buff bytes.Buffer
	index = 0
	for _, key := range keys {
		for _, value := range queryParams[key] {
			if index != 0 {
				buff.WriteRune('&')
			}
			index++
			buff.WriteString(key)
			buff.WriteRune('=')
			buff.WriteString(url.QueryEscape(value))
		}
	}
	return buff.String()
}

func hashSha256(in string) string {
	h := sha256.New()
	h.Write([]byte(in))
	return fmt.Sprintf("%x", h.Sum(nil))
}
func signHmac(key []byte, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}
func (s *sigV4RequestSigner) getSignatureKey(dateString string) []byte {
	kDate := signHmac([]byte(fmt.Sprintf("AWS4%s", s.credentials.SecretAccessKey)), []byte(dateString))
	kRegion := signHmac(kDate, []byte(s.region))
	kService := signHmac(kRegion, []byte(s.service))
	return signHmac(kService, []byte("aws4_request"))
}
