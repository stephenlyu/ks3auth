package ks3auth

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"net/url"
	"sort"
	"strings"
)

/**
 * key 进行encodeURIComponent编码，'/'不能被编码
 *
 */
func encodeKey(key string) string {
	var newKey = url.QueryEscape(key)
	newKey = strings.ReplaceAll(newKey, "%2F", "/")
	if newKey[0] == '/' {
		newKey = strings.ReplaceAll(newKey, "/", "%2F")
	}
	// '//'needs convert to '/%2F'
	newKey = strings.ReplaceAll(newKey, "//", "/%2F")
	return newKey
}

func key2Lower(headers map[string]string) map[string]string {
	ret := make(map[string]string)
	if headers != nil {
		for k, v := range headers {
			ret[strings.ToLower(k)] = v
		}
	}
	return headers
}

func generateHeaders(headers map[string]string) string {
	var ret string
	if headers != nil {
		var keys []string
		for k := range headers {
			if strings.HasPrefix(k, "x-kss") {
				keys = append(keys, k)
			}
		}
		sort.Slice(keys, func(i int, j int) bool {
			return keys[i] < keys[j]
		})
		for i, key := range keys {
			ret += key + ":" + headers[key]
			if i < len(keys)-1 {
				ret += "\n"
			}
		}
	}

	return ret
}

func hmacSha1(keyStr string, value string) string {

	key := []byte(keyStr)
	mac := hmac.New(sha1.New, key)
	mac.Write([]byte(value))
	//进行base64编码
	res := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return res
}

func CalcSignature(sk string, bucket string, key string, resource string,
	httpVerb string, headers map[string]string, timestamp string) string {
	var Resource = encodeKey(key) + resource
	var authHeaders = key2Lower(headers)
	var canonicalizedKssHeaders = generateHeaders(authHeaders)
	var canonicalizedResource = "/" + bucket + "/" + Resource
	var contentType = authHeaders["content-type"]
	var contentMD5 = authHeaders["content-md5"]
	var string2Sign string
	if canonicalizedKssHeaders != "" {
		string2Sign = httpVerb + "\n" + contentMD5 + "\n" + contentType + "\n" + timestamp + "\n" + canonicalizedKssHeaders + "\n" + canonicalizedResource
	} else {
		string2Sign = httpVerb + "\n" + contentMD5 + "\n" + contentType + "\n" + timestamp + "\n" + canonicalizedResource
	}
	var signature = hmacSha1(sk, string2Sign)
	return signature
}
