package util

import "encoding/base64"

// Base64URLEncode Base64URLEncode
// more efficient than hex encoding
func Base64URLEncode(b []byte) string {
	return base64.URLEncoding.EncodeToString(b)
}

// Base64URLDecode Base64URLDecode
func Base64URLDecode(s string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(s)
}

// Base64STDEncode Base64STDEncode
func Base64STDEncode(src []byte) *[]byte {
	dst := make([]byte, base64.StdEncoding.EncodedLen(len(src)))
	base64.StdEncoding.Encode(dst, src)
	return &dst
}

// Base64STDDecode Base64STDDecode
func Base64STDDecode(src []byte) ([]byte, error) {
	dst := make([]byte, base64.StdEncoding.DecodedLen(len(src)))
	n, err := base64.StdEncoding.Decode(dst, src)
	if err != nil {
		return nil, err
	}
	return dst[0:n], nil
}

// Base64STDDecodeString Base64STDDecodeString
func Base64STDDecodeString(src string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(src)
}

// Base64RawSTDDecodeString Base64RawSTDDecodeString
func Base64RawSTDDecodeString(src string) ([]byte, error) {
	return base64.RawStdEncoding.DecodeString(src)
}

// Base64RawSTDEncode Base64RawSTDEncode
// unpadded base64 encoding
func Base64RawSTDEncode(src []byte) *[]byte {
	dst := make([]byte, base64.RawStdEncoding.EncodedLen(len(src)))
	base64.RawStdEncoding.Encode(dst, src)
	return &dst
}

// Base64RawSTDDecode Base64RawSTDDecode
func Base64RawSTDDecode(src []byte) *[]byte {
	dst := make([]byte, base64.RawStdEncoding.DecodedLen(len(src)))
	base64.RawStdEncoding.Decode(dst, src)
	return &dst
}
