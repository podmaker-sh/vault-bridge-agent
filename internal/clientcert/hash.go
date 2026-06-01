package clientcert

import sh "crypto/sha256"

func sha256(b []byte) []byte {
	sum := sh.Sum256(b)
	return sum[:]
}
