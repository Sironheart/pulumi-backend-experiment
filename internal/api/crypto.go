package api

import (
	"encoding/base64"
	"net/http"
)

const (
	maxCryptoBatchItems      = 1000
	maxCryptoPlaintextBytes  = 1 << 20
	maxCryptoCiphertextBytes = 2 << 20
)

// requireCrypter guards secrets endpoints when no KMS key is configured.
func (s *Server) requireCrypter(w http.ResponseWriter) (Crypter, bool) {
	if s.crypter == nil {
		writeError(w, http.StatusBadRequest, "no kmsKeyArn configured")
		return nil, false
	}
	return s.crypter, true
}

func (s *Server) encryptValue(w http.ResponseWriter, r *http.Request) {
	c, ok := s.requireCrypter(w)
	if !ok {
		return
	}
	var req struct {
		Plaintext []byte `json:"plaintext"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeDecodeError(w, err, "invalid request")
		return
	}
	ciphertext, ok := encryptOne(w, r, c, req.Plaintext)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ciphertext": ciphertext})
}

func (s *Server) decryptValue(w http.ResponseWriter, r *http.Request) {
	c, ok := s.requireCrypter(w)
	if !ok {
		return
	}
	var req struct {
		Ciphertext []byte `json:"ciphertext"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeDecodeError(w, err, "invalid request")
		return
	}
	plaintext, ok := decryptOne(w, r, c, req.Ciphertext)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"plaintext": plaintext})
}

func (s *Server) batchEncrypt(w http.ResponseWriter, r *http.Request) {
	c, ok := s.requireCrypter(w)
	if !ok {
		return
	}
	var req struct {
		Plaintexts [][]byte `json:"plaintexts"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeDecodeError(w, err, "invalid request")
		return
	}
	if len(req.Plaintexts) > maxCryptoBatchItems {
		writeError(w, http.StatusRequestEntityTooLarge, "crypto batch too large")
		return
	}
	out := make([][]byte, 0, len(req.Plaintexts))
	for _, p := range req.Plaintexts {
		ct, ok := encryptOne(w, r, c, p)
		if !ok {
			return
		}
		out = append(out, ct)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ciphertexts": out})
}

func (s *Server) batchDecrypt(w http.ResponseWriter, r *http.Request) {
	c, ok := s.requireCrypter(w)
	if !ok {
		return
	}
	var req struct {
		Ciphertexts [][]byte `json:"ciphertexts"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeDecodeError(w, err, "invalid request")
		return
	}
	if len(req.Ciphertexts) > maxCryptoBatchItems {
		writeError(w, http.StatusRequestEntityTooLarge, "crypto batch too large")
		return
	}
	out := map[string][]byte{}
	for _, ct := range req.Ciphertexts {
		pt, ok := decryptOne(w, r, c, ct)
		if !ok {
			return
		}
		out[base64.StdEncoding.EncodeToString(ct)] = pt
	}
	writeJSON(w, http.StatusOK, map[string]any{"plaintexts": out})
}

func encryptOne(w http.ResponseWriter, r *http.Request, c Crypter, plaintext []byte) ([]byte, bool) {
	if len(plaintext) > maxCryptoPlaintextBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "plaintext too large")
		return nil, false
	}
	ciphertext, err := c.Encrypt(r.Context(), plaintext)
	if err != nil {
		internalError(w, r, err, "encryption failed")
		return nil, false
	}
	return []byte(ciphertext), true
}

func decryptOne(w http.ResponseWriter, r *http.Request, c Crypter, ciphertext []byte) ([]byte, bool) {
	if len(ciphertext) > maxCryptoCiphertextBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "ciphertext too large")
		return nil, false
	}
	plaintext, err := c.Decrypt(r.Context(), string(ciphertext))
	if err != nil {
		writeError(w, http.StatusBadRequest, "decryption failed")
		return nil, false
	}
	return plaintext, true
}
