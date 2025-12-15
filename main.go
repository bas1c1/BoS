package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
)

type kv struct {
	mu   sync.RWMutex
	data map[string][]byte
}

func newKV() *kv {
	return &kv{data: make(map[string][]byte)}
}

func (k *kv) set(key, val string) {
	k.mu.Lock()
	k.data[key] = []byte(val)
	k.mu.Unlock()
}

func (k *kv) get(key string) (string, bool) {
	k.mu.RLock()
	v, ok := k.data[key]
	k.mu.RUnlock()
	return string(v), ok
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func (k *kv) del(key string) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	v, ok := k.data[key]
	if !ok {
		return false
	}
	zero(v)
	delete(k.data, key)
	return true
}

func (k *kv) snapshot() map[string]string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	out := make(map[string]string, len(k.data))
	for key, v := range k.data {
		out[key] = string(v)
	}
	return out
}

func (k *kv) replace(in map[string]string) {
	k.mu.Lock()
	for key, v := range k.data {
		zero(v)
		delete(k.data, key)
	}
	for key, val := range in {
		k.data[key] = []byte(val)
	}
	k.mu.Unlock()
}

func hmacSHA512(key, data []byte) []byte {
	m := hmac.New(sha512.New, key)
	m.Write(data)
	return m.Sum(nil)
}

func pbkdf2sha512(password, salt []byte, iter, dkLen int) []byte {
	hLen := sha512.Size
	l := (dkLen + hLen - 1) / hLen
	var dk []byte
	for i := 1; i <= l; i++ {
		var block bytes.Buffer
		block.Write(salt)
		block.Write([]byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)})
		u := hmacSHA512(password, block.Bytes())
		t := make([]byte, hLen)
		copy(t, u)
		for j := 1; j < iter; j++ {
			u = hmacSHA512(password, u)
			for k := range t {
				t[k] ^= u[k]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:dkLen]
}

func deriveKey(pass, salt []byte) []byte {
	return pbkdf2sha512(pass, salt, 100000, 32)
}

func saveToFile(store *kv, file, pass string) error {
	state := store.snapshot()
	blob, err := json.Marshal(state)
	if err != nil {
		return err
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	key := deriveKey([]byte(pass), salt)
	c, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	g, err := cipher.NewGCM(c)
	if err != nil {
		return err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	ct := g.Seal(nil, nonce, blob, nil)
	f, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(salt); err != nil {
		return err
	}
	if _, err := f.Write(nonce); err != nil {
		return err
	}
	if _, err := f.Write(ct); err != nil {
		return err
	}
	zero(blob)
	zero(key)
	return nil
}

func loadFromFile(store *kv, file, pass string) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	if len(data) < 28 {
		return fmt.Errorf("invalid file")
	}
	salt := data[:16]
	nonce := data[16:28]
	ct := data[28:]
	key := deriveKey([]byte(pass), salt)
	c, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	g, err := cipher.NewGCM(c)
	if err != nil {
		return err
	}
	pt, err := g.Open(nil, nonce, ct, nil)
	if err != nil {
		return err
	}
	var m map[string]string
	if err := json.Unmarshal(pt, &m); err != nil {
		return err
	}
	store.replace(m)
	zero(pt)
	zero(key)
	return nil
}

func handle(c net.Conn, store *kv) {
	defer c.Close()
	r := bufio.NewReader(c)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.Fields(strings.TrimSpace(line))
		if len(cmd) == 0 {
			continue
		}
		switch strings.ToUpper(cmd[0]) {
		case "SET":
			if len(cmd) < 3 {
				fmt.Fprintln(c, "ERR")
				continue
			}
			key, val := cmd[1], strings.Join(cmd[2:], " ")
			store.set(key, val)
			fmt.Fprintln(c, "OK")
		case "GET":
			if len(cmd) != 2 {
				fmt.Fprintln(c, "ERR")
				continue
			}
			if v, ok := store.get(cmd[1]); ok {
				fmt.Fprintln(c, v)
			} else {
				fmt.Fprintln(c, "NIL")
			}
		case "DEL":
			if len(cmd) != 2 {
				fmt.Fprintln(c, "ERR")
				continue
			}
			if store.del(cmd[1]) {
				fmt.Fprintln(c, "OK")
			} else {
				fmt.Fprintln(c, "NIL")
			}
		case "SAVE":
			if len(cmd) != 3 {
				fmt.Fprintln(c, "ERR")
				continue
			}
			if err := saveToFile(store, cmd[1], cmd[2]); err != nil {
				fmt.Fprintln(c, "ERR")
			} else {
				fmt.Fprintln(c, "OK")
			}
		case "LOAD":
			if len(cmd) != 3 {
				fmt.Fprintln(c, "ERR")
				continue
			}
			if err := loadFromFile(store, cmd[1], cmd[2]); err != nil {
				fmt.Fprintln(c, "ERR")
			} else {
				fmt.Fprintln(c, "OK")
			}
		default:
			fmt.Fprintln(c, "ERR")
		}
	}
}

func main() {
	store := newKV()
	ln, err := net.Listen("tcp", ":4000")
	if err != nil {
		panic(err)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handle(conn, store)
	}
}