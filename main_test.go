package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSetGetDel(t *testing.T) {
	s := newKV()
	s.set("a", "1")
	if v, ok := s.get("a"); !ok || v != "1" {
		t.Fatal("get failed")
	}
	if !s.del("a") {
		t.Fatal("del failed")
	}
	if _, ok := s.get("a"); ok {
		t.Fatal("key should be gone")
	}
}

func TestSaveLoad(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "db.bin")
	pass := "secret"
	s1 := newKV()
	s1.set("x", "42")
	if err := saveToFile(s1, file, pass); err != nil {
		t.Fatalf("save: %v", err)
	}
	s2 := newKV()
	if err := loadFromFile(s2, file, pass); err != nil {
		t.Fatalf("load: %v", err)
	}
	if v, ok := s2.get("x"); !ok || v != "42" {
		t.Fatal("data mismatch after load")
	}
}

func TestLoadWrongPassword(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "db.bin")
	s := newKV()
	s.set("k", "v")
	if err := saveToFile(s, file, "good"); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := loadFromFile(newKV(), file, "bad"); err == nil {
		t.Fatal("expected auth error")
	}
}

func TestLoadInvalidFile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "bad.bin")
	if err := os.WriteFile(file, []byte("short"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := loadFromFile(newKV(), file, "123"); err == nil {
		t.Fatal("should fail on malformed file")
	}
}

func TestSaveToDirPath(t *testing.T) {
	dir := t.TempDir()
	pass := "pwd"
	if err := saveToFile(newKV(), dir, pass); err == nil {
		t.Fatal("saving into directory must fail")
	}
}