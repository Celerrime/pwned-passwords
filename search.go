package main

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strings"
)

type pwdb struct {
	f  *os.File
	n  int
	rs int
}

type pwdb_record struct {
	hash  string
	count int
}

func pwdb_open(fn string) (error, *pwdb) {
	f, err := os.Open(os.Args[1])
	if err != nil {
		return err, nil
	}

	stat, err := f.Stat()
	if err != nil {
		return err, nil
	}

	const rs = 63
	if stat.Size()%rs != 0 {
		return fmt.Errorf("Unexpected password file format (lines must be like '<40 hex chars hash>:<count><\" \" padding>\\r', each exactly 63 bytes)"), nil
	}

	return nil, &pwdb{f, int(stat.Size() / rs), rs}
}

func (db *pwdb) record(i int) (ret pwdb_record) {
	b := make([]byte, db.rs)
	db.f.ReadAt(b, int64(i*db.rs))
	if _, err := fmt.Sscanf(string(b), "%40s:%d", &ret.hash, &ret.count); err != nil {
		fmt.Errorf("Can't parse record #%v: %v\n", i, err)
	}
	return
}

func (db *pwdb) search(cleartext string) *pwdb_record {
	hasher := sha1.New()
	io.WriteString(hasher, cleartext)
	needle := strings.ToUpper(hex.EncodeToString(hasher.Sum(nil)))

	i := sort.Search(db.n, func(i int) bool {
		return db.record(i).hash >= needle
	})

	if record := db.record(i); i < db.n && record.hash == needle {
		return &record
	}

	return nil
}

func main() {
	if len(os.Args) < 3 {
		log.Fatalf("usage: %s <path-to-pwned-passwords-ordered-2.0.txt> <password-to-test>...\n", os.Args[0])
	}

	err, db := pwdb_open(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	for i := 2; i < len(os.Args); i++ {
		if record := db.search(os.Args[i]); record != nil {
			fmt.Printf("%s: FOUND (%v)\n", os.Args[i], record.count)
		} else {
			fmt.Printf("%s: not found\n", os.Args[i])
		}
	}
}
