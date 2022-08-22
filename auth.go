package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
)

func erebor(s string) string {
	conn, err := net.Dial("tcp", "127.0.0.1:8044")
	if err != nil {
		return "(error): could not connect to erebor\n"
	}
	fmt.Fprintf(conn, s)
	status, err := bufio.NewReader(conn).ReadString('\n')
	return status
}

func token() string {
	b := make([]byte, 10)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func adduser(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	pw := r.URL.Query().Get("pw")
	h := sha256.Sum256([]byte(pw))
	s := fmt.Sprintf("set user %s %x", id, h)
	e := strings.TrimRight(erebor(s), "\n")
	if e == "OK" {
		fmt.Fprintf(w, "{\"user\":\"%s\"}\n", id)
		fmt.Println("adduser", id, "=> success")
		s := fmt.Sprintf("del token %s", id)
		erebor(s)
	} else {
		fmt.Fprintf(w, "{\"error\":\"Failed to add user\"}\n")
		fmt.Println("adduser", id, "=> failed")
	}
}

func auth(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	pw := r.URL.Query().Get("pw")
	h := sha256.Sum256([]byte(pw))
	s := fmt.Sprintf("get user %s", id)
	auth := erebor(s)
	if strings.TrimRight(auth, "\n") == hex.EncodeToString(h[:]) {
		t := token()
		s := fmt.Sprintf("set token %s %x", id, sha256.Sum256([]byte(t)))
		erebor(s)
		fmt.Fprintf(w, "{\"token\":\"%s\"}\n", t)
		fmt.Println("auth", id, "=> success")
	} else {
		fmt.Fprintln(w, "{\"error\":\"Authentication failed\"}")
		fmt.Println("auth", id, "=> failed")
	}
}

func main() {
	http.HandleFunc("/api/adduser", adduser)
	http.HandleFunc("/api/auth", auth)
	http.ListenAndServe(":80", nil)
}
