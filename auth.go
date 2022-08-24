package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
)

func erebor(s string) string {
	conn, err := net.Dial("tcp", "127.0.0.1:8044")
	if err != nil {
		return "(error): could not connect to erebor\n"
	}
	defer conn.Close()
	fmt.Fprintf(conn, s)
	status, err := bufio.NewReader(conn).ReadString('\n')
	return strings.TrimRight(status, "\n")
}

func token() string {
	b := make([]byte, 10)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func adduser(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	pw := r.URL.Query().Get("pw")
	if id == "" || pw == "" {
		fmt.Fprintf(w, "{\"error\":\"Missing username or password\"}\n")
		log.Println("adduser", id, "=> failed")
		return
	}
	h := sha256.Sum256([]byte(pw))
	s := fmt.Sprintf("set user %s %x", id, h)
	e := erebor(s)
	if e == "OK" {
		fmt.Fprintf(w, "{\"user\":\"%s\"}\n", id)
		log.Println("adduser", id, "=> success")
		s := fmt.Sprintf("del token %s", id)
		erebor(s)
	} else {
		fmt.Fprintf(w, "{\"error\":\"Failed to add user\"}\n")
		log.Println("adduser", id, "=> failed")
	}
}

func deluser(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	tk := r.URL.Query().Get("tk")
	h := sha256.Sum256([]byte(tk))
	s := fmt.Sprintf("get token %s", id)
	auth := erebor(s)
	if auth == hex.EncodeToString(h[:]) {
		s := fmt.Sprintf("del user %s", id)
		erebor(s)
		s = fmt.Sprintf("del token %s", id)
		erebor(s)
		fmt.Fprintf(w, "{\"user\":\"%s\"}\n", id)
		log.Println("deluser", id, "=> success")
	} else {
		fmt.Fprintln(w, "{\"error\":\"Invalid username or token\"}")
		log.Println("deluser", id, "=> failed")
	}
}

func auth(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	pw := r.URL.Query().Get("pw")
	h := sha256.Sum256([]byte(pw))
	s := fmt.Sprintf("get user %s", id)
	auth := erebor(s)
	if auth == hex.EncodeToString(h[:]) {
		t := token()
		s := fmt.Sprintf("set token %s %x", id, sha256.Sum256([]byte(t)))
		erebor(s)
		fmt.Fprintf(w, "{\"token\":\"%s\"}\n", t)
		log.Println("auth", id, "=> success")
	} else {
		fmt.Fprintln(w, "{\"error\":\"Authentication failed\"}")
		log.Println("auth", id, "=> failed")
	}
}

func main() {
	http.HandleFunc("/api/adduser", adduser)
	http.HandleFunc("/api/deluser", deluser)
	http.HandleFunc("/api/auth", auth)
	log.Fatal(http.ListenAndServe(":80", nil))
}
