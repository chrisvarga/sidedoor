package main

import (
	"bufio"
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
		return "error => could not connect to erebor\n"
	}
	fmt.Fprintf(conn, s)
	status, err := bufio.NewReader(conn).ReadString('\n')
	return status
}

func adduser(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	pw := r.URL.Query().Get("pw")
	fmt.Fprintln(w, "id =>", id)
	fmt.Fprintln(w, "pw =>", pw)
	h := sha256.Sum256([]byte(pw))
	s := fmt.Sprintf("set user %s %x", id, h)
	fmt.Fprint(w, erebor(s))
}

func auth(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	pw := r.URL.Query().Get("pw")
	fmt.Fprintln(w, "id =>", id)
	fmt.Fprintln(w, "pw =>", pw)
	h := sha256.Sum256([]byte(pw))
	s := fmt.Sprintf("get user %s", id)
	auth := erebor(s)
	if strings.TrimRight(auth, "\n") == hex.EncodeToString(h[:]) {
		fmt.Fprintln(w, "success")
	} else {
		fmt.Fprintln(w, "authentication failed")
	}
}

func main() {
	http.HandleFunc("/adduser", adduser)
	http.HandleFunc("/auth", auth)
	http.ListenAndServe(":80", nil)
}
