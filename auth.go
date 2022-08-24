package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
)

type Authentication struct {
	Username string
	Password string
	Token    string
}

func authentication(r *http.Request) (string, string, string) {
	var authentication Authentication

	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Fatalln(err)
	}
	json.Unmarshal(body, &authentication)

	username := authentication.Username
	password := authentication.Password
	token := authentication.Token
	return username, password, token
}

func authentication2(r string) (string, string, string) {
	var authentication Authentication
	json.Unmarshal([]byte(r), &authentication)

	username := authentication.Username
	password := authentication.Password
	token := authentication.Token
	return username, password, token
}

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

func store(table string, data string) {
	err := os.WriteFile(table, []byte(data), 0644)
	if err != nil {
		log.Fatal(err)
	}
}

func read(table string) string {
	data, err := os.ReadFile(table)
	if err != nil {
		log.Fatal(err)
	}
	return string(data)
}

func token() string {
	b := make([]byte, 10)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func adduser(w http.ResponseWriter, r *http.Request) {
	username, password, _ := authentication(r)
	if username == "" || password == "" {
		fmt.Fprintf(w, "{\"error\":\"Missing username or password\"}\n")
		log.Println("adduser", username, "=> failed")
		return
	}
	s := fmt.Sprintf("get user %s", username)
	if erebor(s) != "(error): key not found" {
		// User already exists; but don't reveal that.
		fmt.Fprintf(w, "{\"error\":\"Failed to add user\"}\n")
		log.Println("adduser", username, "=> failed")
		return
	}
	h := sha256.Sum256([]byte(password))
	s = fmt.Sprintf("set user %s %x", username, h)
	e := erebor(s)
	if e == "OK" {
		fmt.Fprintf(w, "{\"username\":\"%s\"}\n", username)
		log.Println("adduser", username, "=> success")
		s = fmt.Sprintf("del token %s", username)
		erebor(s)
	} else {
		fmt.Fprintf(w, "{\"error\":\"Failed to add user\"}\n")
		log.Println("adduser", username, "=> failed")
	}
}

func deluser(w http.ResponseWriter, r *http.Request) {
	username, _, token := authentication(r)
	h := sha256.Sum256([]byte(token))
	s := fmt.Sprintf("get token %s", username)
	auth := erebor(s)
	if auth == hex.EncodeToString(h[:]) {
		s := fmt.Sprintf("del user %s", username)
		erebor(s)
		s = fmt.Sprintf("del token %s", username)
		erebor(s)
		fmt.Fprintf(w, "{\"username\":\"%s\"}\n", username)
		log.Println("deluser", username, "=> success")
	} else {
		fmt.Fprintln(w, "{\"error\":\"Invalid username or token\"}")
		log.Println("deluser", username, "=> failed")
	}
}

func setuser(w http.ResponseWriter, r *http.Request) {
	username, password, token := authentication(r)
	if username == "" || password == "" {
		fmt.Fprintln(w, "{\"error\":\"Invalid username or password\"}")
		log.Println("setuser", username, "=> failed")
		return
	}
	s := fmt.Sprintf("get user %s", username)
	if erebor(s) == "(error): key not found" {
		fmt.Fprintln(w, "{\"error\":\"Invalid username or token\"}")
		log.Println("setuser", username, "=> failed")
		return
	}

	h := sha256.Sum256([]byte(token))
	s = fmt.Sprintf("get token %s", username)
	auth := erebor(s)
	if auth == hex.EncodeToString(h[:]) {
		h = sha256.Sum256([]byte(password))
		s := fmt.Sprintf("set user %s %x", username, h)
		erebor(s)
		fmt.Fprintf(w, "{\"username\":\"%s\"}\n", username)
		log.Println("setuser", username, "=> success")
	} else {
		fmt.Fprintln(w, "{\"error\":\"Invalid username or token\"}")
		log.Println("setuser", username, "=> failed")
	}
}

func auth(w http.ResponseWriter, r *http.Request) {
	username, password, _ := authentication(r)
	h := sha256.Sum256([]byte(password))
	s := fmt.Sprintf("get user %s", username)
	auth := erebor(s)
	if auth == hex.EncodeToString(h[:]) {
		t := token()
		s := fmt.Sprintf("set token %s %x", username, sha256.Sum256([]byte(t)))
		erebor(s)
		s = fmt.Sprintf("{\"username\":\"%s\",\"token\":\"%x\"}", username, sha256.Sum256([]byte(t)))
		store(username, s)
		log.Println(read(username))
		u, p, tt := authentication2(read(username))
		log.Println(u, p, tt)
		fmt.Fprintf(w, "{\"username\":\"%s\",\"token\":\"%x\"}\n", username, t)
		log.Println("auth", username, "=> success")
	} else {
		fmt.Fprintln(w, "{\"error\":\"Authentication failed\"}")
		log.Println("auth", username, "=> failed")
	}
}

func main() {
	http.HandleFunc("/api/v1/adduser", adduser)
	http.HandleFunc("/api/v1/deluser", deluser)
	http.HandleFunc("/api/v1/setuser", setuser)
	http.HandleFunc("/api/v1/auth", auth)
	log.Fatal(http.ListenAndServe(":80", nil))
}
