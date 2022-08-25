package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

type Authentication struct {
	Username string
	Password string
	Token    string
}

func parse(r *http.Request) (string, string, string) {
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

// Usage:
//   t := read("token")
func read(table string) map[string]interface{} {
	data, err := os.ReadFile(table)
	if err != nil {
		return make(map[string]interface{})
	}
	var result map[string]interface{}
	json.Unmarshal([]byte(string(data)), &result)
	return result
}

// Usage:
//   store("token", t)
func store(table string, data map[string]interface{}) {
	s, _ := json.MarshalIndent(data, "", "    ")
	err := os.WriteFile(table, []byte(s), 0644)
	if err != nil {
		fmt.Println(err)
	}
}

func token() string {
	b := make([]byte, 10)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func adduser(w http.ResponseWriter, r *http.Request) {
	username, password, _ := parse(r)
	if username == "" || password == "" {
		fmt.Fprintf(w, "{\"error\":\"Missing username or password\"}\n")
		log.Println("adduser", username, "=> failed")
		return
	}
	users := read("users")
	if users[username] != nil {
		// User already exists; but don't reveal that.
		fmt.Fprintf(w, "{\"error\":\"Failed to add user\"}\n")
		log.Println("adduser", username, "=> failed")
		return
	}

	// Hash the password before storing it.
	h := sha256.Sum256([]byte(password))
	s := fmt.Sprintf("%x", h)
	users[username] = s
	store("users", users)

	// Delete any old tokens.
	tokens := read("tokens")
	delete(tokens, username)
	store("tokens", tokens)

	fmt.Fprintf(w, "{\"username\":\"%s\"}\n", username)
	log.Println("adduser", username, "=> success")
}

func deluser(w http.ResponseWriter, r *http.Request) {
	username, _, t := parse(r)
	h := sha256.Sum256([]byte(t))
	tokens := read("tokens")
	users := read("users")

	auth := tokens[username]
	if auth == hex.EncodeToString(h[:]) {
		delete(users, username)
		delete(tokens, username)
		store("users", users)
		store("tokens", tokens)
		fmt.Fprintf(w, "{\"username\":\"%s\"}\n", username)
		log.Println("deluser", username, "=> success")
	} else {
		fmt.Fprintln(w, "{\"error\":\"Invalid username or token\"}")
		log.Println("deluser", username, "=> failed")
	}
}

func setuser(w http.ResponseWriter, r *http.Request) {
	username, password, token := parse(r)

	// Pre-validation.
	if username == "" || password == "" {
		fmt.Fprintln(w, "{\"error\":\"Invalid username or password\"}")
		log.Println("setuser", username, "=> failed")
		return
	}
	users := read("users")
	if users[username] == nil {
		fmt.Fprintln(w, "{\"error\":\"Invalid username or token\"}")
		log.Println("setuser", username, "=> failed")
		return
	}
	tokens := read("tokens")
	if tokens[username] == nil {
		fmt.Fprintln(w, "{\"error\":\"Invalid username or token\"}")
		log.Println("setuser", username, "=> failed")
		return
	}

	h := sha256.Sum256([]byte(token))
	auth := tokens[username]
	if auth == hex.EncodeToString(h[:]) {
		h = sha256.Sum256([]byte(password))
		s := fmt.Sprintf("%x", h)
		users[username] = s
		store("users", users)
		fmt.Fprintf(w, "{\"username\":\"%s\"}\n", username)
		log.Println("setuser", username, "=> success")
	} else {
		fmt.Fprintln(w, "{\"error\":\"Invalid username or token\"}")
		log.Println("setuser", username, "=> failed")
	}
}

func auth(w http.ResponseWriter, r *http.Request) {
	username, password, _ := parse(r)
	users := read("users")
	tokens := read("tokens")

	h := sha256.Sum256([]byte(password))
	auth := users[username]
	if auth == hex.EncodeToString(h[:]) {
		t := token()
		ht := sha256.Sum256([]byte(t))
		s := fmt.Sprintf("%x", ht)
		tokens[username] = s
		store("tokens", tokens)
		fmt.Fprintf(w, "{\"username\":\"%s\",\"token\":\"%s\"}\n", username, t)
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
