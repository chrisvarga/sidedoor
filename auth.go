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
	err := os.WriteFile(table, append([]byte(s), "\n"...), 0644)
	if err != nil {
		fmt.Println(err)
	}
}

func token() string {
	b := make([]byte, 20)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func create(w http.ResponseWriter, r *http.Request) {
	username, password, _ := parse(r)
	if username == "" || password == "" {
		fmt.Fprintf(w, "{\"error\":\"Username or password cannot be empty\"}\n")
		log.Println("create", username, "=> failed")
		return
	}
	users := read("users")
	if users[username] != nil {
		fmt.Fprintf(w, "{\"error\":\"Username is invalid or already taken\"}\n")
		log.Println("create", username, "=> failed")
		return
	}

	h := sha256.Sum256([]byte(password))
	s := fmt.Sprintf("%x", h)
	users[username] = s
	store("users", users)

	tokens := read("tokens")
	delete(tokens, username)
	store("tokens", tokens)

	fmt.Fprintf(w, "{\"username\":\"%s\"}\n", username)
	log.Println("create", username, "=> success")
}

func remove(w http.ResponseWriter, r *http.Request) {
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
		log.Println("remove", username, "=> success")
	} else {
		fmt.Fprintln(w, "{\"error\":\"Invalid username or token\"}")
		log.Println("remove", username, "=> failed")
	}
}

func update(w http.ResponseWriter, r *http.Request) {
	username, password, token := parse(r)

	if username == "" || password == "" {
		fmt.Fprintln(w, "{\"error\":\"Invalid username or password\"}")
		log.Println("update", username, "=> failed")
		return
	}
	users := read("users")
	if users[username] == nil {
		fmt.Fprintln(w, "{\"error\":\"Invalid username or token\"}")
		log.Println("update", username, "=> failed")
		return
	}
	tokens := read("tokens")
	if tokens[username] == nil {
		fmt.Fprintln(w, "{\"error\":\"Invalid username or token\"}")
		log.Println("update", username, "=> failed")
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
		log.Println("update", username, "=> success")
	} else {
		fmt.Fprintln(w, "{\"error\":\"Invalid username or token\"}")
		log.Println("update", username, "=> failed")
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
	http.HandleFunc("/api/v1/create", create)
	http.HandleFunc("/api/v1/remove", remove)
	http.HandleFunc("/api/v1/update", update)
	http.HandleFunc("/api/v1/auth", auth)
	log.Fatal(http.ListenAndServe(":80", nil))
}
