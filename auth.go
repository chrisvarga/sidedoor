package main

import (
    "fmt"
    "bufio"
    "net"
    "net/http"
    "crypto/sha256"
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

func main() {
    http.HandleFunc("/adduser", adduser)
    http.ListenAndServe(":80", nil)
}
