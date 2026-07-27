package main

import (
	"database/sql"
	"fmt"
	"net/http"
)

// Intentional SAST demo patterns (not production code).
func handler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	db, _ := sql.Open("sqlite3", "demo.db")
	rows, _ := db.Query("SELECT * FROM users WHERE name = '" + q + "'")
	defer rows.Close()
	fmt.Fprintln(w, "ok")
}

func main() {
	http.HandleFunc("/", handler)
	_ = http.ListenAndServe(":8080", nil)
}
