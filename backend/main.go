package main

import (
	"fmt"
	"net/http"
)

func main() {
	fs := http.FileServer(http.Dir("./frontend"))
	http.Handle("/", fs)

	fmt.Println("Server running on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		panic(err)
	}
}