package dvwa

import (
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
)

var (
	tokenRe = regexp.MustCompile(`<input type='hidden' name='user_token' value='(?P<token>[a-f0-9]{32})' />`)
)

type Client struct {
	Addr     string
	Security string
	*http.Client
}

func NewClient(addr, security string) (*Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	client := &Client{
		Addr:     addr,
		Security: security,
		Client:   &http.Client{Jar: jar},
	}

	return client, client.login()
}

func (c *Client) login() error {
	resp, err := c.Get(fmt.Sprintf("http://%s/login.php", c.Addr))
	if err != nil {
		return err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	matches := tokenRe.FindSubmatch(body)
	if len(matches) < 2 {
		return fmt.Errorf("could not find a user token on login page")
	}

	data := url.Values{}
	data.Set("username", "admin")
	data.Set("password", "password")
	data.Set("Login", "Login")
	data.Set("user_token", string(matches[1]))

	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("http://%s/login.php", c.Addr), strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err = c.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to login with status code %d", resp.StatusCode)
	}

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if !strings.Contains(string(body), "Welcome to Damn Vulnerable Web Application!") {
		return fmt.Errorf("DVWA server not set up yet")
	}

	index, err := url.Parse(fmt.Sprintf("http://%s/index.php", c.Addr))
	if err != nil {
		return err
	}

	cookies := append(c.Jar.Cookies(index), &http.Cookie{Name: "security", Value: c.Security})
	c.Jar.SetCookies(index, cookies)

	return nil
}
