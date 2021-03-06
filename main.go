package main

import (
	"os"

	"gopkg.in/alecthomas/kingpin.v2"

	"github.com/jace-ys/cybersec/csrf"
	"github.com/jace-ys/cybersec/dvwa"
	"github.com/jace-ys/cybersec/sqli"
	"github.com/jace-ys/cybersec/xss"
)

var (
	cli          = kingpin.New("dvwa", "Automated exploits for the Damn Vulnerable Web Application (DVWA).")
	dvwaAddr     = cli.Flag("addr", "Address of the DVWA server.").Required().String()
	dvwaSecurity = cli.Flag("security", "Security level of the vulnerability to target. Must be one of [low, medium, high].").Default("low").Enum("low", "medium", "high")

	sqliCmd = cli.Command("sqli", "Run the SQL injection exploit to list all users and their passwords.")

	sqliBlindCmd     = cli.Command("sqli-blind", "Run the blind SQL injection exploit to crack a user's password hash.")
	sqliBlindMode    = sqliBlindCmd.Flag("mode", "Search mode to use for cracking the password hash.").Default("concurrent").Enum("concurrent", "binary")
	sqliBlindWorkers = sqliBlindCmd.Flag("workers", "Number of workers to use for concurrent search mode.").Default("10").Int()
	sqliBlindUserID  = sqliBlindCmd.Arg("user-id", "User ID to target. Must be between 1-5.").Required().Enum("1", "2", "3", "4", "5")

	xssCmd  = cli.Command("xss", "Run the XSS server to receive a users' stolen cookies.")
	xssPort = xssCmd.Flag("port", "Port to run the XSS reflection server on.").Default("8000").Int()

	csrfCmd  = cli.Command("csrf", "Run the CSRF web page to hijack a user's password.")
	csrfPort = csrfCmd.Flag("port", "Port to run the CSRF web server on.").Default("8000").Int()
)

func main() {
	cmd := kingpin.MustParse(cli.Parse(os.Args[1:]))

	client, err := dvwa.NewClient(*dvwaAddr, *dvwaSecurity)
	if err != nil {
		cli.FatalIfError(err, "client init")
	}

	switch cmd {
	case sqliCmd.FullCommand():
		cli.FatalIfError(sqli.Run(client), cmd)
	case sqliBlindCmd.FullCommand():
		cli.FatalIfError(sqli.RunBlind(client, *sqliBlindUserID, *sqliBlindMode, *sqliBlindWorkers), cmd)
	case xssCmd.FullCommand():
		cli.FatalIfError(xss.Run(*xssPort), cmd)
	case csrfCmd.FullCommand():
		cli.FatalIfError(csrf.Run(*dvwaAddr, *dvwaSecurity, *csrfPort), cmd)
	}
}
