// The built-in protection mode of demo up: the shop, the four APIs and
// Accounts with no gateway, each API checking tokens, roles, blocked
// accounts, rates and bodies itself and keeping its own security log. The
// demo process only routes each API path to its service, with the caller's
// token and no identity of its own. demo block -local changes the blocked
// list of every API of that run.

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Alex-Zechariah-02/fetch/internal/guard"
	"github.com/Alex-Zechariah-02/fetch/internal/services"
)

// localFolder is the run folder of the mode in the demo home.
const localFolder = "local"

// upLocal is demo up -local: it builds the services, Accounts and the shop,
// makes a new run folder in home with the keys, an empty blocked list and the
// security logs, and runs everything until interrupted.
func upLocal(home string, stdin bool) error {
	if err := checkFree(localAddresses()); err != nil {
		return err
	}
	serviceBinary, accountsBinary, shop, err := fetchPrograms(home, "")
	if err != nil {
		return err
	}
	dir := filepath.Join(home, localFolder)
	files, err := localFiles(dir)
	if err != nil {
		return err
	}
	if err := prepareFolder(dir, files); err != nil {
		return err
	}
	listener, err := services.Listen(dataListen, services.Ingress{})
	if err != nil {
		return fmt.Errorf("the shop address: %w", err)
	}
	ctx, stop := stopContext(stdin)
	defer stop()
	banner := fmt.Sprintf("BUILT-IN PROTECTION: no gateway; each API checks every request itself.\nSecurity logs: %s\n\nShop: http://%s/\nPress Ctrl+C to stop.", dir, dataListen)
	return serveFetch(ctx, dir, listener, apiRouter(os.DirFS(shop), nil), serviceBinary, accountsBinary, nil, true, banner)
}

// localFiles are the files of one run: the services' secret and signing
// settings, the Accounts public key every API trusts, and no blocked account.
func localFiles(dir string) (map[string][]byte, error) {
	files, err := serviceFiles(dir)
	if err != nil {
		return nil, err
	}
	files[guard.KeysFile] = indented([]guard.Key{{Kid: localKid, PublicKeyFile: filepath.Join(dir, publicKeyFile)}})
	files[guard.BlockedFile] = indented([]string{})
	return files, nil
}

// block is demo block -local: it adds an account to (or with -unblock removes
// it from) the blocked list of the running built-in protection mode, first in
// the run folder, then in every API through its control listener.
func block(args []string) error {
	set := flag.NewFlagSet("block", flag.ContinueOnError)
	local := set.Bool("local", false, "the running built-in protection mode (the gateway blocks accounts in its Dashboard)")
	home := set.String("home", defaultHome(), "the demo home of demo up -local")
	unblock := set.Bool("unblock", false, "remove the account from the list instead")
	if err := set.Parse(args); err != nil {
		return err
	}
	if !*local || set.NArg() != 1 || !validSubject(set.Arg(0)) {
		return errors.New("use: demo block -local [-home H] [-unblock] ACCOUNT")
	}
	dir := filepath.Join(*home, localFolder)
	path := filepath.Join(dir, guard.BlockedFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("no built-in protection run in %s: %w", dir, err)
	}
	var list []string
	if err := json.Unmarshal(data, &list); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	account := set.Arg(0)
	list = slices.DeleteFunc(list, func(s string) bool { return s == account })
	if !*unblock {
		list = append(list, account)
	}
	slices.Sort(list)
	fmt.Printf("blocked accounts: %v\n", list)
	content := indented(list)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		return err
	}
	secret, err := os.ReadFile(filepath.Join(dir, secretFile))
	if err != nil {
		return err
	}
	return putBlocked(content, strings.TrimSpace(string(secret)))
}

// putBlocked replaces the blocked list of every API; one that does not take
// it is named, and a rerun repeats the whole list.
func putBlocked(list []byte, secret string) error {
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: refuseRedirect}
	defer client.CloseIdleConnections()
	for _, service := range fetchServices {
		request, err := http.NewRequest("PUT", "http://"+service.control+"/blocked", bytes.NewReader(list))
		if err != nil {
			return err
		}
		request.Header.Set("Authorization", "Bearer "+secret)
		response, err := client.Do(request)
		if err != nil {
			return fmt.Errorf("%s: no answer; its blocked list may be the old one: %w", service.name, err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			return fmt.Errorf("%s refused the blocked list (status %d)", service.name, response.StatusCode)
		}
		fmt.Printf("%-9s blocked list updated\n", service.name)
	}
	return nil
}
