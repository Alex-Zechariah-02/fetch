// The container images. demo certs also writes the APIWard image's settings
// into the gateway folder, which is mounted read-only where the image reads
// them; demo prepare then gives that new gateway its administrator and
// baseline, as demo up does on a first run; demo health is the Fetch image's
// health check.

package main

import (
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"path"
	"time"
)

// Where the APIWard image reads its settings, keys and certificates (the
// gateway folder of demo certs, mounted read-only) and keeps its database
// and audit log (a local volume).
const (
	imageConfig   = "/etc/apiward"
	imageState    = "/var/lib/apiward"
	imageSettings = "apiward.json"
)

// addImageFiles adds to gateway, the gateway folder's files, the APIWard
// image's settings, which name the folder's files under imageConfig, and the
// deny-all and baseline documents that demo prepare establishes.
func addImageFiles(gateway map[string][]byte, fetch netip.Addr) error {
	kid, err := keyID(gateway[publicKeyFile])
	if err != nil {
		return fmt.Errorf("the Accounts public key: %w", err)
	}
	in := func(name string) string { return path.Join(imageConfig, name) }
	files := gatewayFiles{database: path.Join(imageState, databaseFile), audit: path.Join(imageState, auditFile)}
	gateway[imageSettings] = indented(hostSettings(files, kid, in, in(dataCertFile), in(dataKeyFile)))
	baseline := deployedBaseline(fetch)
	gateway[baselineFile] = indented(baseline)
	gateway[denyAllFile] = indented(denyAll(baseline))
	return nil
}

// prepare gives a new gateway, started from the APIWard image with the
// settings of the gateway folder certs, its administrator and baseline
// policy through the Admin API on this host's loopback address. It asks for
// the enrolment secret that apiward install printed and a new password.
func prepare(args []string) error {
	set := flag.NewFlagSet("prepare", flag.ContinueOnError)
	certs := set.String("certs", "", "the gateway folder from demo certs")
	if err := set.Parse(args); err != nil {
		return err
	}
	if set.NArg() != 0 {
		return errors.New("prepare takes only -certs\n" + usage)
	}
	folder, err := certFolder(*certs, baselineFile, denyAllFile)
	if err != nil {
		return err
	}
	mode, err := awaitAdmin(newAdminClient())
	if err != nil {
		return err
	}
	if mode != "bootstrap_locked" {
		return fmt.Errorf("the gateway reports state %q: prepare sets up only a gateway that has no policy yet", mode)
	}
	secret, err := readSecretLine("Enrolment secret printed by apiward install (not shown): ")
	if err != nil {
		return err
	}
	fmt.Println("Choose the password for the Dashboard administrator", upAdmin+".")
	password, err := choosePassword()
	if err != nil {
		return err
	}
	if err := prepareGateway(folder, true, secret, password); err != nil {
		return err
	}
	printSignIns()
	fmt.Printf("\nDashboard: http://%s/  (sign in as %s)\n", adminListen, upAdmin)
	return nil
}

// adminWait bounds how long prepare waits for a gateway container that was
// just started: it opens its database and the Admin API within seconds.
const adminWait = 30 * time.Second

// awaitAdmin returns the gateway's state once its Admin API answers, or the
// last failure when it has not answered within adminWait.
func awaitAdmin(admin *adminClient) (string, error) {
	deadline := time.Now().Add(adminWait)
	for {
		mode, err := admin.health()
		if err == nil || time.Now().After(deadline) {
			return mode, err
		}
		time.Sleep(time.Second)
	}
}

// health succeeds once every Fetch service's control listener on this host
// accepts connections: the Fetch image's health check.
func health(args []string) error {
	if len(args) != 0 {
		return errors.New("health takes no arguments\n" + usage)
	}
	for _, service := range fetchServices {
		if !dialable(service.control) {
			return fmt.Errorf("%s does not answer on %s", service.name, service.control)
		}
	}
	return nil
}
