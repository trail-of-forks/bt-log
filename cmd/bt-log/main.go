package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/haydentherapper/bt-log/internal/purl"
	f_log "github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/client"
	"github.com/transparency-dev/tessera/storage/posix"
	"golang.org/x/mod/sumdb/note"
)

var (
	host              = flag.String("host", "localhost", "host to listen on")
	port              = flag.Uint("port", 8080, "port to listen on")
	storageDir        = flag.String("storage-dir", "", "Root directory to store log data")
	entryType         = flag.String("entry-type", "", "Specifies the log entry structure. Valid types are [purl, pypi]")
	purlType          = flag.String("purl-type", "", "Restricts pURLs to be of a specific type")
	privKeyFile       = flag.String("private-key", "", "Location of private key file")
	pubKeyFile        = flag.String("public-key", "", "Location of public key file")
	witnessUrl        = flag.String("witness-url", "", "Optional witness to cosign checkpoint")
	witnessPubKeyFile = flag.String("witness-public-key", "", "Optional witness public key location to verify cosignatures")
)

func addCacheHeaders(value string, fs http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Cache-Control", value)
		fs.ServeHTTP(w, r)
	}
}

type LogEntry interface {
	Marshal() ([]byte, error)
	Unmarshal([]byte) error
}

type PURLLogEntry struct {
	PURL string `json:"purl"` // e.g. pkg:pypi/pkgname@1.2.3?checksum=sha256:5141b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be92
	// TODO: Add registry, add filename
}

func (e PURLLogEntry) Marshal() ([]byte, error) {
	if e.PURL == "" {
		return nil, fmt.Errorf("package URL emtpy")
	}
	return []byte(e.PURL), nil
}

func (e *PURLLogEntry) Unmarshal(u []byte) error {
	e.PURL = string(u)
	return nil
}

type PyPILogEntry struct {
	Filename string `json:"filename"` // e.g. pypi_attestations-0.0.27.tar.gz for source distributions or pypi_attestations-0.0.27-py3-none-any.whl for wheels
	Checksum string `json:"checksum"` // e.g. sha256:5141b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be92
	Identity string `json:"identity"` // e.g. https://github.com/octo-org/octo-automation/.github/workflows/oidc.yml@refs/heads/main
}

func (e PyPILogEntry) Marshal() ([]byte, error) {
	if e.Filename == "" {
		return nil, fmt.Errorf("filename empty")
	}
	if e.Checksum == "" {
		return nil, fmt.Errorf("checksum empty")
	}
	if e.Identity != "" {
		return []byte(fmt.Sprintf("%s\n%s\n%s", e.Filename, e.Checksum, e.Identity)), nil
	} else {
		return []byte(fmt.Sprintf("%s\n%s", e.Filename, e.Checksum)), nil
	}
}

func (e *PyPILogEntry) Unmarshal(u []byte) error {
	s := strings.Split(string(u), "\n")
	switch len(s) {
	case 2:
		e.Filename = s[0]
		e.Checksum = s[1]
		return nil
	case 3:
		e.Filename = s[0]
		e.Checksum = s[1]
		e.Identity = s[2]
		return nil
	default:
		return fmt.Errorf("incorrect encoding, must contain filename and checksum and optionally identity")
	}
}

type LogEntryResponse struct {
	Index          uint64   `json:"index"`
	Checkpoint     []byte   `json:"checkpoint"`
	InclusionProof [][]byte `json:"inclusionProof"`
}

func main() {
	flag.Parse()

	if *storageDir == "" {
		log.Fatalf("--storage-dir must be set")
	}
	if *entryType != "purl" && *entryType != "pypi" {
		log.Fatalf("--entry-type must be set to either 'purl' or 'pypi'")
	}
	if *entryType == "purl" && *purlType == "" {
		log.Fatalf("--purl-type must be set")
	}
	if *privKeyFile == "" {
		log.Fatalf("--private-key must be set")
	}
	if *pubKeyFile == "" {
		log.Fatalf("--public-key must be set")
	}
	if (*witnessUrl != "" && *witnessPubKeyFile == "") ||
		(*witnessUrl == "" && *witnessPubKeyFile != "") {
		log.Fatalf("--witness-url and --witness-public-key must both be set")
	}

	ctx := context.Background()

	// Create NoteSigner/Verifier for signing/verifying checkpoints
	privKey, err := os.ReadFile(*privKeyFile)
	if err != nil {
		log.Fatalf("failed to read private key file for %s: %v", *privKeyFile, err)
	}
	s, err := note.NewSigner(string(privKey))
	if err != nil {
		log.Fatalf("failed to read signer %s: %v", *privKeyFile, err)
	}

	pubKey, err := os.ReadFile(*pubKeyFile)
	if err != nil {
		log.Fatalf("failed to read public key file for %s: %v", *pubKeyFile, err)
	}
	v, err := note.NewVerifier(string(pubKey))
	if err != nil {
		log.Fatalf("failed to read verifier %s: %v", *pubKeyFile, err)
	}

	// Create witness
	var witness *tessera.Witness
	if *witnessPubKeyFile != "" && *witnessUrl != "" {
		witnessPubKey, err := os.ReadFile(*witnessPubKeyFile)
		if err != nil {
			log.Fatal(err)
		}
		wUrl, err := url.Parse(*witnessUrl)
		if err != nil {
			log.Fatal(err)
		}
		wit, err := tessera.NewWitness(string(witnessPubKey), wUrl)
		if err != nil {
			log.Fatalf("error creating witness: %v", err)
		}
		witness = &wit
	}

	// Create the Tessera POSIX storage, using the directory from the --storage-dir flag
	driver, err := posix.New(ctx, posix.Config{
		Path: *storageDir,
	})
	if err != nil {
		log.Fatalf("failed to construct driver: %v", err)
	}

	opts := tessera.NewAppendOptions().
		WithCheckpointSigner(s).
		WithCheckpointInterval(5*time.Second).
		WithBatching(256, time.Second).
		WithAntispam(256, nil)
	if witness != nil {
		opts = opts.WithWitnesses(tessera.NewWitnessGroup(1, witness), &tessera.WitnessOptions{FailOpen: false})
	}
	appender, shutdown, r, err := tessera.NewAppender(ctx, driver, opts)
	if err != nil {
		log.Fatalf("failed to create appender: %v", err)
	}
	addFn := appender.Add
	tileFetcher := r.ReadTile
	await := tessera.NewPublicationAwaiter(ctx, r.ReadCheckpoint, time.Second)

	// Define a handler for /add that accepts POST requests and adds the POST body to the log
	http.HandleFunc("POST /add", func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Parse request
		var e LogEntry
		switch *entryType {
		case "purl":
			e = &PURLLogEntry{}
		case "pypi":
			e = &PyPILogEntry{}
		default:
			// Shouldn't happen as we verify the entry type on server init
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if err := json.Unmarshal(b, e); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(err.Error()))
			return
		}

		if *entryType == "purl" {
			if err := purl.VerifyPURL(e.(*PURLLogEntry).PURL, *purlType); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(err.Error()))
				return
			}
		}
		// TODO: Verify PyPI as well - verify filename against regex, verify checksum

		m, err := e.Marshal()
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(err.Error()))
			return
		}

		f := addFn(r.Context(), tessera.NewEntry(m))
		idx, rawCp, err := await.Await(ctx, f)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(err.Error()))
			return
		}
		cp, _, _, err := f_log.ParseCheckpoint(rawCp, v.Name(), v)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(err.Error()))
			return
		}
		pb, err := client.NewProofBuilder(ctx, cp.Size, tileFetcher)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(err.Error()))
			return
		}
		inclusionProof, err := pb.InclusionProof(ctx, idx.Index)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(err.Error()))
			return
		}
		// make sure the proof is valid
		leafHash := rfc6962.DefaultHasher.HashLeaf(m)
		if err := proof.VerifyInclusion(rfc6962.DefaultHasher, idx.Index, cp.Size, leafHash, inclusionProof, cp.Hash); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(err.Error()))
			return
		}

		resp := LogEntryResponse{
			Index:          idx.Index,
			InclusionProof: inclusionProof,
			Checkpoint:     rawCp,
		}

		jResp, err := json.Marshal(resp)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(err.Error()))
			return
		}
		if _, err = w.Write(jResp); err != nil {
			log.Printf("/add: %v", err)
			return
		}
	})

	// Proxy all GET requests to the filesystem as a lightweight file server.
	fs := http.FileServer(http.Dir(*storageDir))
	http.Handle("GET /checkpoint", addCacheHeaders("no-cache", fs))
	http.Handle("GET /tile/", addCacheHeaders("max-age=31536000, immutable", fs))

	address := fmt.Sprintf("%s:%d", *host, *port)
	fmt.Printf("Server running at %s\n", address)

	// Gracefully shutdown for SIGINT/SIGTERM
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	srv := &http.Server{
		Addr:    address,
		Handler: http.DefaultServeMux,
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("error in ListenAndServe: %v", err)
		}
	}()

	// Wait until SIGINT/SIGTERM, then shutdown server and invoke Tessera cleanup
	sig := <-signalChan
	fmt.Printf("received %s, shutting down", sig)
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal(err)
	}
	if err := shutdown(ctx); err != nil {
		log.Fatal(err)
	}
}
