package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/haydentherapper/bt-log/internal/purl"
	"github.com/haydentherapper/bt-log/internal/pypi"
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
	entryType         = flag.String("entry-type", "", "Specifies the log entry structure. Valid types are ["+EntryTypePURL+", "+EntryTypePyPI+"]")
	purlType          = flag.String("purl-type", "", "Restricts pURLs to be of a specific type")
	privKeyFile       = flag.String("private-key", "", "Location of private key file")
	pubKeyFile        = flag.String("public-key", "", "Location of public key file")
	witnessUrl        = flag.String("witness-url", "", "Optional witness to cosign checkpoint")
	witnessPubKeyFile = flag.String("witness-public-key", "", "Optional witness public key location to verify cosignatures")
)

const (
	EntryTypePURL = "purl"
	EntryTypePyPI = "pypi"
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

type PyPILogEntry = pypi.Entry

type LogEntryResponse struct {
	Index          uint64   `json:"index"`
	Checkpoint     []byte   `json:"checkpoint"`
	InclusionProof [][]byte `json:"inclusionProof"`
}

type StatusPageData struct {
	Origin              string
	EntryType           string
	PURLType            string
	StorageDir          string
	WitnessConfigured   bool
	CheckpointAvailable bool
	TreeSize            uint64
	RootHash            string
	RawCheckpoint       string
	CheckpointError     string
	GeneratedAt         string
}

var statusPageTmpl = template.Must(template.New("status").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>bt-log status</title>
  <style>
    body { font-family: system-ui, sans-serif; margin: 2rem; line-height: 1.4; max-width: 900px; }
    table { border-collapse: collapse; margin: 1rem 0; }
    th { text-align: left; padding-right: 1.5rem; }
    th, td { padding-top: 0.35rem; padding-bottom: 0.35rem; vertical-align: top; }
    code, pre { background: #f6f8fa; border-radius: 6px; }
    code { padding: 0.1rem 0.3rem; }
    pre { padding: 1rem; overflow-x: auto; }
  </style>
</head>
<body>
  <h1>bt-log status</h1>
  <table>
    <tr><th>Origin</th><td><code>{{.Origin}}</code></td></tr>
    <tr><th>Entry type</th><td><code>{{.EntryType}}</code>{{if .PURLType}} / <code>{{.PURLType}}</code>{{end}}</td></tr>
    <tr><th>Storage directory</th><td><code>{{.StorageDir}}</code></td></tr>
    <tr><th>Witness</th><td>{{if .WitnessConfigured}}configured{{else}}not configured{{end}}</td></tr>
    <tr><th>Generated at</th><td>{{.GeneratedAt}}</td></tr>
  </table>

  <h2>Checkpoint</h2>
  {{if .CheckpointAvailable}}
  <table>
    <tr><th>Tree size</th><td>{{.TreeSize}}</td></tr>
    <tr><th>Root hash</th><td><code>{{.RootHash}}</code></td></tr>
  </table>
  <pre>{{.RawCheckpoint}}</pre>
  {{else}}
  <p>No checkpoint is available yet.</p>
  {{if .CheckpointError}}<p><strong>Error:</strong> <code>{{.CheckpointError}}</code></p>{{end}}
  {{end}}

  <h2>Links</h2>
  <ul>
    <li><a href="/checkpoint">/checkpoint</a></li>
    <li><a href="/tile/">/tile/</a></li>
  </ul>
</body>
</html>`))

func main() {
	flag.Parse()

	if *storageDir == "" {
		log.Fatalf("--storage-dir must be set")
	}
	if *entryType != EntryTypePURL && *entryType != EntryTypePyPI {
		log.Fatalf("--entry-type must be set to either '%s' or '%s'", EntryTypePURL, EntryTypePyPI)
	}
	if *entryType == EntryTypePURL && *purlType == "" {
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
		WithCheckpointInterval(time.Second).
		WithBatching(1024, 100*time.Millisecond).
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
	await := tessera.NewPublicationAwaiter(ctx, r.ReadCheckpoint, 200*time.Millisecond)

	http.HandleFunc("GET /", func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/" {
			http.NotFound(w, req)
			return
		}

		data := StatusPageData{
			Origin:            v.Name(),
			EntryType:         *entryType,
			StorageDir:        *storageDir,
			WitnessConfigured: witness != nil,
			GeneratedAt:       time.Now().UTC().Format(time.RFC3339),
		}
		if *entryType == EntryTypePURL {
			data.PURLType = *purlType
		}

		rawCp, err := r.ReadCheckpoint(req.Context())
		if err != nil {
			data.CheckpointError = err.Error()
		} else {
			cp, _, _, err := f_log.ParseCheckpoint(rawCp, v.Name(), v)
			if err != nil {
				data.CheckpointError = err.Error()
			} else {
				data.CheckpointAvailable = true
				data.TreeSize = cp.Size
				data.RootHash = hex.EncodeToString(cp.Hash)
				data.RawCheckpoint = string(rawCp)
			}
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := statusPageTmpl.Execute(w, data); err != nil {
			log.Printf("status page: %v", err)
		}
	})

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
		case EntryTypePURL:
			e = &PURLLogEntry{}
		case EntryTypePyPI:
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

		if *entryType == EntryTypePURL {
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
