package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/gob"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"regexp"
	"syscall"
	"time"

	"github.com/haydentherapper/bt-log/internal/pypi"
	"github.com/package-url/packageurl-go"
	tlog "github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/tessera/api/layout"
	"github.com/transparency-dev/tessera/client"
	"golang.org/x/mod/sumdb/note"
)

const (
	entryTypePURL = "purl"
	entryTypePyPI = "pypi"
)

var (
	logURL             = flag.String("log-url", "", "Log URL")
	pubKeyPath         = flag.String("public-key", "", "Path for log public key")
	storageDir         = flag.String("storage-dir", "", "Directory to store last verified checkpoint")
	once               = flag.Bool("once", true, "Whether to run in a loop or not")
	frequency          = flag.Duration("frequency", time.Minute, "How often to run the monitor")
	debug              = flag.Bool("debug", false, "Print additional information")
	jsonLogging        = flag.Bool("json-logging", false, "Output log messages as JSON")
	entryType          = flag.String("entry-type", entryTypePyPI, "Entry type: purl or pypi")
	purlTypeRegex      = flag.String("purl-type-regex", "", "Regex to match pURL type. Must set all pURL regex if set")
	purlNamespaceRegex = flag.String("purl-namespace-regex", "", "Regex to match pURL namespace. Must set all pURL regex if set")
	purlNameRegex      = flag.String("purl-name-regex", "", "Regex to match pURL name. Must set all pURL regex if set")
	purlVersionRegex   = flag.String("purl-version-regex", "", "Regex to match pURL version. Must set all pURL regex if set")
	checksumRegex      = flag.String("checksum-regex", "", "Regex to match PyPI checksum")
	filenameRegex      = flag.String("filename-regex", "", "Regex to match PyPI filename")
)

func errAttr(err error) slog.Attr {
	return slog.Any("error", err)
}

func processPURLEntry(raw []byte, regexMatch bool, idHashMap map[string]string, ebIndex uint64, logSize uint64) {
	// Parse pURL string
	purl, err := packageurl.FromString(string(raw))
	if err != nil {
		slog.Error("error parsing pURL", "purl", string(raw), "tile-index", ebIndex, "log-size", logSize, errAttr(err))
		return
	}
	slog.Debug("New entry", "purl", purl.String(), "tile-index", ebIndex, "log-size", logSize)

	// Log if entry matches provided regex
	if regexMatch {
		typeMatch, err := regexp.MatchString(*purlTypeRegex, purl.Type)
		if err != nil {
			slog.Error("error matching pURL", "purl", purl.String(),
				"matcher", "type", "value", purl.Type, "regex", *purlTypeRegex,
				"tile-index", ebIndex, "log-size", logSize, errAttr(err))
			return
		}
		namespaceMatch, err := regexp.MatchString(*purlNamespaceRegex, purl.Namespace)
		if err != nil {
			slog.Error("error matching pURL", "purl", purl.String(),
				"matcher", "namespace", "value", purl.Namespace, "regex", *purlNamespaceRegex,
				"tile-index", ebIndex, "log-size", logSize, errAttr(err))
			return
		}
		nameMatch, err := regexp.MatchString(*purlNameRegex, purl.Name)
		if err != nil {
			slog.Error("error matching pURL", "purl", purl.String(),
				"matcher", "name", "value", purl.Name, "regex", *purlNameRegex,
				"tile-index", ebIndex, "log-size", logSize, errAttr(err))
			return
		}
		versionMatch, err := regexp.MatchString(*purlVersionRegex, purl.Version)
		if err != nil {
			slog.Error("error matching pURL", "purl", purl.String(),
				"matcher", "version", "value", purl.Version, "regex", *purlVersionRegex,
				"tile-index", ebIndex, "log-size", logSize, errAttr(err))
			return
		}
		if typeMatch && namespaceMatch && nameMatch && versionMatch {
			slog.Info("Entry found", "purl", purl.String(), "tile-index", ebIndex, "log-size", logSize)
		}
	}

	// Verify 1-1 mapping between package ID and checksum
	checksum, ok := purl.Qualifiers.Map()["checksum"]
	if !ok {
		slog.Error("error getting checksum from pURL", "purl", purl.String(), "tile-index", ebIndex, "log-size", logSize)
		return
	}
	purlWithoutChecksum := packageurl.NewPackageURL(purl.Type, purl.Namespace, purl.Name,
		purl.Version, nil, "").ToString()
	existing, found := idHashMap[purlWithoutChecksum]
	if found && checksum != existing {
		// Log if mapping is no longer 1-1
		slog.Error(
			fmt.Sprintf("ALERT: mismatched checksum for purl %s, got %s, expected %s",
				purlWithoutChecksum, existing, checksum),
			"purl", purl.String())
		return
	}
	idHashMap[purlWithoutChecksum] = checksum
}

func processPyPIEntry(raw []byte, regexMatch bool, idHashMap map[string]string, ebIndex uint64, logSize uint64) {
	var entry pypi.Entry
	if err := entry.Unmarshal(raw); err != nil {
		slog.Error("error parsing pypi entry", "raw", string(raw), "tile-index", ebIndex, "log-size", logSize, errAttr(err))
		return
	}
	slog.Debug("New entry", "checksum", entry.Checksum, "filename", entry.Filename, "tile-index", ebIndex, "log-size", logSize)

	if regexMatch {
		matchPyPI(entry.Checksum, entry.Filename, ebIndex, logSize)
	}

	existing, found := idHashMap[entry.Filename]
	if found && entry.Checksum != existing {
		slog.Error(
			fmt.Sprintf("ALERT: mismatched checksum for filename %s, got %s, expected %s",
				entry.Filename, existing, entry.Checksum),
			"filename", entry.Filename)
		return
	}
	idHashMap[entry.Filename] = entry.Checksum
}

func matchPyPI(checksum, filename string, ebIndex, logSize uint64) {
	if *checksumRegex != "" {
		m, err := regexp.MatchString(*checksumRegex, checksum)
		if err != nil {
			slog.Error("error matching checksum", "checksum", checksum, "regex", *checksumRegex,
				"tile-index", ebIndex, "log-size", logSize, errAttr(err))
			return
		}
		if !m {
			return
		}
	}
	if *filenameRegex != "" {
		m, err := regexp.MatchString(*filenameRegex, filename)
		if err != nil {
			slog.Error("error matching filename", "filename", filename, "regex", *filenameRegex,
				"tile-index", ebIndex, "log-size", logSize, errAttr(err))
			return
		}
		if !m {
			return
		}
	}
	slog.Info("Entry found", "checksum", checksum, "filename", filename, "tile-index", ebIndex, "log-size", logSize)
}

func main() {
	flag.Parse()

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
		slog.SetLogLoggerLevel(level)
	}
	if *jsonLogging {
		logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
			Level: level,
		}))
		slog.SetDefault(logger)
	}

	if *logURL == "" {
		slog.Error("--log-url must be set")
		os.Exit(1)
	}
	if *pubKeyPath == "" {
		slog.Error("--public-key must be set")
		os.Exit(1)
	}
	if *storageDir == "" {
		slog.Error("--storage-dir must be set")
		os.Exit(1)
	}
	if *entryType != entryTypePURL && *entryType != entryTypePyPI {
		slog.Error("--entry-type must be purl or pypi")
		os.Exit(1)
	}
	purlRegexMatch := *purlTypeRegex != "" && *purlNamespaceRegex != "" && *purlNameRegex != "" && *purlVersionRegex != ""
	pypiRegexMatch := *checksumRegex != "" || *filenameRegex != ""

	ticker := time.NewTicker(*frequency)
	defer ticker.Stop()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

	// for-select at end of loop due to ticker not ticking initially
	for {
		lURL, err := url.Parse(*logURL)
		if err != nil {
			slog.Error("error parsing log URL", errAttr(err))
			return
		}

		// Initialize client to fetch latest checkpoint and entry bundles
		logFetcher, err := client.NewHTTPFetcher(lURL, http.DefaultClient)
		if err != nil {
			slog.Error("error creating log HTTP client", errAttr(err))
			return
		}

		// Create checkpoint verifier using log public key
		pubKey, err := os.ReadFile(*pubKeyPath)
		if err != nil {
			slog.Error("failed to read public key file", "file", *pubKeyPath, errAttr(err))
			return
		}
		v, err := note.NewVerifier(string(pubKey))
		if err != nil {
			slog.Error("failed to initialize checkpoint verifier", "file", *pubKeyPath, errAttr(err))
			return
		}

		// Parse and verify previous and latest checkpoints
		checkpointPath := path.Join(*storageDir, "checkpoint")
		previousCPBytes, err := os.ReadFile(checkpointPath)
		first := false
		if err != nil {
			// Handle when no checkpoint exists, for the first run of the monitor
			if errors.Is(err, os.ErrNotExist) {
				first = true
			} else {
				slog.Error("failed to read previous checkpoint", errAttr(err))
				return
			}
		}
		// Initialize empty package ID->hash map, to be overwritten
		// if this is not the first run
		idHashMap := make(map[string]string)
		idHashMapPath := path.Join(*storageDir, "idhashmap")

		var previousCP *tlog.Checkpoint
		if first {
			emptyRoot := sha256.Sum256([]byte{})
			previousCP = &tlog.Checkpoint{
				Origin: v.Name(),
				Size:   0,
				Hash:   emptyRoot[:],
			}
		} else {
			previousCP, _, _, err = tlog.ParseCheckpoint(previousCPBytes, v.Name(), v)
			if err != nil {
				slog.Error("failed to verify previous checkpoint", errAttr(err))
				return
			}
			f, err := os.Open(idHashMapPath)
			if err != nil {
				slog.Error("error opening map file", errAttr(err))
				return
			}
			defer f.Close()
			dec := gob.NewDecoder(bufio.NewReader(f))
			if err := dec.Decode(&idHashMap); err != nil {
				slog.Error("error decoding map from disk", errAttr(err))
				return
			}
		}
		latestCPBytes, err := logFetcher.ReadCheckpoint(context.Background())
		if err != nil {
			slog.Error("error reading latest log checkpoint", errAttr(err))
			return
		}
		latestCP, _, _, err := tlog.ParseCheckpoint(latestCPBytes, v.Name(), v)
		if err != nil {
			slog.Error("failed to verify latest checkpoint", errAttr(err))
			return
		}

		// Pass the latest checkpoint even though we haven't verified consistency yet.
		// It's only used for building inclusion proofs, which aren't needed here.
		pb, err := client.NewProofBuilder(context.Background(), latestCP.Size, logFetcher.ReadTile)
		if err != nil {
			slog.Error("error creating proof builder", errAttr(err))
			return
		}

		// Verify consistency before requesting new entries
		consistencyProof, err := pb.ConsistencyProof(context.Background(), previousCP.Size, latestCP.Size)
		if err != nil {
			slog.Error("error constructing consistency proof", errAttr(err))
			return
		}
		if err := proof.VerifyConsistency(rfc6962.DefaultHasher, previousCP.Size, latestCP.Size, consistencyProof, previousCP.Hash, latestCP.Hash); err != nil {
			slog.Error("error verifying consistency proof", errAttr(err))
			return
		}

		// Iterate over all entry bundles, from the previous up to latest log size
		entryBundles := layout.Range(previousCP.Size, latestCP.Size-previousCP.Size, latestCP.Size)
		for eb := range entryBundles {
			entries, err := client.GetEntryBundle(context.Background(), logFetcher.ReadEntryBundle, eb.Index, latestCP.Size)
			if err != nil {
				slog.Error("error fetching entry bundle", "tile-index", eb.Index, "log-size", latestCP.Size, errAttr(err))
				return
			}
			// Iterate over each entry in the bundle, which may be from a partial tile
			for _, e := range entries.Entries[eb.First:] {
				switch *entryType {
				case entryTypePURL:
					processPURLEntry(e, purlRegexMatch, idHashMap, eb.Index, latestCP.Size)
				case entryTypePyPI:
					processPyPIEntry(e, pypiRegexMatch, idHashMap, eb.Index, latestCP.Size)
				}
			}
		}

		// Persist latest checkpoint
		if err := os.MkdirAll(*storageDir, 0o755); err != nil {
			slog.Error("error creating directory for checkpoint", errAttr(err))
			return
		}
		if err := os.WriteFile(checkpointPath, latestCPBytes, 0o644); err != nil {
			slog.Error("error writing latest checkpoint", errAttr(err))
			return
		}

		// Persist encoded package ID -> hash map
		var buffer bytes.Buffer
		enc := gob.NewEncoder(&buffer)
		if err := enc.Encode(idHashMap); err != nil {
			slog.Error("error encoding map", errAttr(err))
			return
		}
		if err := os.WriteFile(idHashMapPath, buffer.Bytes(), 0o644); err != nil {
			slog.Error("error writing map", errAttr(err))
			return
		}

		// Exit early if continuous monitoring isn't requested
		if *once {
			return
		}

		// Wait until a tick or SIGTERM
		select {
		case <-ticker.C:
			continue
		case <-signalChan:
			slog.Info("received signal, exiting")
			return
		}
	}
}
