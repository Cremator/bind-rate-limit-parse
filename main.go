package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"regexp"
	"time"

	"github.com/dgraph-io/badger/v4"
	"go4.org/netipx"
)

var (
	cidrWebPrefix string
	expiration    time.Duration
	dbPath        string
	httpPort      string
	db            *badger.DB
	ctx, cancel   = context.WithCancel(context.Background())
	invalidSet    *netipx.IPSet
	cidrRegex     = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}\b`)
	cidrCh        = make(chan map[string]string, 10000)
)

func init() {
	// Command line flags configuration for application settings

	// URL path prefix for HTTP endpoint serving CIDR data
	flag.StringVar(&cidrWebPrefix, "webprefix", "/cidrs", "Prefix for HTTP CIDRs endpoint")

	// Time after which individual CIDR entries expire (in seconds)
	flag.DurationVar(&expiration, "expiration", time.Hour*2, "Expiration time for individual CIDRs")

	// Redis database number selection
	flag.StringVar(&dbPath, "dbpath", "/badger-data", "Select Badger DB path")

	// Port for the HTTP server to listen on
	flag.StringVar(&httpPort, "port", "8080", "HTTP server port")

	// Parse command line flags to populate the variables
	flag.Parse()
	b := netipx.IPSetBuilder{}

	b.AddPrefix(netip.MustParsePrefix("0.0.0.0/8"))
	b.AddPrefix(netip.MustParsePrefix("10.0.0.0/8"))
	b.AddPrefix(netip.MustParsePrefix("100.64.0.0/10"))
	b.AddPrefix(netip.MustParsePrefix("127.0.0.0/8"))
	b.AddPrefix(netip.MustParsePrefix("169.254.0.0/16"))
	b.AddPrefix(netip.MustParsePrefix("172.16.0.0/12"))
	b.AddPrefix(netip.MustParsePrefix("192.0.0.0/24"))
	b.AddPrefix(netip.MustParsePrefix("192.0.2.0/24"))
	b.AddPrefix(netip.MustParsePrefix("192.88.99.0/24"))
	b.AddPrefix(netip.MustParsePrefix("192.168.0.0/16"))
	b.AddPrefix(netip.MustParsePrefix("198.18.0.0/15"))
	b.AddPrefix(netip.MustParsePrefix("198.51.100.0/24"))
	b.AddPrefix(netip.MustParsePrefix("203.0.113.0/24"))
	b.AddPrefix(netip.MustParsePrefix("240.0.0.0/4"))
	b.AddPrefix(netip.MustParsePrefix("255.255.255.255/32"))

	invalidSet, _ = b.IPSet()
}

func main() {
	defer cancel()

	// Handle OS signals to trigger cancellation
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)

	go func() {
		<-sigCh
		log.Println("Received termination signal. Shutting down...")
		cancel()
	}()

	// Initialize BadgerDB with specified options for performance and log management
	opts := badger.DefaultOptions(dbPath)
	opts.Logger = nil                   // silence logs if needed
	opts.ValueLogFileSize = 128<<20 - 1 // 128MB value log file size for faster writes

	var err error
	db, err = badger.Open(opts)
	if err != nil {
		log.Fatalf("Error opening BadgerDB: %v", err)
	}
	defer db.Close()
	// Start a goroutine to periodically run Badger's value log garbage collection to manage disk space
	go func() {
		for {
			time.Sleep(5 * time.Minute)
			for {
				if err := db.RunValueLogGC(0.5); err != nil {
					break
				}
			}
		}
	}()
	// Start a goroutine to process CIDR entries from the channel and insert them into Badger
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case c := <-cidrCh:
				if len(c) == 0 {
					continue
				}
				insertCIDRsToBadger(c)
			}
		}
	}()
	// Start syslog server
	go startSyslogServer()

	// Start HTTP server
	http.HandleFunc(cidrWebPrefix, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-ctx.Done():
			http.Error(w, "Server shutting down", http.StatusServiceUnavailable)
			return
		default:
			// Retrieve all CIDRs from Badger
			cidrs, err := getAllCIDRs()
			if err != nil {
				http.Error(w, "Failed to retrieve CIDRs", http.StatusInternalServerError)
				return
			}

			// Generate plain text response
			w.Header().Set("Content-Type", "text/plain")
			for _, cidr := range cidrs {
				fmt.Fprintf(w, "%s\n", cidr)
			}
			log.Printf("HTTP Web request for URL: %s, from: %s, header: %s, cidrs: %d\n", r.URL, r.RemoteAddr, r.Header, len(cidrs))
		}
	})

	// Start listening on the specified port
	log.Printf("HTTP Server listening on port %s\n", httpPort)
	server := http.Server{Addr: ":" + httpPort}
	go func() {
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			log.Println("HTTP server error:", err)
		}
	}()

	// Monitor context cancellation
	<-ctx.Done()

	// Shutdown HTTP server gracefully
	log.Println("Shutting down HTTP server...")
	if err := server.Shutdown(context.Background()); err != nil {
		log.Println("HTTP server shutdown error:", err)
	}
}

func startSyslogServer() {
	// Set up UDP listener on port 514
	udpAddr, err := net.ResolveUDPAddr("udp", ":514")
	if err != nil {
		log.Fatalf("Failed to resolve UDP address: %v", err)
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("Failed to listen on UDP: %v", err)
	}
	defer udpConn.Close()

	// Set up TCP listener on port 514
	tcpAddr, err := net.ResolveTCPAddr("tcp", ":514")
	if err != nil {
		log.Fatalf("Failed to resolve TCP address: %v", err)
	}

	tcpListener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		log.Fatalf("Failed to listen on TCP: %v", err)
	}
	defer tcpListener.Close()

	log.Println("Rsyslog server is listening on port 514...")

	// Start a goroutine to handle UDP syslog messages
	go handleUDP(udpConn)

	// Start a goroutine to handle TCP syslog messages
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			tcpConn, err := tcpListener.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				log.Printf("accept error: %v", err)
				continue
			}
			go handleTCP(tcpConn)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown
	<-ctx.Done()

	log.Println("Closing syslog listeners...")

	_ = tcpListener.Close()
	_ = udpConn.Close()

	time.Sleep(200 * time.Millisecond) // allow goroutines to exit cleanly

	log.Println("Syslog server stopped")
}

func handleUDP(conn *net.UDPConn) {
	buf := make([]byte, 65535)

	for {

		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))

		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}

		select {
		case cidrCh <- extractCIDRsFromMessage(string(buf[:n])):
		default:
			log.Println("cidrCh full, dropping syslog message")
		}
	}
}

func handleTCP(conn net.Conn) {
	defer conn.Close()

	r := bufio.NewReader(conn)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		conn.SetReadDeadline(time.Now().Add(60 * time.Second))

		line, err := r.ReadString('\n')
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			return
		}

		select {
		case cidrCh <- extractCIDRsFromMessage(line):
		default:
			log.Println("cidrCh full, dropping syslog message")
		}
	}
}

func extractCIDRsFromMessage(m string) map[string]string {
	// Extract CIDRs from the message

	matchesr := cidrRegex.FindAllString(m, -1)
	var matches = make(map[string]string)
	for _, ms := range matchesr {
		if c, err := netip.ParsePrefix(ms); err != nil {
			log.Println("Error parsing CIDR:", err)
			continue
		} else if c.Bits() < 24 || ms != c.String() || invalidSet.ContainsPrefix(c) {
			log.Printf("Error CIDR conversion - origin - %s - convert - %s\n", ms, c.String())
			continue
		} else {
			matches[c.String()] = m
		}
	}
	log.Printf("Received syslog message: %s\n", m)
	return matches
}

func insertCIDRsToBadger(c map[string]string) {
	if len(c) == 0 {
		return
	}

	err := db.Update(func(txn *badger.Txn) error {
		for cidr, msg := range c {
			if err := txn.SetEntry(
				badger.NewEntry([]byte(cidr), []byte(msg)).WithTTL(expiration + time.Duration(rand.Int64N(int64(expiration/2)))*time.Second),
			); err != nil {
				return err
			}
		}
		return nil
	})

	if err != nil {
		log.Println("Badger insert error:", err)
	}
}

func getAllCIDRs() ([]string, error) {
	var cidrs []string
	var sorted netipx.IPSetBuilder

	err := db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			key := item.Key()

			cidrStr := string(key)

			c, err := netip.ParsePrefix(cidrStr)
			if err != nil {
				continue
			}

			if c.Bits() < 24 {
				continue
			}

			sorted.AddPrefix(c)
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	merged, _ := sorted.IPSet()
	for _, c := range merged.Prefixes() {
		cidrs = append(cidrs, c.String())
	}

	return cidrs, nil
}
