package main

import (
	"bufio"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	emailverifier "github.com/AfterShip/email-verifier"
	_ "github.com/mattn/go-sqlite3"
)

type VerificationStatus string

const (
	StatusClean       VerificationStatus = "clean"
	StatusBounced     VerificationStatus = "bounced"
	StatusBadSyntax   VerificationStatus = "bad_syntax"
	StatusBadNoMX     VerificationStatus = "bad_no_mx"
	StatusDisposable  VerificationStatus = "bad_disposable"
	StatusRoleAccount VerificationStatus = "role_account"
)

type VerifyResult struct {
	Email      string
	Status     VerificationStatus
	Reason     string
	Domain     string
	HasMX      bool
	Disposable bool
	Role       bool
	Free       bool
	Suggestion string
}

type DomainCacheEntry struct {
	HasMX bool
	Err   error
}

type BatchVerifier struct {
	verifier    *emailverifier.Verifier
	blacklist   map[string]struct{}
	domainCache sync.Map
	concurrency int
}

func NewBatchVerifier(blacklistPath string, concurrency int) (*BatchVerifier, error) {
	v := emailverifier.NewVerifier().EnableDomainSuggest()
	bl := make(map[string]struct{})

	if blacklistPath != "" {
		if f, err := os.Open(blacklistPath); err == nil {
			defer f.Close()
			if strings.HasSuffix(blacklistPath, ".json") {
				var list []string
				if err := json.NewDecoder(f).Decode(&list); err == nil {
					for _, em := range list {
						bl[strings.ToLower(strings.TrimSpace(em))] = struct{}{}
					}
				}
			} else {
				scanner := bufio.NewScanner(f)
				for scanner.Scan() {
					em := strings.ToLower(strings.TrimSpace(scanner.Text()))
					if strings.Contains(em, "@") {
						bl[em] = struct{}{}
					}
				}
			}
			fmt.Printf("Loaded %d blacklisted/bounced emails into verifier memory.\n", len(bl))
		}
	}

	return &BatchVerifier{
		verifier:    v,
		blacklist:   bl,
		concurrency: concurrency,
	}, nil
}

func (bv *BatchVerifier) checkDomainMX(domain string) (bool, error) {
	if val, ok := bv.domainCache.Load(domain); ok {
		entry := val.(DomainCacheEntry)
		return entry.HasMX, entry.Err
	}

	mx, err := bv.verifier.CheckMX(domain)
	hasMX := false
	if mx != nil && mx.HasMXRecord {
		hasMX = true
	}
	bv.domainCache.Store(domain, DomainCacheEntry{HasMX: hasMX, Err: err})
	return hasMX, err
}

func (bv *BatchVerifier) VerifyOne(rawEmail string) VerifyResult {
	email := strings.ToLower(strings.TrimSpace(rawEmail))
	res := VerifyResult{
		Email:  email,
		Status: StatusClean,
	}

	if email == "" {
		res.Status = StatusBadSyntax
		res.Reason = "empty_email"
		return res
	}

	// 1. Check Blacklist / Prior Bounces
	if _, ok := bv.blacklist[email]; ok {
		res.Status = StatusBounced
		res.Reason = "blacklisted_or_previously_bounced"
		return res
	}

	// 2. Syntax Check
	syntax := bv.verifier.ParseAddress(email)
	if !syntax.Valid {
		res.Status = StatusBadSyntax
		res.Reason = "invalid_rfc5322_syntax"
		return res
	}

	res.Domain = syntax.Domain
	res.Free = bv.verifier.IsFreeDomain(syntax.Domain)
	res.Role = bv.verifier.IsRoleAccount(syntax.Username)
	res.Disposable = bv.verifier.IsDisposable(syntax.Domain)
	res.Suggestion = bv.verifier.SuggestDomain(syntax.Domain)

	// 3. Disposable Domain Check
	if res.Disposable {
		res.Status = StatusDisposable
		res.Reason = "disposable_domain"
		return res
	}

	// 4. DNS MX Check (Cached per domain)
	hasMX, err := bv.checkDomainMX(syntax.Domain)
	res.HasMX = hasMX
	if !hasMX || err != nil {
		res.Status = StatusBadNoMX
		if err != nil {
			res.Reason = err.Error()
		} else {
			res.Reason = "no_mx_records_found"
		}
		return res
	}

	// 5. Role Account Check
	if res.Role {
		res.Status = StatusRoleAccount
		res.Reason = "role_based_mailbox"
		return res
	}

	// 6. Clean
	res.Status = StatusClean
	res.Reason = "verified_clean_active_mx"
	return res
}

func verifySQLiteDB(dbPath, blacklistPath string, concurrency, limit, batchSize int, daemon bool) {
	fmt.Printf("=== Starting High-Performance Email Verification on SQLite DB ===\n")
	fmt.Printf("Database: %s\n", dbPath)

	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_busy_timeout=10000")
	if err != nil {
		log.Fatalf("Failed to open SQLite DB: %v", err)
	}
	defer db.Close()

	// Ensure target verification table exists
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS email_verifications (
			email TEXT PRIMARY KEY,
			status TEXT,
			reason TEXT,
			domain TEXT,
			has_mx INTEGER,
			is_disposable INTEGER,
			is_role INTEGER,
			is_free INTEGER,
			suggestion TEXT,
			verified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_verif_status ON email_verifications(status);

		CREATE VIEW IF NOT EXISTS v_clean_leads AS 
		SELECT l.* 
		FROM leads l 
		INNER JOIN email_verifications v ON l.email = v.email 
		WHERE v.status = 'clean';

		CREATE VIEW IF NOT EXISTS v_bad_leads AS 
		SELECT l.*, v.status as verification_status, v.reason as verification_reason
		FROM leads l 
		INNER JOIN email_verifications v ON l.email = v.email 
		WHERE v.status != 'clean';
	`)
	if err != nil {
		log.Fatalf("Failed to create verification table/views: %v", err)
	}

	bv, err := NewBatchVerifier(blacklistPath, concurrency)
	if err != nil {
		log.Fatalf("Failed to initialize batch verifier: %v", err)
	}

	// Count already verified
	var verifiedCount int
	_ = db.QueryRow("SELECT COUNT(*) FROM email_verifications;").Scan(&verifiedCount)
	var totalLeads int
	_ = db.QueryRow("SELECT COUNT(*) FROM leads;").Scan(&totalLeads)
	fmt.Printf("Database status: %d / %d leads verified so far.\n", verifiedCount, totalLeads)

	chunkSize := 25000
	totalToProcess := limit
	if totalToProcess <= 0 {
		totalToProcess = totalLeads - verifiedCount
	}
	fmt.Printf("Target to verify: %d emails with %d concurrent workers (chunk size: %d)...\n", totalToProcess, concurrency, chunkSize)

	totalProcessed := 0
	for {
		curLimit := chunkSize
		if limit > 0 {
			remaining := limit - totalProcessed
			if remaining <= 0 {
				break
			}
			if remaining < curLimit {
				curLimit = remaining
			}
		}

		rows, err := db.Query("SELECT l.email FROM leads l WHERE l.email NOT IN (SELECT email FROM email_verifications) LIMIT ?", curLimit)
		if err != nil {
			log.Fatalf("Query error: %v", err)
		}

		var emailList []string
		for rows.Next() {
			var em string
			if err := rows.Scan(&em); err == nil {
				emailList = append(emailList, em)
			}
		}
		rows.Close()

		if len(emailList) == 0 {
			if daemon {
				fmt.Printf("[%s] No unverified leads in database. Sleeping 10s for incoming harvester leads...\n", time.Now().Format("15:04:05"))
				time.Sleep(10 * time.Second)
				continue
			}
			fmt.Println("All leads in database are verified!")
			break
		}

		// Channels for work distribution
		jobs := make(chan string, concurrency*4)
		results := make(chan VerifyResult, concurrency*4)

		var wg sync.WaitGroup
		for w := 0; w < concurrency; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for em := range jobs {
					results <- bv.VerifyOne(em)
				}
			}()
		}

		// Inserter routine
		doneInserter := make(chan struct{})
		var chunkClean, chunkBounce, chunkNoMX, chunkDisp, chunkRole, chunkSyntax int64

		go func() {
			defer close(doneInserter)
			batch := make([]VerifyResult, 0, batchSize)

			flush := func() {
				if len(batch) == 0 {
					return
				}
				tx, err := db.Begin()
				if err != nil {
					log.Printf("Tx begin error: %v", err)
					return
				}
				stmt, err := tx.Prepare(`
					INSERT OR REPLACE INTO email_verifications 
					(email, status, reason, domain, has_mx, is_disposable, is_role, is_free, suggestion) 
					VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
				`)
				if err != nil {
					_ = tx.Rollback()
					log.Printf("Stmt prepare error: %v", err)
					return
				}
				for _, r := range batch {
					hasMxInt := 0
					if r.HasMX {
						hasMxInt = 1
					}
					dispInt := 0
					if r.Disposable {
						dispInt = 1
					}
					roleInt := 0
					if r.Role {
						roleInt = 1
					}
					freeInt := 0
					if r.Free {
						freeInt = 1
					}
					_, _ = stmt.Exec(r.Email, string(r.Status), r.Reason, r.Domain, hasMxInt, dispInt, roleInt, freeInt, r.Suggestion)
				}
				_ = stmt.Close()
				if err := tx.Commit(); err != nil {
					log.Printf("Tx commit error: %v", err)
				}
				batch = batch[:0]
			}

			for res := range results {
				batch = append(batch, res)
				switch res.Status {
				case StatusClean:
					atomic.AddInt64(&chunkClean, 1)
				case StatusBounced:
					atomic.AddInt64(&chunkBounce, 1)
				case StatusBadNoMX:
					atomic.AddInt64(&chunkNoMX, 1)
				case StatusDisposable:
					atomic.AddInt64(&chunkDisp, 1)
				case StatusRoleAccount:
					atomic.AddInt64(&chunkRole, 1)
				case StatusBadSyntax:
					atomic.AddInt64(&chunkSyntax, 1)
				}
				if len(batch) >= batchSize {
					flush()
				}
			}
			flush()
		}()

		t0 := time.Now()
		for _, em := range emailList {
			jobs <- em
		}
		close(jobs)
		wg.Wait()
		close(results)
		<-doneInserter

		totalProcessed += len(emailList)
		elapsed := time.Since(t0).Seconds()
		rate := float64(len(emailList)) / elapsed
		fmt.Printf("  Chunk complete: %d verified in %.1fs (%.0f emails/sec) | Clean: %d, Bounces: %d, Bad MX: %d, Disp: %d\n",
			len(emailList), elapsed, rate, chunkClean, chunkBounce, chunkNoMX, chunkDisp)

		if limit > 0 && totalProcessed >= limit {
			break
		}
	}

	fmt.Printf("\n=== Verification Batch Complete ===\n")
	printStats(db)
}

func verifyCSV(csvIn, csvOut, blacklistPath string, concurrency int) {
	fmt.Printf("=== Verifying CSV: %s ===\n", csvIn)
	f, err := os.Open(csvIn)
	if err != nil {
		log.Fatalf("Failed to open CSV: %v", err)
	}
	defer f.Close()

	reader := csv.NewReader(f)
	header, err := reader.Read()
	if err != nil {
		log.Fatalf("Failed to read CSV header: %v", err)
	}

	emailIdx := 1
	for i, h := range header {
		if strings.Contains(strings.ToLower(h), "email") {
			emailIdx = i
			break
		}
	}

	bv, err := NewBatchVerifier(blacklistPath, concurrency)
	if err != nil {
		log.Fatalf("Failed to create verifier: %v", err)
	}

	var rows [][]string
	for {
		r, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		rows = append(rows, r)
	}
	total := len(rows)
	fmt.Printf("Loaded %d rows from %s (email column index: %d)\n", total, csvIn, emailIdx)
	fmt.Printf("Verifying with %d parallel workers...\n", concurrency)

	type csvJob struct {
		idx int
		row []string
		em  string
	}
	type csvResult struct {
		idx int
		res VerifyResult
	}

	jobs := make(chan csvJob, concurrency*4)
	results := make(chan csvResult, concurrency*4)
	verifiedResults := make([]VerifyResult, total)

	var wg sync.WaitGroup
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				results <- csvResult{
					idx: j.idx,
					res: bv.VerifyOne(j.em),
				}
			}
		}()
	}

	doneCollector := make(chan struct{})
	counts := make(map[VerificationStatus]int)

	go func() {
		defer close(doneCollector)
		processed := 0
		for cr := range results {
			verifiedResults[cr.idx] = cr.res
			counts[cr.res.Status]++
			processed++
			if processed%1000 == 0 || processed == total {
				fmt.Printf("  Verified %d/%d (%.1f%%) | Clean: %d, Bounces: %d, Bad MX: %d, Disp: %d\n",
					processed, total, float64(processed)/float64(total)*100,
					counts[StatusClean], counts[StatusBounced], counts[StatusBadNoMX], counts[StatusDisposable])
			}
		}
	}()

	for i, r := range rows {
		em := ""
		if len(r) > emailIdx {
			em = r[emailIdx]
		}
		jobs <- csvJob{idx: i, row: r, em: em}
	}
	close(jobs)
	wg.Wait()
	close(results)
	<-doneCollector

	if csvOut != "" {
		outFile, err := os.Create(csvOut)
		if err != nil {
			log.Fatalf("Failed to create output CSV: %v", err)
		}
		defer outFile.Close()

		writer := csv.NewWriter(outFile)
		newHeader := append(header, "verification_status", "verification_reason", "has_mx", "is_disposable", "is_role")
		_ = writer.Write(newHeader)

		for i, r := range rows {
			res := verifiedResults[i]
			hasMXStr := "false"
			if res.HasMX {
				hasMXStr = "true"
			}
			dispStr := "false"
			if res.Disposable {
				dispStr = "true"
			}
			roleStr := "false"
			if res.Role {
				roleStr = "true"
			}
			outRow := append(r, string(res.Status), res.Reason, hasMXStr, dispStr, roleStr)
			_ = writer.Write(outRow)
		}
		writer.Flush()
		fmt.Printf("✅ Wrote %d verified results to %s\n", total, csvOut)
	}

	fmt.Printf("\n--- Verification Summary for %s ---\n", csvIn)
	for st, c := range counts {
		fmt.Printf("  %-16s: %6d (%5.1f%%)\n", st, c, float64(c)/float64(total)*100)
	}
}

func printStats(db *sql.DB) {
	fmt.Printf("\n=== SQLite Database Verification Statistics ===\n")
	var total int
	_ = db.QueryRow("SELECT COUNT(*) FROM email_verifications").Scan(&total)
	fmt.Printf("Total Verified in DB: %d\n", total)

	rows, err := db.Query(`
		SELECT status, count(*) FROM email_verifications GROUP BY status ORDER BY count(*) DESC;
	`)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var st string
		var cnt int
		if err := rows.Scan(&st, &cnt); err == nil {
			pct := 0.0
			if total > 0 {
				pct = float64(cnt) / float64(total) * 100
			}
			fmt.Printf("  %-16s: %8d (%5.1f%%)\n", st, cnt, pct)
		}
	}
}

func main() {
	dbPath := flag.String("db", "/Users/a/Downloads/scale_1m_batches/leads_master.db", "SQLite database path")
	blacklistPath := flag.String("blacklist", "/Users/a/Downloads/segmented_campaign_lists/complaints_blacklist.json", "Blacklist JSON or text file")
	csvIn := flag.String("csv", "", "Path to CSV file to verify")
	csvOut := flag.String("out", "", "Path to output verified CSV")
	concurrency := flag.Int("concurrency", 64, "Number of concurrent verification workers")
	limit := flag.Int("limit", 0, "Max number of emails to verify from DB (0 for all)")
	batchSize := flag.Int("batch", 2000, "SQLite insert batch transaction size")
	statsOnly := flag.Bool("stats", false, "Print verification stats from DB and exit")
	daemon := flag.Bool("daemon", false, "Run continuously in background, verifying new leads as they arrive")
	singleEmail := flag.String("email", "", "Verify a single email and print JSON result")
	flag.Parse()

	// 1. Single email mode
	if *singleEmail != "" {
		bv, err := NewBatchVerifier(*blacklistPath, 1)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
		res := bv.VerifyOne(*singleEmail)
		data, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(data))
		return
	}

	// 2. Stats only mode
	if *statsOnly {
		db, err := sql.Open("sqlite3", *dbPath)
		if err != nil {
			log.Fatalf("Failed to open DB: %v", err)
		}
		defer db.Close()
		printStats(db)
		return
	}

	// 3. CSV Mode
	if *csvIn != "" {
		verifyCSV(*csvIn, *csvOut, *blacklistPath, *concurrency)
		return
	}

	// 4. SQLite DB Mode
	verifySQLiteDB(*dbPath, *blacklistPath, *concurrency, *limit, *batchSize, *daemon)
}
