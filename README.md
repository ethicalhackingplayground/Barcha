 Barcha

[![Go Reference](https://pkg.go.dev/badge/github.com/youruser/barcha.svg)](https://pkg.go.dev/github.com/youruser/barcha)  
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Barcha** is a fast, Go‑based SQL Injection reconnaissance tool that leverages Shodan and Ghauri to discover, verify, and test live HTTPS hosts under your target domain. It automates:

- **Shodan Enumeration**: Finds SSL‑enabled hosts via a targeted dork.  
- **Live & Redirect Checks**: Confirms reachability, follows redirects, and ignores TLS certificate errors.  
- **Automated Testing**: Invokes [Ghauri](https://github.com/r0oth3x49/ghauri) per host, in batch mode, with customizable levels and payload dumps.  
- **Result Management**: Saves scan history in SQLite and prints a colorized table of live hosts.

---

## Features

- **Shodan Dork**: `hostname:"*.example.com" -403 -503 -http.title:"Invalid URL" -302 -404`  
- **Reverse DNS**: Resolves IPs to hostnames (skips Amazon AWS “IP NAT” addresses).  
- **Redirect Handling**: Transparently follows HTTP↔HTTPS redirects.  
- **TLS Flexibility**: Ignores expired or self‑signed certificates.  
- **Ghauri Integration**: Fully automated SQLi testing (`--batch`, `--confirm`, `--force-ssl`, `--level=3`, `--dbs`, `--dump`).  
- **Persistent History**: Logs each scan to `barcha_history.db`.

---

## Requirements

- Go **1.18+**  
- [Ghauri](https://github.com/r0oth3x49/ghauri) installed and on your `PATH`  
- A valid **Shodan API Key** (set in `SHODAN_API_KEY` environment variable)  

---

## Installation

### From Source

```bash
git clone https://github.com/youruser/barcha.git
cd barcha
go mod tidy
go build -o barcha main.go
