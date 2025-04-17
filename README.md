<p align="center">
  <img src="[https://raw.githubusercontent.com/youruser/barcha/main/banner.png](https://sdmntprnorthcentralus.oaiusercontent.com/files/00000000-63ac-622f-907d-c3131a842230/raw?se=2025-04-17T13%3A26%3A37Z&sp=r&sv=2024-08-04&sr=b&scid=246b7070-c341-58ac-b9de-c97cd8a66cd2&skoid=de76bc29-7017-43d4-8d90-7a49512bae0f&sktid=a48cca56-e6da-484e-a814-9c849652bcb3&skt=2025-04-16T21%3A27%3A13Z&ske=2025-04-17T21%3A27%3A13Z&sks=b&skv=2024-08-04&sig=xuYYFk5fLiKILoulz%2Bgl3V/UQevsRgaSwZoSJFZK9%2BE%3D)" alt="Barcha Banner" width="600"/>
</p>

# 🚀 Barcha

[![Go Reference](https://pkg.go.dev/badge/github.com/youruser/barcha.svg)](https://pkg.go.dev/github.com/youruser/barcha)  
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Barcha** is your Swiss‑Army knife for SQL Injection reconnaissance 🔍. Written in Go, it automates:

- **Shodan enumeration** of SSL hosts 🕵️‍♂️  
- **Liveness & redirect checks** (ignores bad certs) 🔄  
- **Automated Ghauri tests** for each host 🛡️  
- **SQLite logging** of every scan 🔖  

---

## 🌟 Features

- 📡 **Shodan Dork**: `hostname:"*.example.com" -403 -503 -http.title:"Invalid URL" -302 -404`  
- 🖧 **Reverse DNS**: IP→hostname, skips `amazonaws` NAT addresses  
- 🔀 **Redirect Handling**: Follows HTTP↔HTTPS transparently  
- 🔐 **TLS Flexibility**: Ignores expired/self‑signed certs  
- 🛠️ **Ghauri Integration**: `--batch`, `--confirm`, `--force-ssl`, `--level=3`, `--dbs`, `--dump`  
- 📊 **History**: Logs into `barcha_history.db`  

---

## 📋 Requirements

- Go **1.18+**  
- [Ghauri](https://github.com/r0oth3x49/ghauri) on your `PATH`  
- Shodan API key in `SHODAN_API_KEY`  

---

## ⚡ Installation

### From Source

```bash
git clone https://github.com/youruser/barcha.git
cd barcha
go mod tidy
go build -o barcha main.go
