# 🦉 ODedupe

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux-0a0c10?style=flat-square"/>
  <img src="https://img.shields.io/badge/Category-Core%20/%20Utilities-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/Part%20of-OwlSec%20Toolkit-7b5ea7?style=flat-square"/>
  <img src="https://img.shields.io/badge/Version-1.0-cyan?style=flat-square"/>
</p>

> **ODedupe** — Duplicate File Hunter ║

---

> ⚠️ **AUTHORISED USE ONLY** — Use only on systems you own or have explicit written permission to test. Unauthorised use is illegal.

---

## 📌 Overview

ODedupe is a professional, offline-first Duplicate File Hunter with an interactive cyan owl TUI and a full CLI (flag-based) supporting txt|md|json|csv|sarif exports, MITRE ATT&CK tagging on findings where meaningful, and A+..F posture grading.

---

## ✨ Features

- Find duplicate files by content hash with configurable algorithms and workers
- Filter by size, extension, name, hidden files and exclude globs
- Fuzzy near-duplicate matching with adjustable threshold
- Keeper strategies (oldest/newest/shortest path) plus hardlink/move/delete plans
- Extension and directory stats, empty-file and largest-file reports
- Baseline/manifest compare and group export as JSON or CSV

---

## ⚙️ Requirements

- **Linux**
- **Go 1.21+** (stdlib only; `CGO_ENABLED=0`)

---

## 🚀 Usage

```bash
go build -ldflags="-s -w" -o ODedupe ODedupe.go
./ODedupe --help
./ODedupe --path /data --algo sha256 --workers 4
./ODedupe --path /data --min-size 1K --ext-stats
./ODedupe --path /data --fuzzy --fuzzy-threshold 90
```

---

## 📦 Part of OwlSec Toolkit

This tool is part of the **OwlSec** suite — a collection of 300+ security and privacy tools.

🔗 [owlsec.org](https://owlsec.org)

---

## ©️ License

MIT License — © Khaled S. Haddad
