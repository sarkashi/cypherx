#!/usr/bin/env python3

import platform

VERSION        = "1.0.0"
PROJECT        = "CypherX"
GITHUB         = "github.com/sarkashi/cypherx"
LICENSE        = "MIT"
OS             = platform.system()
IS_WINDOWS     = OS == "Windows"
IS_LINUX       = OS == "Linux"

DEFAULT_LIMIT    = 50
DEFAULT_THREADS  = 30
DEFAULT_TIMEOUT  = 10
DEFAULT_PORTS    = "1-1024"

RESULTS_DIR    = "results"
REPORTS_DIR    = "reports"
LOGS_DIR       = "logs"
WORDLISTS_DIR  = "wordlists"

VERSION_URL    = "https://raw.githubusercontent.com/sarkashi/cypherx/main/version.txt"
