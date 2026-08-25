# MideScan v1.0 by Cybermide
# OWASP Top 10 2021 Web Vulnerability Scanner
# Modules Package Initializer

from . import (
    crawler,
    a01_access,
    a02_crypto,
    a03_injection,
    a04_design,
    a05_misconfig,
    a06_components,
    a07_auth,
    a08_integrity,
    a09_logging,
    a10_ssrf
)