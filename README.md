# TLS Certificate Chain Checker

`Invoke-AkamaiSslCheck.ps1` is a PowerShell utility that helps you spot TLS certificate issues before they impact production. It connects to an HTTPS endpoint, captures the certificate chain that the server presents, and reports on trust, completeness, and validity.

## Features

- Connects to a hostname (optionally via a specified IP) using SNI and captures the full certificate chain.
- Identifies the leaf, intermediate, and CA certificates and highlights when intermediates are missing.
- Validates that the chain builds to a trusted root on the local machine.
- Confirms that the leaf certificate is currently valid (not expired or not yet active).
- Emits PASS/FAIL messages with color-coding for quick triage while also returning structured data for automation.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7+
- Network access to the target host/IP and TCP port (defaults to 443)

## Usage

```powershell
# Basic invocation – resolves the hostname and inspects the returned certificate chain
powershell -ExecutionPolicy Bypass -File .\Invoke-AkamaiSslCheck.ps1 -Hostname origin.example.com

# Connect to a specific IP while sending the hostname as the SNI/Host header
powershell -ExecutionPolicy Bypass -File .\Invoke-AkamaiSslCheck.ps1 -Hostname origin.example.com -Ip 203.0.113.10

# Override the default port and timeout
powershell -ExecutionPolicy Bypass -File .\Invoke-AkamaiSslCheck.ps1 -Hostname origin.example.com -Port 8443 -TimeoutSeconds 5

# Capture the summary object for further scripting
$result = powershell -ExecutionPolicy Bypass -File .\Invoke-AkamaiSslCheck.ps1 -Hostname origin.example.com
```

## Sample Output

```
[PASS] Certificate Chain - Server presented 3 certificate(s).
[PASS] Trusted CA - Chain builds to a trusted root certificate.
[PASS] Certificate Validity - Certificate valid for another 121 day(s).

Summary:
Hostname                : example.com
Target                  : example.com:443
Certificate Subject     : CN=*.example.com, O=Internet Corporation for Assigned Names and Numbers, L=Los Angeles, S=California, C=US
Certificate Issuer      : CN=DigiCert Global G3 TLS ECC SHA384 2020 CA1, O=DigiCert Inc, C=US
Not Before              : 1/14/2025 7:00:00 PM
Not After               : 1/15/2026 6:59:59 PM
Days Until Expiration   : 121
Chain Status            : None
Trust Status            : None
CA                      : CN=DigiCert Global Root G3, OU=www.digicert.com, O=DigiCert Inc, C=US
Intermediate            : CN=DigiCert Global G3 TLS ECC SHA384 2020 CA1, O=DigiCert Inc, C=US
Leaf                    : CN=*.example.com, O=Internet Corporation for Assigned Names and Numbers, L=Los Angeles, S=California, C=US
Chain Complete          : True
Trusted                 : True
Expired                 : False
Not Yet Valid           : False
```

## Notes

- The script uses your local trust store when determining whether a chain is trusted. If the required root is missing locally, the trusted status may report `False` even if the certificate is valid elsewhere.
- Revocation checking is disabled to keep the checks fast. Adjust the chain policy in the script if you need online revocation validation.
- Run the script against different IPs or ports to isolate which origin or listener is presenting an incomplete or invalid chain.
