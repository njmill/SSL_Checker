<#
.SYNOPSIS
Tests a remote HTTPS endpoint and reports on the completeness and validity of its TLS certificate chain.

.DESCRIPTION
Establishes a TLS connection to the specified hostname (optionally to a supplied IP address while
sending the hostname as SNI) and inspects the returned certificate chain. The script verifies that
all intermediate certificates are present, that the chain builds to a trusted root, and that the
leaf certificate is currently valid.

.PARAMETER Hostname
The hostname to present in the TLS handshake and to validate.

.PARAMETER Ip
Optional IP address to connect to. Useful when you want to test a specific origin while keeping the
supplied hostname in the TLS SNI extension.

.PARAMETER Port
TLS port to connect to. Defaults to 443.

.PARAMETER TimeoutSeconds
Connection timeout in seconds. Defaults to 15 seconds.

.EXAMPLE
PS> .\Invoke-AkamaiSslCheck.ps1 -Hostname origin.contoso.com

.EXAMPLE
PS> .\Invoke-AkamaiSslCheck.ps1 -Hostname origin.contoso.com -Ip 203.0.113.10
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$Hostname,

    [Parameter()]
    [string]$Ip,

    [Parameter()]
    [int]$Port = 443,

    [Parameter()]
    [ValidateRange(1,300)]
    [int]$TimeoutSeconds = 15
)

function Convert-ChainStatus {
    param(
        [System.Security.Cryptography.X509Certificates.X509ChainStatus[]]$Status
    )

    if (-not $Status) {
        return @()
    }

    $messages = @()
    foreach ($item in $Status) {
        if (-not $item) {
            continue
        }

        $info = $item.StatusInformation
        if ($null -ne $info) {
            $info = $info.Trim()
        }

        if ([string]::IsNullOrWhiteSpace($info)) {
            $messages += $item.Status.ToString()
        }
        else {
            $messages += "{0}: {1}" -f $item.Status, $info
        }
    }

    return $messages
}

function Write-BooleanField {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Label,

        [Parameter(Mandatory=$true)]
        [bool]$Value,

        [bool]$GoodWhenTrue = $true
    )

    Write-Host ("{0}: " -f $Label) -NoNewline
    if ($Value) {
        $color = if ($GoodWhenTrue) { [System.ConsoleColor]::Green } else { [System.ConsoleColor]::Red }
    }
    else {
        $color = if ($GoodWhenTrue) { [System.ConsoleColor]::Red } else { [System.ConsoleColor]::Green }
    }

    Write-Host $Value -ForegroundColor $color
}

$connectTarget = if ([string]::IsNullOrWhiteSpace($Ip)) { $Hostname } else { $Ip }

$script:CapturedCertificate = $null
$script:CapturedChainElements = New-Object System.Collections.Generic.List[System.Security.Cryptography.X509Certificates.X509Certificate2]
$script:CapturedChainStatus = @()
$script:CapturedPolicyErrors = [System.Net.Security.SslPolicyErrors]::None

$validationCallback = {
    param($sender, $certificate, $chain, $sslPolicyErrors)

    if ($certificate) {
        $raw = $certificate.GetRawCertData()
        $script:CapturedCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($raw)
    }

    $script:CapturedChainElements.Clear()
    foreach ($element in $chain.ChainElements) {
        $certCopy = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($element.Certificate.RawData)
        [void]$script:CapturedChainElements.Add($certCopy)
    }

    $script:CapturedChainStatus = $chain.ChainStatus
    $script:CapturedPolicyErrors = $sslPolicyErrors

    return $true
}

$availableProtocolNames = [Enum]::GetNames([System.Security.Authentication.SslProtocols])
$protocolAttempts = @(
    [pscustomobject]@{ Name = 'SystemDefault'; Protocol = $null; UseDefault = $true }
)

if ($availableProtocolNames -contains 'Tls13') {
    $protocolAttempts += [pscustomobject]@{ Name = 'TLS 1.3'; Protocol = [System.Security.Authentication.SslProtocols]::Tls13; UseDefault = $false }
}
$protocolAttempts += [pscustomobject]@{ Name = 'TLS 1.2'; Protocol = [System.Security.Authentication.SslProtocols]::Tls12; UseDefault = $false }

$handshakeSucceeded = $false
$handshakeErrors = @()

foreach ($attempt in $protocolAttempts) {
    $tcpClient = New-Object System.Net.Sockets.TcpClient
    $asyncResult = $tcpClient.BeginConnect($connectTarget, $Port, $null, $null)

    if (-not $asyncResult.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds($TimeoutSeconds))) {
        $tcpClient.Close()
        throw "Connection to $connectTarget`:$Port timed out after $TimeoutSeconds seconds."
    }

    $tcpClient.EndConnect($asyncResult)

    $sslStream = $null
    try {
        $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false, $validationCallback)

        try {
            if ($attempt.UseDefault) {
                $sslStream.AuthenticateAsClient($Hostname)
            }
            else {
                $clientCertificates = New-Object System.Security.Cryptography.X509Certificates.X509CertificateCollection
                $sslStream.AuthenticateAsClient($Hostname, $clientCertificates, $attempt.Protocol, $false)
            }

            $handshakeSucceeded = $true
            break
        }
        catch {
            $detail = $_.Exception.Message
            if ($_.Exception.InnerException -and $_.Exception.InnerException.Message) {
                $detail = "{0} ({1})" -f $detail, $_.Exception.InnerException.Message
            }
            $handshakeErrors += "[{0}] {1}" -f $attempt.Name, $detail
        }
        finally {
            if ($sslStream) {
                $sslStream.Dispose()
            }
        }
    }
    finally {
        $tcpClient.Close()
    }
}

if (-not $handshakeSucceeded) {
    $attemptDetails = if ($handshakeErrors.Count -gt 0) { $handshakeErrors -join '; ' } else { 'No additional error details available.' }
    throw "TLS handshake with $Hostname failed. Attempts: $attemptDetails"
}


if (-not $script:CapturedCertificate) {
    throw "No certificate was presented by $Hostname."
}

$remoteCert = $script:CapturedCertificate
$now = Get-Date
# Ignore time validity for chain/trust evaluation; expiration is reported separately.
$ignoreTimeValidityFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::IgnoreNotTimeValid -bor [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::IgnoreNotTimeNested
$ignoreTimeStatusFlags = [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::NotTimeValid -bor [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::NotTimeNested

# Build chain for completeness using only provided intermediates
$chainForCompleteness = New-Object System.Security.Cryptography.X509Certificates.X509Chain
$chainForCompleteness.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
$chainForCompleteness.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::AllowUnknownCertificateAuthority -bor $ignoreTimeValidityFlags
$chainForCompleteness.ChainPolicy.ExtraStore.Clear()

if ($script:CapturedChainElements.Count -gt 1) {
    for ($i = 1; $i -lt $script:CapturedChainElements.Count; $i++) {
        [void]$chainForCompleteness.ChainPolicy.ExtraStore.Add($script:CapturedChainElements[$i])
    }
}

$chainComplete = $chainForCompleteness.Build($remoteCert)
$rawChainStatus = $chainForCompleteness.ChainStatus
$completenessStatuses = Convert-ChainStatus -Status ($rawChainStatus | Where-Object { ($_.Status -band $ignoreTimeStatusFlags) -eq 0 })
$hasPartialChain = $rawChainStatus | Where-Object { $_.Status -eq [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::PartialChain }
if ($hasPartialChain) {
    $chainComplete = $false
}

# Trusted CA check using local machine trust store
$chainForTrust = New-Object System.Security.Cryptography.X509Certificates.X509Chain
$chainForTrust.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
$chainForTrust.ChainPolicy.VerificationFlags = $ignoreTimeValidityFlags
$trusted = $chainForTrust.Build($remoteCert)
$rawTrustStatus = $chainForTrust.ChainStatus
$trustStatuses = Convert-ChainStatus -Status ($rawTrustStatus | Where-Object { ($_.Status -band $ignoreTimeStatusFlags) -eq 0 })

# Expiration checks
$expired = $remoteCert.NotAfter -lt $now
$notYetValid = $remoteCert.NotBefore -gt $now
$daysUntilExpiration = [math]::Floor(($remoteCert.NotAfter - $now).TotalDays)

$chainSubjects = @()
foreach ($cert in $script:CapturedChainElements) {
    $chainSubjects += $cert.Subject
}

$summary = [pscustomobject]@{
    Hostname = $Hostname
    Target = "{0}:{1}" -f $connectTarget, $Port
    CertificateSubject = $remoteCert.Subject
    CertificateIssuer = $remoteCert.Issuer
    NotBefore = $remoteCert.NotBefore
    NotAfter = $remoteCert.NotAfter
    DaysUntilExpiration = $daysUntilExpiration
    ChainCertificates = $chainSubjects
    ChainComplete = $chainComplete
    ChainStatus = $completenessStatuses
    Trusted = $trusted
    TrustStatus = $trustStatuses
    Expired = $expired
    NotYetValid = $notYetValid
}

$chainDetail = if ($chainComplete) {
    "Server presented {0} certificate(s)." -f $script:CapturedChainElements.Count
} else {
    if ($completenessStatuses.Count -gt 0) {
        "Chain errors: {0}" -f ($completenessStatuses -join '; ')
    }
    else {
        "Chain did not include all required intermediates."
    }
}

$trustDetail = if ($trusted) {
    "Chain builds to a trusted root certificate."
} else {
    if ($trustStatuses.Count -gt 0) {
        "Trust errors: {0}" -f ($trustStatuses -join '; ')
    }
    else {
        "Certificate chain is not trusted."
    }
}

$validityDetail = if ($expired) {
    $days = [math]::Abs([math]::Floor(($remoteCert.NotAfter - $now).TotalDays))
    if ($days -eq 0) {
        "Certificate expired today ({0})." -f $remoteCert.NotAfter
    }
    else {
        "Certificate expired {0} day(s) ago ({1})." -f $days, $remoteCert.NotAfter
    }
} elseif ($notYetValid) {
    "Certificate is not valid until {0}." -f $remoteCert.NotBefore
} else {
    "Certificate valid for another {0} day(s)." -f $daysUntilExpiration
}

$checks = @(
    [pscustomobject]@{ Name = 'Certificate Chain'; Passed = $chainComplete; Details = $chainDetail },
    [pscustomobject]@{ Name = 'Trusted CA'; Passed = $trusted; Details = $trustDetail },
    [pscustomobject]@{ Name = 'Certificate Validity'; Passed = (-not $expired -and -not $notYetValid); Details = $validityDetail }
)

foreach ($check in $checks) {
    $status = if ($check.Passed) { 'PASS' } else { 'FAIL' }
    $message = "[{0}] {1} - {2}" -f $status, $check.Name, $check.Details
    if ($check.Passed) {
        Write-Host $message -ForegroundColor Green
    }
    else {
        Write-Host $message -ForegroundColor Red
    }
}


#Break out $summary into individual print statements for better readability
Write-Host "`nSummary:"
$labelWidth = 24

$textFields = @(
    @{ Label = 'Hostname'; Value = $summary.Hostname },
    @{ Label = 'Target'; Value = $summary.Target },
    @{ Label = 'Certificate Subject'; Value = $summary.CertificateSubject },
    @{ Label = 'Certificate Issuer'; Value = $summary.CertificateIssuer },
    @{ Label = 'Not Before'; Value = $summary.NotBefore },
    @{ Label = 'Not After'; Value = $summary.NotAfter },
    @{ Label = 'Days Until Expiration'; Value = $summary.DaysUntilExpiration },
    @{ Label = 'Chain Status'; Value = $summary.ChainStatus -join '; ' },
    @{ Label = 'Trust Status'; Value = $summary.TrustStatus -join '; ' }
)

foreach ($field in $textFields) {
    $value = if ([string]::IsNullOrWhiteSpace([string]$field.Value)) { 'None' } else { $field.Value }

    if ($field.Label -eq 'Days Until Expiration' -and -not [string]::IsNullOrWhiteSpace([string]$field.Value)) {
        $days = 0
        if ([int]::TryParse([string]$field.Value, [ref]$days)) {
            $color = [System.ConsoleColor]::Green
            if ($days -lt 30) {
                $color = [System.ConsoleColor]::Red
            }
            elseif ($days -le 90) {
                $color = [System.ConsoleColor]::Yellow
            }

            Write-Host ("{0,-$labelWidth}: " -f $field.Label) -NoNewline
            Write-Host $value -ForegroundColor $color
            continue
        }
    }

    Write-Host ("{0,-$labelWidth}: {1}" -f $field.Label, $value)
}
$chainSubjects = @($summary.ChainCertificates)
$leafSubject = if ($chainSubjects.Count -ge 1) { $chainSubjects[0] } else { 'Unknown' }
$caSubject = if ($chainSubjects.Count -ge 1) { $chainSubjects[$chainSubjects.Count - 1] } else { 'Unknown' }
$intermediateSubjects = if ($chainSubjects.Count -gt 2) { $chainSubjects[1..($chainSubjects.Count - 2)] } else { @() }
$intermediateValue = if ($intermediateSubjects.Count -gt 0) { $intermediateSubjects -join ', ' } else { 'None' }

Write-Host ("{0,-$labelWidth}: {1}" -f 'CA', $caSubject)
Write-Host ("{0,-$labelWidth}: {1}" -f 'Intermediate', $intermediateValue)
Write-Host ("{0,-$labelWidth}: {1}" -f 'Leaf', $leafSubject)

Write-BooleanField ('Chain Complete'.PadRight($labelWidth)) $summary.ChainComplete
Write-BooleanField ('Trusted'.PadRight($labelWidth)) $summary.Trusted
Write-BooleanField ('Expired'.PadRight($labelWidth)) $summary.Expired $false
Write-BooleanField ('Not Yet Valid'.PadRight($labelWidth)) $summary.NotYetValid $false









