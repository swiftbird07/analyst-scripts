# This small script will check the signature of a COM object's binary
# Author: @swiftbird07
# Version: 1.0
# Arguments: 
#   -key: Specify a specific registry key path to check (e.g. "HKEY_USERS\S-1-5-21-277831620-2573412192-714610973-1001_Classes\AppXewfz11nnnd1v7scbs4vmxpc1svxc4r90\Shell\open\command")
#   -allCOMObjects: Check all COM objects on the system (this may take a while)
#   -hideTrusted: Hide COM objects signed by trusted signers defined in the script (e.g. Microsoft)
#   -verboseMode: Print verbose output

param(
    [Parameter(Mandatory=$false)]
    [string]$key = '',

    [Parameter(Mandatory=$false)]
    [switch]$allCOMObjects,

    [Parameter(Mandatory=$false)]
    [switch]$hideTrusted,

    [Parameter(Mandatory=$false)]
    [switch]$verboseMode
)

# Define trusted signers within this array
$trustedSigners = @(
    "Microsoft Corporation",
    "Microsoft Windows",
    "Elasticsearch",
    "Logitech",
    "Magnitude Software",
    "Simba Technologies Inc.",
    "Mozilla Corporation",
    "NVIDIA Corporation",
    "Google Inc.",
    "VMware, Inc.",
    "Malwarebytes Inc.",
    "Stiftelsen Syncthing",
    "Discord Inc.",
    "Valve Corp.",
    "Wireguard LLC",
    "Parsec Cloud",
    "OpenVPN Technologies, Inc.",
    "Malwarebytes Corporation" # Add more trusted signers as needed
)


# Initialize counters for each signature status
$script:trustedCount = 0
$script:untrustedCount = 0
$script:unsignedCount = 0
$script:failedSignatureCount = 0

function CheckSignature {
    param(
        [string]$binaryPath,
        [switch]$hide,
        [switch]$verboseSwitch
    )

    if ($verboseSwitch) {
        Write-Output "Checking signature for: $binaryPath"
    }


    $signature = Get-AuthenticodeSignature -FilePath $binaryPath
    $signedByFull = $signature.SignerCertificate.Subject
    $signedBy = $signedByFull -replace '.*O="?([^,]+).*','$1'
    $filename = Split-Path $binaryPath -Leaf

    if ($verboseSwitch) {
        Write-Output "Full Signature Subject: $signedByFull"
    }

    if ($signature.Status -eq 'Valid') {
        $isTrusted = $false
        foreach ($signer in $trustedSigners) {
            if ($signedBy -like "*$signer*") {
                $isTrusted = $true
                break
            }
        }

        if ($isTrusted -and $hide) {
            $script:trustedCount++
            return
        } elseif ($isTrusted) {
            $script:trustedCount++
            Write-Output "Executable: $filename"
            Write-Host "Signed Status: Signed by" -NoNewline; Write-Host " $signedBy " -NoNewline -ForegroundColor Blue; Write-Output "- Verified"
        } else {
            $script:untrustedCount++
            Write-Output "Executable: $filename"
            Write-Host "Signed Status: Signed by" -NoNewline; Write-Host " $signedBy " -NoNewline -ForegroundColor Green; Write-Output "- Verified"
        }
    } elseif ($signedBy -eq "") {
        $script:unsignedCount++
        Write-Output "Executable: $filename"
        Write-Host "Signed Status: " -NoNewline; Write-Host "UNSIGNED" -ForegroundColor DarkYellow
    } else {
        $script:failedSignatureCount++
        Write-Output "Executable: $filename"
        if ($trustedSigners -contains $signedBy) {
            Write-Host "ALERT: POSSIBLE FAKE SIGNATURE BY A TRUSTED ORGANIZATION!" -ForegroundColor Red
        }
        Write-Host "Signed Status: Signed by" -NoNewline; Write-Host " $signedBy " -NoNewline -ForegroundColor Red; Write-Output "- SIGNATURE FAILED"
    }

    Write-Output ""
    Write-Output ""
}

if ($allCOMObjects) {
    Write-Output "Searching all COM objects (this may take a while)..."

    $allDelegateValues = Get-ChildItem "Registry::HKCR\*\Shell\open\command" -ErrorAction SilentlyContinue | Where-Object { $_.GetValue("DelegateExecute") }
    foreach ($delegateValue in $allDelegateValues) {
        $clsidPath = "Registry::HKCR\CLSID\$($delegateValue.GetValue('DelegateExecute'))\InprocServer32"
        if (Test-Path $clsidPath) {
            if ($verboseMode) {
                Write-Output "Found CLSID: $($delegateValue.GetValue('DelegateExecute')) in $($delegateValue.PSPath)"
            }
            $binary = Get-ItemProperty -Path $clsidPath | Select-Object -ExpandProperty '(Default)'
            CheckSignature -binaryPath $binary -hide:$hideTrusted -verboseSwitch:$verboseMode
        }
    }
} elseif ($key) {
    if ($verboseMode) {
        Write-Output "Scanning specific registry key: $key"
    }

    $delegateValue = Get-ItemProperty -Path "Registry::$key" -ErrorAction SilentlyContinue | Where-Object { $_.DelegateExecute }

    if ($delegateValue) {
        $clsidPath = "Registry::HKCR\CLSID\$($delegateValue.DelegateExecute)\InprocServer32"

        if (Test-Path $clsidPath) {
            $binary = Get-ItemProperty -Path $clsidPath | Select-Object -ExpandProperty '(Default)'
            CheckSignature -binaryPath $binary -hide:$hideTrusted -verboseSwitch:$verboseMode
        } else {
            Write-Output "No matching CLSID found for DelegateExecute value: $($delegateValue.DelegateExecute)"
        }
    } else {
        Write-Output "No DelegateExecute value found in $key"
    }
}
# Display summary at the end
Write-Output ""
Write-Output "Finished scanning."
Write-Output "------------------"
Write-Output "SUMMARY:"
Write-Host "Signed (Trusted): $trustedCount" -ForegroundColor Blue
Write-Host "Signed (Untrusted): $untrustedCount" -ForegroundColor Green
Write-Host "Unsigned: $unsignedCount" -ForegroundColor DarkYellow
Write-Host "Failed Signatures: $failedSignatureCount" -ForegroundColor Red
