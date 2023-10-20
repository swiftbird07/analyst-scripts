# check_signature.ps1
# This script checks the signature of given files or directories containing executables
# Author: @ma0f97
# Version: 1.0
# Arguments: 
#   -file: Specify a specific file or directory path to check (e.g. "C:\Windows\System32\notepad.exe" or "C:\Windows\System32")
#   -hideTrusted: Hide files signed by trusted signers defined in the script (e.g. Microsoft)
#   -verboseMode: Print verbose output

param(
    [Parameter(Mandatory=$true)]
    [string]$file,

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

# Lists to store unique signers, unsigned files, and failed signatures
$script:uniqueSigners = @{}
$script:unsignedFiles = @()
$script:failedSignatureFiles = @()

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
    $fullPath = Resolve-Path $binaryPath
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
            # Add to unique signers list
            if ($isTrusted) {
                $script:uniqueSigners[$signedBy] = "Trusted"
            } else {
                $script:uniqueSigners[$signedBy] = "Untrusted"
            }

            $script:trustedCount++
            Write-Output "Executable: $filename"
            Write-Host "Signed Status: Signed by" -NoNewline; Write-Host " $signedBy " -NoNewline -ForegroundColor Blue; Write-Output "- Verified"
        } else {
            # Add to unique signers list
            if ($isTrusted) {
                $script:uniqueSigners[$signedBy] = "Trusted"
            } else {
                $script:uniqueSigners[$signedBy] = "Untrusted"
            }

            $script:untrustedCount++
            Write-Output "Executable: $filename"
            Write-Host "Signed Status: Signed by" -NoNewline; Write-Host " $signedBy " -NoNewline -ForegroundColor Green; Write-Output "- Verified"
        }
    } elseif ($signedBy -eq "") {
        # Add to unsigned files list
        $script:unsignedFiles += $fullPath

        $script:unsignedCount++
        Write-Output "Executable: $filename"
        Write-Host "Signed Status: " -NoNewline; Write-Host "UNSIGNED" -ForegroundColor DarkYellow
    } else {
        # Add to failed signature files list
        $script:failedSignatureFiles += $fullPath

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


if (Test-Path $file -PathType Leaf) {
    # Single file provided
    CheckSignature -binaryPath $file -hide:$hideTrusted -verboseSwitch:$verboseMode
} elseif (Test-Path $file -PathType Container) {
    Write-Output "Checking signatures for all executables in $file and subdirectories (this may take a while)..."
    # Directory provided
    $executables = Get-ChildItem -Path $file -Recurse -Include *.exe,*.dll | Where-Object { -not $_.PSIsContainer }
    if ($verboseMode) {
        Write-Output "Found $($executables.Count) executables in $file"
    }

    foreach ($executable in $executables) {
        CheckSignature -binaryPath $executable.FullName -hide:$hideTrusted -verboseSwitch:$verboseMode
    }
} else {
    Write-Output "The provided path is neither a valid file nor a directory."
    exit
}

# Display summary at the end
Write-Output "SUMMARY:"
Write-Host "Trusted Signatures: $trustedCount" -ForegroundColor Blue
Write-Host "Signed but Untrusted: $untrustedCount" -ForegroundColor Green
Write-Host "Unsigned: $unsignedCount" -ForegroundColor DarkYellow
Write-Host "Failed Signatures: $failedSignatureCount" -ForegroundColor Red
Write-Output "----------------------------------------"
Write-Output "Unique Signers:"
foreach ($signer in $script:uniqueSigners.Keys) {
    $color = if ($script:uniqueSigners[$signer] -eq "Trusted") { "Blue" } else { "Green" }
    Write-Host "   $signer" -ForegroundColor $color
}
Write-Output "----------------------------------------"
Write-Output "Unsigned Files:"
$script:unsignedFiles | ForEach-Object {
    Write-Output "   $_"
}
Write-Output "----------------------------------------"
Write-Output "Files with Failed Signatures:"
$script:failedSignatureFiles | ForEach-Object {
    Write-Output "   $_"
}
