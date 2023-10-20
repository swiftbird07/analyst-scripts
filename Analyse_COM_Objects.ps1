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
    "Microsoft Windows"
    "Another Trusted Signerp0" # Add more trusted signers as needed
)

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
    $signedBy = $signedByFull -replace '.*O=([^,]+).*','$1'
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
            return
        } elseif ($isTrusted) {
            Write-Output "Executable: $filename"
            Write-Host "Signed Status: Signed by" -NoNewline; Write-Host " $signedBy " -NoNewline -ForegroundColor Blue; Write-Output "- Verified"
        } else {
            Write-Output "Executable: $filename"
            Write-Host "Signed Status: Signed by" -NoNewline; Write-Host " $signedBy " -NoNewline -ForegroundColor Green; Write-Output "- Verified"
        }
    } elseif ($signature.Status -eq 'UnknownError') {
        Write-Output "Executable: $filename"
        Write-Host "Signed Status: UNSIGNED" -ForegroundColor Red
    } else {
        Write-Output "Executable: $filename"
        Write-Host "Signed Status: Signed by" -NoNewline; Write-Host " $signedBy " -NoNewline -ForegroundColor Orange; Write-Output "- SIGNATURE FAILED"
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
