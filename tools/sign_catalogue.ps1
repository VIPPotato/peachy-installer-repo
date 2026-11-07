# Windows PowerShell 5.1; private BCRYPT_ECCPRIVATE_BLOB material stays in memory.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateSet('Sign', 'Verify')][string]$Action,
    [Parameter(Mandatory = $true)][string]$Root,
    [Parameter(Mandatory = $true)][string]$Policy,
    [switch]$Historical
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# Native stdin must be BOM-free even if the invoking host chooses UTF-8 with BOM.
$OutputEncoding = [Text.UTF8Encoding]::new($false)
$privateBytes = $null
$secret = $null
$privateKey = $null
$signer = $null
$sha256 = $null
$stage = 'initialization'

function Hex([byte[]]$Bytes) {
    return ([BitConverter]::ToString($Bytes)).Replace('-', '').ToLowerInvariant()
}

function Unhex([string]$Value) {
    if ($Value -cnotmatch '\A(?:[0-9a-f]{2})+\z') { throw 'Invalid public encoding' }
    [byte[]]$bytes = New-Object byte[] ($Value.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = [Convert]::ToByte($Value.Substring(2 * $i, 2), 16)
    }
    return ,$bytes
}

function Get-Inspection {
    $arguments = @($script:producer, 'inspect', '--snapshot', $Root, '--policy', $Policy)
    if ($Historical) { $arguments += '--historical' }
    $text = & $script:python @arguments 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'Full bundle/policy validation refused' }
    return ($text -join "`n" | ConvertFrom-Json)
}

function Digest($Information, [string]$KeyId) {
    [byte[]]$index = [Convert]::FromBase64String($Information.indexBase64)
    [byte[]]$prefix = [Text.Encoding]::ASCII.GetBytes("PeachyInstaller.Catalogue.v1`0ecdsa-p256-sha256-p1363`0" + $KeyId + "`0")
    [byte[]]$message = New-Object byte[] ($prefix.Length + $index.Length)
    [Array]::Copy($prefix, 0, $message, 0, $prefix.Length)
    [Array]::Copy($index, 0, $message, $prefix.Length, $index.Length)
    return ,$script:sha256.ComputeHash($message)
}

function Assert-PublicSignature($Information, $Envelope) {
    if ($Envelope.schemaVersion -ne 1 -or $Envelope.algorithm -cne 'ecdsa-p256-sha256-p1363') {
        throw 'Unsupported signature'
    }
    $matches = @($Information.keys | Where-Object { $_.keyId -ceq $Envelope.keyId })
    if ($matches.Count -ne 1) { throw 'Signature key is not eligible' }
    [byte[]]$point = Unhex $matches[0].publicPoint
    [byte[]]$blob = New-Object byte[] 72
    # BCRYPT_ECDSA_PUBLIC_P256_MAGIC, cbKey=32, followed by public X || Y only.
    [Array]::Copy([BitConverter]::GetBytes([uint32]0x31534345), 0, $blob, 0, 4)
    [Array]::Copy([BitConverter]::GetBytes([uint32]32), 0, $blob, 4, 4)
    [Array]::Copy($point, 0, $blob, 8, 64)
    $key = $null
    $verifier = $null
    try {
        $key = [Security.Cryptography.CngKey]::Import($blob, [Security.Cryptography.CngKeyBlobFormat]::EccPublicBlob)
        $verifier = [Security.Cryptography.ECDsaCng]::new($key)
        [byte[]]$signature = Unhex $Envelope.signature
        if ($verifier.KeySize -ne 256 -or $signature.Length -ne 64 -or
            -not $verifier.VerifyHash((Digest $Information $Envelope.keyId), $signature)) {
            throw 'Public-only P1363 verification refused'
        }
    } finally {
        if ($null -ne $verifier) { $verifier.Dispose() }
        if ($null -ne $key) { $key.Dispose() }
    }
}

try {
    # Remove the secret before launching ANY subprocess. It is never a CLI
    # argument, temporary file, JSON value or Python/Git environment variable.
    if ($Action -ceq 'Sign') {
        $secret = [Environment]::GetEnvironmentVariable('PEACHY_CATALOGUE_SIGNING_KEY', 'Process')
        # Windows PowerShell's redirected stdin writer can add a UTF-8 BOM and
        # one line ending. Remove only that framing, not arbitrary whitespace.
        if (-not [string]::IsNullOrEmpty($secret)) {
            if ($secret.StartsWith([string][char]0xfeff, [StringComparison]::Ordinal)) { $secret = $secret.Substring(1) }
            if ($secret.EndsWith("`r`n", [StringComparison]::Ordinal)) { $secret = $secret.Substring(0, $secret.Length - 2) }
            elseif ($secret.EndsWith("`n", [StringComparison]::Ordinal)) { $secret = $secret.Substring(0, $secret.Length - 1) }
        }
    }
    [Environment]::SetEnvironmentVariable('PEACHY_CATALOGUE_SIGNING_KEY', $null, 'Process')
    if ($Historical -and $Action -cne 'Verify') { throw 'Historical signing is forbidden' }
    $script:python = (Get-Command python -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
    $script:producer = Join-Path $PSScriptRoot 'publish_catalogue.py'
    $script:sha256 = [Security.Cryptography.SHA256]::Create()
    $stage = 'bundle-policy-validation'
    $information = Get-Inspection
    if ($Action -ceq 'Sign') {
        $stage = 'candidate-signature-precondition'
        if ($null -ne $information.PSObject.Properties['envelope']) { throw 'Existing signature refused' }
        $stage = 'private-key-encoding'
        if ([string]::IsNullOrEmpty($secret) -or $secret.Length -ne 140 -or
            $secret -cnotmatch '\A[A-Za-z0-9+/]{139}=\z') { throw 'Invalid private blob encoding' }
        $privateBytes = [Convert]::FromBase64String($secret)
        $secret = $null
        $stage = 'private-key-blob-layout'
        if ($privateBytes.Length -ne 104 -or [BitConverter]::ToUInt32($privateBytes, 0) -ne 0x32534345 -or
            [BitConverter]::ToUInt32($privateBytes, 4) -ne 32) { throw 'Invalid private blob layout' }
        [byte[]]$point = New-Object byte[] 64
        [Array]::Copy($privateBytes, 8, $point, 0, 64)
        $stage = 'private-key-public-identity'
        $keyId = Hex ($script:sha256.ComputeHash($point))
        $pointHex = Hex $point
        $matches = @($information.keys | Where-Object { $_.keyId -ceq $keyId -and $_.publicPoint -ceq $pointHex })
        if ($matches.Count -ne 1) { throw 'Private/public policy identity mismatch' }
        $stage = 'private-key-import'
        $privateKey = [Security.Cryptography.CngKey]::Import($privateBytes, [Security.Cryptography.CngKeyBlobFormat]::EccPrivateBlob)
        [Array]::Clear($privateBytes, 0, $privateBytes.Length)
        $privateBytes = $null
        $signer = [Security.Cryptography.ECDsaCng]::new($privateKey)
        if ($signer.KeySize -ne 256) { throw 'Invalid curve' }
        # Export PUBLIC material only to check the imported CNG identity.
        [byte[]]$importedPublic = $privateKey.Export([Security.Cryptography.CngKeyBlobFormat]::EccPublicBlob)
        if ($importedPublic.Length -ne 72 -or (Hex $importedPublic[8..71]) -cne $pointHex) {
            throw 'Imported key identity mismatch'
        }
        $stage = 'native-signature'
        [byte[]]$signature = $signer.SignHash((Digest $information $keyId))
        if ($signature.Length -ne 64) { throw 'Provider did not produce IEEE P1363' }
        $envelope = [ordered]@{schemaVersion = 1; algorithm = 'ecdsa-p256-sha256-p1363'; keyId = $keyId; signature = (Hex $signature)}
        Assert-PublicSignature $information ([pscustomobject]$envelope)
        $json = $envelope | ConvertTo-Json -Compress
        $stage = 'signature-publication'
        $stored = $json | & $script:python $script:producer store-signature --snapshot $Root --policy $Policy `
            --expected-bundle $information.bundleSha256 --expected-policy $information.policySha256 2>$null
        if ($LASTEXITCODE -ne 0) { throw 'Signature storage/readback refused' }
        $stage = 'signature-readback'
        $after = Get-Inspection
        if ($after.bundleSha256 -cne $information.bundleSha256 -or $after.policySha256 -cne $information.policySha256 -or
            $after.envelope.keyId -cne $keyId -or $after.envelope.signature -cne $envelope.signature) {
            throw 'Signed snapshot changed during readback'
        }
        Assert-PublicSignature $after $after.envelope
    } else {
        $stage = 'public-verification'
        if ($null -eq $information.PSObject.Properties['envelope']) { throw 'Missing signature' }
        Assert-PublicSignature $information $information.envelope
    }
    $proofInformation = $information
    if ($Action -ceq 'Sign') { $proofInformation = $after }
    $proof = [ordered]@{signatureVerified = $true; algorithm = 'ecdsa-p256-sha256-p1363';
        keyId = $proofInformation.envelope.keyId; indexSha256 = $proofInformation.indexSha256;
        bundleSha256 = $proofInformation.bundleSha256; policySha256 = $proofInformation.policySha256;
        signatureSha256 = $proofInformation.signatureSha256}
    [Console]::Out.WriteLine(($proof | ConvertTo-Json -Compress))
} catch {
    # Do not format exceptions/InvocationInfo: malformed private data must never
    # reach PowerShell error records, transcripts, process logs or CI output.
    [Console]::Error.WriteLine('Catalogue signing/verification refused. Stage: ' + $stage)
    exit 1
} finally {
    $secret = $null
    [Environment]::SetEnvironmentVariable('PEACHY_CATALOGUE_SIGNING_KEY', $null, 'Process')
    if ($null -ne $privateBytes) { [Array]::Clear($privateBytes, 0, $privateBytes.Length) }
    if ($null -ne $signer) { $signer.Dispose() }
    if ($null -ne $privateKey) { $privateKey.Dispose() }
    if ($null -ne $script:sha256) { $script:sha256.Dispose() }
}
