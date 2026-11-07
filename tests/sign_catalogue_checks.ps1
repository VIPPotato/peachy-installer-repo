# Only owned metadata fixtures and ephemeral in-memory test keys are used.
param([Parameter(Mandatory = $true)][string]$TestRoot, [Parameter(Mandatory = $true)][string]$Signer)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$key = $null
$ecdsa = $null
$otherKey = $null
$other = $null
$privateBytes = $null
$script:privateEncoding = $null
$script:otherEncoding = $null
$hash = [Security.Cryptography.SHA256]::Create()
$utf8 = [Text.UTF8Encoding]::new($false)
$passed = [Collections.Generic.List[string]]::new()
$script:snapshot = Join-Path $TestRoot 'snapshot'
$script:policy = Join-Path $TestRoot 'policy.json'
$signaturePath = Join-Path $script:snapshot 'catalog.signature.json'
$indexPath = Join-Path $script:snapshot 'catalog.json'
$markerPath = Join-Path $script:snapshot '.peachy-generated.json'

function Hex([byte[]]$Value) { return ([BitConverter]::ToString($Value)).Replace('-', '').ToLowerInvariant() }
function WriteJson([string]$Path, $Value) { [IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 50) + "`n", $script:utf8) }
function Require([bool]$Condition, [string]$Label) { if (-not $Condition) { throw ('Check failed: ' + $Label) } }
function RunSigner([string]$Action, [bool]$Success, [string]$Label, [bool]$Historical = $false, [string]$Root = '') {
    if ($Root -eq '') { $Root = $script:snapshot }
    $psi = [Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = 'powershell.exe'
    $psi.Arguments = '-NoProfile -NonInteractive -File "' + $Signer + '" -Action ' + $Action +
        ' -Root "' + $Root + '" -Policy "' + $script:policy + '"'
    if ($Historical) { $psi.Arguments += ' -Historical' }
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $process = [Diagnostics.Process]::Start($psi)
    try {
        $output = $process.StandardOutput.ReadToEnd()
        $errors = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        # Never return raw child diagnostics (even if a broken signer prints key material).
        if (($null -ne $script:privateEncoding -and ($output + $errors).Contains($script:privateEncoding)) -or
            ($null -ne $script:otherEncoding -and ($output + $errors).Contains($script:otherEncoding))) {
            throw 'Private material appeared in captured child output (suppressed)'
        }
        if ($Success -and $process.ExitCode -ne 0 -and $errors -match 'Stage: ([a-z-]+)') {
            throw ('Check failed: ' + $Label + ' at ' + $Matches[1] + '; stored=' + [IO.File]::Exists((Join-Path $script:snapshot 'catalog.signature.json')))
        }
        Require (($process.ExitCode -eq 0) -eq $Success) $Label
        if ($Success) { Require ($output.Contains('"signatureVerified":true')) $Label }
        else { Require ($errors.Contains('Catalogue signing/verification refused.')) $Label }
        $script:passed.Add($Label)
    } finally { $process.Dispose() }
}
function RebindIndex {
    $marker = [IO.File]::ReadAllText($script:markerPath) | ConvertFrom-Json
    $marker.files.'catalog.json' = Hex ($script:hash.ComputeHash([IO.File]::ReadAllBytes($script:indexPath)))
    WriteJson $script:markerPath $marker
}
function NewEnvelope([byte[]]$Signature) {
    return [ordered]@{schemaVersion = 1; algorithm = 'ecdsa-p256-sha256-p1363'; keyId = $script:keyId; signature = (Hex $Signature)}
}
function IndexDigest([string]$Domain = "PeachyInstaller.Catalogue.v1`0ecdsa-p256-sha256-p1363`0") {
    [byte[]]$prefix = [Text.Encoding]::ASCII.GetBytes($Domain + $script:keyId + "`0")
    [byte[]]$raw = [IO.File]::ReadAllBytes($script:indexPath)
    [byte[]]$message = New-Object byte[] ($prefix.Length + $raw.Length)
    [Array]::Copy($prefix, $message, $prefix.Length)
    [Array]::Copy($raw, 0, $message, $prefix.Length, $raw.Length)
    return ,$script:hash.ComputeHash($message)
}

try {
    $ecdsa = [Security.Cryptography.ECDsaCng]::new(256)
    $other = [Security.Cryptography.ECDsaCng]::new(256)
    $key = $ecdsa.Key
    $otherKey = $other.Key
    Require ($key.IsEphemeral -and $otherKey.IsEphemeral) 'fixture keys must be ephemeral'
    $privateBytes = $key.Export([Security.Cryptography.CngKeyBlobFormat]::EccPrivateBlob)
    $script:privateEncoding = [Convert]::ToBase64String($privateBytes)
    [Array]::Clear($privateBytes, 0, $privateBytes.Length)
    $privateBytes = $otherKey.Export([Security.Cryptography.CngKeyBlobFormat]::EccPrivateBlob)
    $script:otherEncoding = [Convert]::ToBase64String($privateBytes)
    [Array]::Clear($privateBytes, 0, $privateBytes.Length)
    $privateBytes = $null
    [byte[]]$public = $key.Export([Security.Cryptography.CngKeyBlobFormat]::EccPublicBlob)
    [byte[]]$point = $public[8..71]
    $script:keyId = Hex ($hash.ComputeHash($point))
    $now = [DateTime]::UtcNow
    $policyData = [ordered]@{schemaVersion = 1; algorithm = 'ecdsa-p256-sha256-p1363'; minimumRevision = 4;
        minimumGeneratedAt = $now.AddDays(-40).ToString("yyyy-MM-ddTHH:mm:ssZ");
        keys = @([ordered]@{keyId = $script:keyId; publicPoint = (Hex $point);
            validFrom = $now.AddDays(-40).ToString("yyyy-MM-ddTHH:mm:ssZ");
            validUntil = $now.AddDays(45).ToString("yyyy-MM-ddTHH:mm:ssZ"); revoked = $false})}
    WriteJson $script:policy $policyData
    RunSigner 'Verify' $false 'unsigned-refusal'
    $env:PEACHY_CATALOGUE_SIGNING_KEY = 'not-a-private-blob'
    RunSigner 'Sign' $false 'malformed-secret-refusal'
    Require (-not [IO.File]::Exists($signaturePath)) 'malformed secret wrote nothing'
    $env:PEACHY_CATALOGUE_SIGNING_KEY = $script:otherEncoding
    RunSigner 'Sign' $false 'wrong-private-identity-refusal'
    Require (-not [IO.File]::Exists($signaturePath)) 'wrong private key wrote nothing'
    $env:PEACHY_CATALOGUE_SIGNING_KEY = $script:privateEncoding
    $foreign = Join-Path $TestRoot 'foreign.json'
    [IO.File]::WriteAllText($foreign, 'foreign output must survive', $utf8)
    $null = New-Item -ItemType HardLink -Path $signaturePath -Target $foreign
    RunSigner 'Sign' $false 'hardlinked-output-refusal'
    Require ([IO.File]::ReadAllText($foreign) -ceq 'foreign output must survive') 'foreign file preserved'
    Remove-Item -LiteralPath $signaturePath
    $policyData.keys[0].revoked = $true
    WriteJson $script:policy $policyData
    RunSigner 'Sign' $false 'revoked-key-refusal'
    $policyData.keys[0].revoked = $false
    WriteJson $script:policy $policyData
    $env:PEACHY_CATALOGUE_SIGNING_KEY = [string][char]0xfeff + [string][char]0xfeff + $script:privateEncoding
    RunSigner 'Sign' $false 'repeated-terminal-bom-refusal'
    Require (-not [IO.File]::Exists($signaturePath)) 'repeated terminal BOM wrote nothing'
    $env:PEACHY_CATALOGUE_SIGNING_KEY = $script:privateEncoding + "`r`n`r`n"
    RunSigner 'Sign' $false 'repeated-terminal-line-ending-refusal'
    Require (-not [IO.File]::Exists($signaturePath)) 'repeated terminal line ending wrote nothing'
    $env:PEACHY_CATALOGUE_SIGNING_KEY = $script:privateEncoding
    RunSigner 'Sign' $true 'actual-sign-public-readback'
    Remove-Item -LiteralPath $signaturePath
    $env:PEACHY_CATALOGUE_SIGNING_KEY = $script:privateEncoding + "`r`n"
    RunSigner 'Sign' $true 'stdin-terminal-line-ending-accepted'
    Remove-Item -LiteralPath $signaturePath
    $env:PEACHY_CATALOGUE_SIGNING_KEY = [string][char]0xfeff + $script:privateEncoding + "`r`n"
    RunSigner 'Sign' $true 'stdin-bom-and-line-ending-accepted'
    $env:PEACHY_CATALOGUE_SIGNING_KEY = $script:privateEncoding
    [byte[]]$signedEnvelope = [IO.File]::ReadAllBytes($signaturePath)
    $envelope = [IO.File]::ReadAllText($signaturePath) | ConvertFrom-Json
    Require (($envelope.PSObject.Properties.Name | Sort-Object) -join ',' -ceq 'algorithm,keyId,schemaVersion,signature') 'exact envelope fields'
    Require ($envelope.signature -cmatch '\A[0-9a-f]{128}\z') 'P1363 envelope encoding'
    RunSigner 'Sign' $false 'existing-signature-preserved'
    Require ([Convert]::ToBase64String([IO.File]::ReadAllBytes($signaturePath)) -ceq [Convert]::ToBase64String($signedEnvelope)) 'unchanged existing signature'
    [Environment]::SetEnvironmentVariable('PEACHY_CATALOGUE_SIGNING_KEY', $null, 'Process')
    RunSigner 'Verify' $true 'actual-public-only-verify'
    [byte[]]$index = [IO.File]::ReadAllBytes($indexPath)
    [byte[]]$marker = [IO.File]::ReadAllBytes($markerPath)
    [IO.File]::AppendAllText($indexPath, ' ', $utf8)
    RebindIndex
    RunSigner 'Verify' $false 'exact-index-byte-tamper-refusal'
    [IO.File]::WriteAllBytes($indexPath, $index)
    [IO.File]::WriteAllBytes($markerPath, $marker)
    $entryPath = Join-Path $script:snapshot 'entries/frozen-cookies.json'
    [byte[]]$entry = [IO.File]::ReadAllBytes($entryPath)
    [IO.File]::AppendAllText($entryPath, ' ', $utf8)
    RunSigner 'Verify' $false 'member-tamper-refusal'
    [IO.File]::WriteAllBytes($entryPath, $entry)
    WriteJson $signaturePath (NewEnvelope ($ecdsa.SignHash((IndexDigest 'wrong-domain'))))
    RunSigner 'Verify' $false 'domain-separation-refusal'
    WriteJson $signaturePath (NewEnvelope ($other.SignHash((IndexDigest))))
    RunSigner 'Verify' $false 'wrong-public-signature-refusal'
    $envelope | Add-Member -NotePropertyName extra -NotePropertyValue 1
    WriteJson $signaturePath $envelope
    RunSigner 'Verify' $false 'extra-envelope-field-refusal'
    $envelope.PSObject.Properties.Remove('extra')
    $envelope.signature = '00' * 63
    WriteJson $signaturePath $envelope
    RunSigner 'Verify' $false 'non-p1363-refusal'
    [IO.File]::WriteAllBytes($signaturePath, $signedEnvelope)
    $junction = Join-Path $TestRoot 'redirected-snapshot'
    $null = New-Item -ItemType Junction -Path $junction -Target $script:snapshot
    try { RunSigner 'Verify' $false 'junction-root-refusal' $false $junction }
    finally { [IO.Directory]::Delete($junction) }
    $historical = [Text.Encoding]::UTF8.GetString($index) | ConvertFrom-Json
    $historical.generatedAt = $now.AddDays(-20).ToString("yyyy-MM-ddTHH:mm:ssZ")
    $historical.expiresAt = $now.AddDays(-10).ToString("yyyy-MM-ddTHH:mm:ssZ")
    WriteJson $indexPath $historical
    RebindIndex
    WriteJson $signaturePath (NewEnvelope ($ecdsa.SignHash((IndexDigest))))
    RunSigner 'Verify' $true 'historical-original-byte-verify' $true
    RunSigner 'Verify' $false 'expired-candidate-refusal'
    $env:PEACHY_CATALOGUE_SIGNING_KEY = $script:privateEncoding
    RunSigner 'Sign' $false 'historical-signing-refusal' $true
    [IO.File]::WriteAllBytes($indexPath, $index)
    [IO.File]::WriteAllBytes($markerPath, $marker)
    [IO.File]::WriteAllBytes($signaturePath, $signedEnvelope)
    # A second PUBLIC envelope exercises randomized-signature no-op publication
    # after this process destroys its ephemeral private key.
    WriteJson (Join-Path $TestRoot 'resigned-public-envelope.json') (NewEnvelope ($ecdsa.SignHash((IndexDigest))))
    [Console]::Out.WriteLine(([ordered]@{passed = @($passed.ToArray()); algorithm = 'ecdsa-p256-sha256-p1363'; privateKeyStayedInMemory = $true} | ConvertTo-Json -Compress))
} catch {
    [Console]::Error.WriteLine('CNG producer harness refused: ' + $_.Exception.Message)
    exit 1
} finally {
    [Environment]::SetEnvironmentVariable('PEACHY_CATALOGUE_SIGNING_KEY', $null, 'Process')
    $script:privateEncoding = $null
    $script:otherEncoding = $null
    if ($null -ne $privateBytes) { [Array]::Clear($privateBytes, 0, $privateBytes.Length) }
    if ($null -ne $ecdsa) { $ecdsa.Dispose() }
    if ($null -ne $other) { $other.Dispose() }
    if ($null -ne $key) { $key.Dispose() }
    if ($null -ne $otherKey) { $otherKey.Dispose() }
    $hash.Dispose()
}
