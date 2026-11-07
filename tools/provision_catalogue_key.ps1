param([switch]$CheckOnly)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repository = 'VIPPotato/peachy-installer-repo'
$secret = 'PEACHY_CATALOGUE_SIGNING_KEY'
$root = Split-Path -Parent $PSScriptRoot
$policyPath = Join-Path $root 'catalogue-signing-policy.json'

# This is an explicit one-time provisioning command, never part of a build.
if (-not $CheckOnly) {
    if (Test-Path -LiteralPath $policyPath) { throw 'A public policy already exists; automatic key replacement is refused.' }
    $ancestor = [IO.DirectoryInfo]$root
    while ($null -ne $ancestor) {
        if ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Redirected policy directory refused.' }
        $ancestor = $ancestor.Parent
    }
    $listing = & gh api --method GET ('repos/' + $repository + '/actions/secrets?per_page=100')
    if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect signing-secret metadata; no key was generated.' }
    $metadata = $listing | ConvertFrom-Json
    if ($metadata.total_count -gt 100 -or @($metadata.secrets | Where-Object { $_.name -ceq $secret }).Count -ne 0) {
        throw 'Existing or incompletely enumerated secrets; automatic replacement refused.'
    }
}
$signer = $null; $verifier = $null; $publicKey = $null; $sha = $null; $private = $null
try {
    $signer = New-Object Security.Cryptography.ECDsaCng 256
    $public = $signer.Key.Export([Security.Cryptography.CngKeyBlobFormat]::EccPublicBlob)
    if ($public.Length -ne 72 -or [BitConverter]::ToUInt32($public,0) -ne 0x31534345 -or [BitConverter]::ToUInt32($public,4) -ne 32) { throw 'Unexpected CNG P-256 public-key format.' }
    $point = New-Object byte[] 64
    [Array]::Copy($public,8,$point,0,64)
    $sha = [Security.Cryptography.SHA256]::Create()
    $id = -join ($sha.ComputeHash($point) | ForEach-Object { $_.ToString('x2') })
    $publicKey = [Security.Cryptography.CngKey]::Import($public,[Security.Cryptography.CngKeyBlobFormat]::EccPublicBlob)
    $verifier = New-Object Security.Cryptography.ECDsaCng $publicKey
    $challenge = $sha.ComputeHash([Text.Encoding]::ASCII.GetBytes('Peachy catalogue provisioning self-test'))
    $signature = $signer.SignHash($challenge)
    if ($signature.Length -ne 64 -or -not $verifier.VerifyHash($challenge,$signature)) { throw 'CNG P1363 public-only verification failed.' }
    $now = [DateTime]::UtcNow
    $format = 'yyyy-MM-ddTHH:mm:ssZ'
    $from = $now.ToString($format,[Globalization.CultureInfo]::InvariantCulture)
    $policy = [ordered]@{
        schemaVersion = 1
        algorithm = 'ecdsa-p256-sha256-p1363'
        minimumRevision = 4
        minimumGeneratedAt = $from
        keys = @([ordered]@{
            keyId = $id
            publicPoint = (-join ($point | ForEach-Object { $_.ToString('x2') }))
            validFrom = $from
            validUntil = $now.AddYears(2).ToString($format,[Globalization.CultureInfo]::InvariantCulture)
            revoked = $false
        })
    }
    if ($CheckOnly) {
        [ordered]@{ check = 'ephemeral CNG key and public-only P1363 verification'; keyId = $id; privateSaved = $false } | ConvertTo-Json
        return
    }
    # Write only the public policy. A partial provisioning refuses a silent retry.
    $bytes = (New-Object Text.UTF8Encoding $false).GetBytes(($policy | ConvertTo-Json -Depth 6) + "`n")
    $file = [IO.File]::Open($policyPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $file.Write($bytes,0,$bytes.Length); $file.Flush($true) } finally { $file.Dispose() }
    $private = $signer.Key.Export([Security.Cryptography.CngKeyBlobFormat]::EccPrivateBlob)
    if ($private.Length -ne 104 -or [BitConverter]::ToUInt32($private,0) -ne 0x32534345 -or [BitConverter]::ToUInt32($private,4) -ne 32) { throw 'Unexpected CNG private-key format; no secret uploaded.' }
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = (Get-Command gh -ErrorAction Stop).Source
    $info.Arguments = 'secret set ' + $secret + ' --repo ' + $repository
    $info.WorkingDirectory = $root
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardInput = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $info
    try {
        if (-not $process.Start()) { throw 'Signing-secret upload did not start.' }
        $process.StandardInput.Write([Convert]::ToBase64String($private))
        $process.StandardInput.Close()
        $null = $process.StandardOutput.ReadToEnd()
        $null = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        if ($process.ExitCode -ne 0) { throw 'Signing-secret upload failed; retained public policy requires reviewed recovery. No private key was saved locally.' }
    } finally { $process.Dispose() }
    $readback = & gh api --method GET ('repos/' + $repository + '/actions/secrets/' + $secret) --jq '{name,created_at,updated_at}'
    if ($LASTEXITCODE -ne 0) { throw 'Secret upload returned success but metadata readback failed; do not regenerate the key.' }
    $verified = $readback | ConvertFrom-Json
    if ($verified.name -cne $secret) { throw 'Signing-secret metadata target differs.' }
    [ordered]@{ keyId = $id; publicPolicy = $policyPath; secret = $verified; privateSavedLocally = $false; valueBinding = 'Must be confirmed by the first production CI signature.' } | ConvertTo-Json -Depth 5
} finally {
    if ($null -ne $private) { [Array]::Clear($private,0,$private.Length) }
    if ($null -ne $verifier) { $verifier.Dispose() }
    if ($null -ne $publicKey) { $publicKey.Dispose() }
    if ($null -ne $signer) { $signer.Dispose() }
    if ($null -ne $sha) { $sha.Dispose() }
}
