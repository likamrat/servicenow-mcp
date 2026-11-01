param(
    [Parameter(Mandatory)][string]$BindingPath,
    [Parameter(Mandatory)][string]$BindingSHA256,
    [Parameter(Mandatory)][string]$NodePath,
    [Parameter(Mandatory)][string]$ServerPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$loaded = $null
$module = $null
$userPointer = [IntPtr]::Zero
$passwordPointer = [IntPtr]::Zero
$exitCode = 1
$stage = 'BINDING'
try {
    $bytes = [IO.File]::ReadAllBytes($BindingPath)
    $actual = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
    if ($actual -cne $BindingSHA256) { throw 'SN_BINDING_CHANGED' }
    $binding = [Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json
    $stage = 'IDENTITY'
    if ($binding.provider_getter -cne 'Get-ServiceNowStoredCredential') { throw 'SN_PROVIDER_INTERFACE_UNAVAILABLE' }
    $executableHash = (Get-FileHash -LiteralPath (Get-Process -Id $PID).Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($executableHash -cne $binding.powershell_sha256) { throw 'SN_EXECUTABLE_CHANGED' }
    $providerHash = (Get-FileHash -LiteralPath $binding.provider_module -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($providerHash -cne $binding.provider_sha256) { throw 'SN_PROVIDER_CHANGED' }
    if ($IsWindows) {
        $env:LOCALAPPDATA = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
    }
    $stage = 'IMPORT'
    $module = Import-Module -Name $binding.provider_module -PassThru -Force 3>$null 4>$null 5>$null 6>$null
    if ($module -is [array] -or -not $module.ExportedFunctions.ContainsKey('Get-ServiceNowStoredCredential')) {
        throw 'SN_PROVIDER_INTERFACE_UNAVAILABLE'
    }
    $stage = 'GETTER'
    $getter = $module.ExportedFunctions['Get-ServiceNowStoredCredential']
    $loaded = & $getter 3>$null 4>$null 5>$null 6>$null
    if ($loaded -is [array] -or $loaded.Instance -cne $binding.instance -or
        $loaded.UserNameSecure -isnot [Security.SecureString] -or
        $loaded.PasswordSecure -isnot [Security.SecureString]) {
        throw 'SN_PROVIDER_RESULT_MISMATCH'
    }
    $stage = 'HANDOFF'
    $userPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($loaded.UserNameSecure)
    $passwordPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($loaded.PasswordSecure)
    $env:SERVICENOW_USERNAME = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($userPointer)
    $env:SERVICENOW_PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordPointer)
    $env:SERVICENOW_INSTANCE = $binding.instance
    $env:SERVICENOW_MCP_DATA_DIR = $binding.state_directory
    $stage = 'SERVER'
    & $NodePath $ServerPath
    $exitCode = $LASTEXITCODE
} catch {
    $known = @('SN_BINDING_CHANGED', 'SN_PROVIDER_INTERFACE_UNAVAILABLE', 'SN_EXECUTABLE_CHANGED',
        'SN_PROVIDER_CHANGED', 'SN_PROVIDER_RESULT_MISMATCH')
    $code = if ($_.Exception.Message -cin $known) { $_.Exception.Message } else { "SN_${stage}_FAILED" }
    [Console]::Error.WriteLine("ServiceNow provider startup failed ($code); no credential details emitted.")
} finally {
    foreach ($name in @('SERVICENOW_USERNAME', 'SERVICENOW_PASSWORD', 'SERVICENOW_INSTANCE', 'SERVICENOW_MCP_DATA_DIR')) {
        [Environment]::SetEnvironmentVariable($name, $null, 'Process')
    }
    if ($userPointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($userPointer) }
    if ($passwordPointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPointer) }
    if ($null -ne $loaded) {
        foreach ($field in @('UserNameSecure', 'PasswordSecure')) {
            $property = $loaded.PSObject.Properties[$field]
            if ($null -ne $property -and $property.Value -is [Security.SecureString]) {
                try { $property.Value.Dispose() }
                catch { [Console]::Error.WriteLine('ServiceNow secure-value disposal failed (SN_DISPOSAL_FAILED).'); $exitCode = 1 }
            }
        }
    }
    $loaded = $null
}
exit $exitCode
