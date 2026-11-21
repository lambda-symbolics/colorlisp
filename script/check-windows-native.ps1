# Run after script/bootstrap with an x64 SBCL and clang on PATH.
# SetupPath selects an external locked environment for every probe subprocess.
param([string]$Sbcl = 'sbcl', [string]$SetupPath)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$probe = Join-Path $PSScriptRoot 'probe-native.lisp'
$temporary = Join-Path ([IO.Path]::GetTempPath()) ('colorlisp-native-' + [guid]::NewGuid().ToString('N'))
$oldLibrary = $env:COLORLISP_NATIVE_LIBRARY
$oldCache = $env:XDG_CACHE_HOME
$oldSetup = $env:COLORLISP_TEST_SETUP
if ($PSBoundParameters.ContainsKey('SetupPath')) {
  if ([string]::IsNullOrWhiteSpace($SetupPath) -or
      -not (Test-Path -LiteralPath $SetupPath -PathType Leaf)) {
    throw 'SetupPath must name an existing setup file.'
  }
  $SetupPath = (Resolve-Path -LiteralPath $SetupPath).ProviderPath
}
$checks = 0

function Assert-Native([bool]$Condition, [string]$Message) {
  if (-not $Condition) { throw $Message }
  $script:checks++
}

function Invoke-NativeProbe([string]$Action, [string]$Library = '') {
  $previous = $ErrorActionPreference
  try {
    $ErrorActionPreference = 'Continue'
    $arguments = @('--noinform', '--disable-debugger', '--script', $probe, $Action)
    if ($Library) { $arguments += $Library }
    $output = & $Sbcl @arguments 2>&1
    $status = $LASTEXITCODE
  } finally { $ErrorActionPreference = $previous }
  return [pscustomobject]@{ Status = $status; Output = ($output | Out-String) }
}

try {
  if ($PSBoundParameters.ContainsKey('SetupPath')) { $env:COLORLISP_TEST_SETUP = $SetupPath }
  New-Item -ItemType Directory -Path $temporary | Out-Null
  $result = Invoke-NativeProbe select
  Assert-Native ($result.Status -eq 0) "Initial native selection failed: $($result.Output)"
  $library = ($result.Output.Trim() -split '\r?\n')[-1]
  $selected = Join-Path $temporary 'selected library.so'
  Copy-Item -LiteralPath $library -Destination $selected
  $env:COLORLISP_NATIVE_LIBRARY = $selected
  $env:XDG_CACHE_HOME = Join-Path $temporary 'cache'
  $decoyDirectory = Join-Path $env:XDG_CACHE_HOME 'colorlisp/native/stale'
  New-Item -ItemType Directory -Force -Path $decoyDirectory | Out-Null
  [IO.File]::WriteAllBytes((Join-Path $decoyDirectory 'colorlisp.exp'), [byte[]]@(0x64,0x86,2,0))
  $result = Invoke-NativeProbe select
  Assert-Native ($result.Status -eq 0) "Override selection failed: $($result.Output)"
  Assert-Native ($result.Output.Trim() -eq $selected) 'The selected override was not returned exactly.'
  $result = Invoke-NativeProbe probe $selected
  Assert-Native ($result.Status -eq 0) "Native grammar/API probe failed: $($result.Output)"

  $valid = [IO.File]::ReadAllBytes($selected)
  $pe = [BitConverter]::ToInt32($valid, 0x3c)
  $cases = @(
    @{ Name = 'coff'; Bytes = [byte[]]@(0x64,0x86,2,0) },
    @{ Name = 'truncated'; Bytes = [byte[]]$valid[0..63] },
    @{ Name = 'wrong-machine'; Offset = $pe + 4; Value = 0 },
    @{ Name = 'bad-signature'; Offset = $pe; Value = 0 },
    @{ Name = 'not-dll'; Offset = $pe + 23; Value = ($valid[$pe + 23] -band 0xdf) },
    @{ Name = 'pe32'; Offset = $pe + 25; Value = 1 }
  )
  foreach ($case in $cases) {
    $invalid = Join-Path $temporary ($case.Name + '.dll')
    $bytes = if ($case.ContainsKey('Bytes')) { $case.Bytes } else { $valid.Clone() }
    if ($case.ContainsKey('Offset')) { $bytes[$case.Offset] = $case.Value }
    [IO.File]::WriteAllBytes($invalid, [byte[]]$bytes)
    $result = Invoke-NativeProbe probe $invalid
    Assert-Native ($result.Status -ne 0) "Accepted invalid $($case.Name) library."
    Assert-Native ($result.Output -match 'not a PE image|not an x64 PE32\+ DLL') "The loader was reached for $($case.Name): $($result.Output)"
  }

  $source = Join-Path $temporary 'unrelated.c'
  $unrelated = Join-Path $temporary 'unrelated.dll'
  [IO.File]::WriteAllText($source, '__declspec(dllexport) int unrelated(void) { return 0; }')
  & clang -shared -o $unrelated $source
  if ($LASTEXITCODE -ne 0) { throw 'Could not build the unrelated x64 DLL fixture.' }
  foreach ($action in @('probe', 'warm-probe')) {
    $result = Invoke-NativeProbe $action $unrelated
    Assert-Native ($result.Status -ne 0) "Accepted a DLL without the ColorLisp API ($action)."
    Assert-Native ($result.Output -match 'colorlisp_session_') "The exact-handle API was not checked ($action): $($result.Output)"
  }
  Write-Output "Windows ColorLisp native artifacts: $checks checks passed."
} finally {
  $env:COLORLISP_NATIVE_LIBRARY = $oldLibrary
  $env:XDG_CACHE_HOME = $oldCache
  $env:COLORLISP_TEST_SETUP = $oldSetup
  if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Recurse -Force }
}

exit 0
