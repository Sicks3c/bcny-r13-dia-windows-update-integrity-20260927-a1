$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$work = Join-Path $env:RUNNER_TEMP "bcny-dia-integrity"
$downloads = Join-Path $work "downloads"
$controls = Join-Path $work "controls"
$evidence = Join-Path $env:RUNNER_TEMP "evidence"
New-Item -ItemType Directory -Force -Path $work, $downloads, $controls, $evidence | Out-Null

$installerUrl = "https://drive.usercontent.google.com/download?id=1IMXmTKrUmThM3t7h8ouSVJD2SRYRUQYZ&export=download&confirm=t"
$appInstallerUrl = "https://releases.diabrowser.com/windows/release-candidate/8EE7CF18-AF4C-48AF-94B0-4B9300876DA5/Dia.x64.appinstaller"
$msixUrl = "https://releases.diabrowser.com/windows/release-candidate/8EE7CF18-AF4C-48AF-94B0-4B9300876DA5/0.28.0.380/Dia.x64.msix"
$dependencyUrl = "https://releases.diabrowser.com/windows/dependencies/x64/Microsoft.VCLibs.x64.14.00.Desktop.14.0.33728.0.appx"
$expected = [ordered]@{
  installer = "19b861126f5179326b6b8ad22321311e4410b994a6608e991604d3f5378d3bd5"
  appinstaller = "87a6d8813603400aa01c591f2d77a61df50e1821d946b5c2076ec7e376f94a39"
  msix = "fd92a6dd178222bc687683a2353b540bd13d0ed42ff87b61124a09bd8be09407"
  dependency = "077a3d1a5d0622bd3004dca85f5e192d6e98ec79b83d4aa06766759ea6c09c3d"
}

$installerPath = Join-Path $downloads "DiaInstaller.exe"
$appInstallerPath = Join-Path $downloads "Dia.x64.appinstaller"
$msixPath = Join-Path $downloads "Dia.x64.msix"
$dependencyPath = Join-Path $downloads "Microsoft.VCLibs.x64.appx"
$tests = [Collections.Generic.List[object]]::new()
$result = [ordered]@{
  schema = "bcny-r13-dia-windows-update-integrity-v1"
  target = "TheBrowserCompany.Dia"
  version = "0.28.0.380"
  architecture = "x64"
  source_urls = [ordered]@{ installer=$installerUrl; appinstaller=$appInstallerUrl; msix=$msixUrl; dependency=$dependencyUrl }
  baseline = $null
  artifact_metadata = [ordered]@{}
  blockmap = $null
  cli_and_temp = $null
  tests = $tests
  cleanup = $null
  fatal = $null
}
$failed = $false
$baselineDia = @()
$baselineDependencies = @()
$baselineShortcut = $false
$baselinePackageProfile = $false
$packageInstalledByRun = $false
$listener = $null

function Add-Test([string]$Id, [string]$Approach, [string]$Name, [bool]$Passed, [object]$Observed, [string]$Meaning) {
  $script:tests.Add([ordered]@{ id=$Id; approach=$Approach; name=$Name; passed=$Passed; observed=$Observed; meaning=$Meaning })
}

function Download-Exact([string]$Url, [string]$Path, [string]$ExpectedHash, [string]$Label) {
  & curl.exe --fail --location --silent --show-error --retry 3 --max-time 1200 --user-agent "authorized-security-research/1.0" --output $Path $Url
  if ($LASTEXITCODE -ne 0) { throw "curl failed for $Label with exit $LASTEXITCODE" }
  $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
  if ($hash -ne $ExpectedHash) { throw "hash mismatch for ${Label}: $hash" }
  return [ordered]@{ bytes=(Get-Item -LiteralPath $Path).Length; sha256=$hash; expected_match=$true }
}

function Signature-Summary([string]$Path) {
  $sig = Get-AuthenticodeSignature -LiteralPath $Path
  return [ordered]@{
    status = [string]$sig.Status
    message = $sig.StatusMessage
    subject = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { $null }
    issuer = if ($sig.SignerCertificate) { $sig.SignerCertificate.Issuer } else { $null }
    thumbprint = if ($sig.SignerCertificate) { $sig.SignerCertificate.Thumbprint } else { $null }
  }
}

function Flip-OwnedCopy([string]$Source, [string]$Destination, [long]$Offset) {
  Copy-Item -LiteralPath $Source -Destination $Destination -Force
  $stream = [IO.File]::Open($Destination, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
  try {
    if ($Offset -ge $stream.Length) { throw "flip offset outside file" }
    $stream.Position = $Offset
    $original = $stream.ReadByte()
    if ($original -lt 0) { throw "failed to read flip byte" }
    $stream.Position = $Offset
    $stream.WriteByte([byte]($original -bxor 1))
    $stream.Flush($true)
  }
  finally { $stream.Dispose() }
}

function Test-FullBlockMap([string]$PackagePath) {
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $zip = [IO.Compression.ZipFile]::OpenRead($PackagePath)
  try {
    $entries = @{}
    foreach ($entry in $zip.Entries) { $entries[$entry.FullName] = $entry }
    $blockEntry = $entries["AppxBlockMap.xml"]
    if (-not $blockEntry) { throw "AppxBlockMap.xml absent" }
    $reader = [IO.StreamReader]::new($blockEntry.Open())
    try { [xml]$xml = $reader.ReadToEnd() } finally { $reader.Dispose() }
    $namespace = [Xml.XmlNamespaceManager]::new($xml.NameTable)
    $namespace.AddNamespace("a", "http://schemas.microsoft.com/appx/2010/blockmap")
    $namespace.AddNamespace("b4", "http://schemas.microsoft.com/appx/2021/blockmap")
    $fileCount = 0
    $blockCount = 0
    $fileHashCount = 0
    $errors = [Collections.Generic.List[string]]::new()
    foreach ($fileNode in $xml.SelectNodes("/a:BlockMap/a:File", $namespace)) {
      $fileCount++
      $entryName = $fileNode.GetAttribute("Name").Replace('\', '/')
      $entry = $entries[$entryName]
      if (-not $entry) {
        $encodedEntryName = (($entryName -split '/') | ForEach-Object { [Uri]::EscapeDataString($_) }) -join '/'
        $entry = $entries[$encodedEntryName]
      }
      if (-not $entry) { $errors.Add("missing:$entryName"); continue }
      $stream = $entry.Open()
      $full = [Security.Cryptography.IncrementalHash]::CreateHash([Security.Cryptography.HashAlgorithmName]::SHA256)
      $remaining = [int64]$fileNode.GetAttribute("Size")
      try {
        foreach ($block in $fileNode.SelectNodes("a:Block", $namespace)) {
          $blockCount++
          $wanted = [int][Math]::Min(65536, $remaining)
          if ($wanted -le 0) { $errors.Add("surplus-block:${entryName}:${blockCount}"); break }
          $buffer = New-Object byte[] $wanted
          $offset = 0
          while ($offset -lt $wanted) {
            $n = $stream.Read($buffer, $offset, $wanted - $offset)
            if ($n -le 0) { break }
            $offset += $n
          }
          if ($offset -ne $wanted) { $errors.Add("short:${entryName}:${blockCount}:$offset/$wanted"); break }
          $full.AppendData($buffer, 0, $offset)
          $blockHasher = [Security.Cryptography.SHA256]::Create()
          try { $actual = [Convert]::ToBase64String($blockHasher.ComputeHash($buffer)) } finally { $blockHasher.Dispose() }
          if ($actual -ne $block.Hash) { $errors.Add("block:${entryName}:${blockCount}") }
          $remaining -= $wanted
        }
        if ($remaining -ne 0) { $errors.Add("remaining:${entryName}:$remaining") }
        $extra = $stream.ReadByte()
        if ($extra -ne -1) { $errors.Add("extra:$entryName") }
        $fileHashNode = $fileNode.SelectSingleNode("b4:FileHash", $namespace)
        if ($fileHashNode) {
          $fileHashCount++
          $actualFileHash = [Convert]::ToBase64String($full.GetHashAndReset())
          if ($actualFileHash -ne $fileHashNode.Hash) { $errors.Add("file:$entryName") }
        }
      }
      finally { $full.Dispose(); $stream.Dispose() }
    }
    return [ordered]@{ files=$fileCount; blocks=$blockCount; file_hashes=$fileHashCount; errors=@($errors); passed=($errors.Count -eq 0) }
  }
  finally { $zip.Dispose() }
}

function Test-AddPackageRejected([string]$Path, [string]$Label, [string[]]$DependencyPaths = @()) {
  $before = @(Get-AppxPackage -Name "TheBrowserCompany.Dia" -ErrorAction SilentlyContinue).Count
  $errorRecord = $null
  $accepted = $false
  try {
    if ($DependencyPaths.Count -gt 0) {
      Add-AppxPackage -Path $Path -DependencyPath $DependencyPaths -ForceApplicationShutdown -ErrorAction Stop
    } else {
      Add-AppxPackage -Path $Path -ForceApplicationShutdown -ErrorAction Stop
    }
    $accepted = $true
  }
  catch { $errorRecord = $_ }
  $afterPackages = @(Get-AppxPackage -Name "TheBrowserCompany.Dia" -ErrorAction SilentlyContinue)
  if ($afterPackages.Count -gt $before) {
    foreach ($pkg in $afterPackages) { Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers:$false -ErrorAction SilentlyContinue }
  }
  return [ordered]@{
    label=$Label
    accepted=$accepted
    error_type=if ($errorRecord) { $errorRecord.Exception.GetType().FullName } else { $null }
    hresult=if ($errorRecord) { ('0x{0:X8}' -f ($errorRecord.Exception.HResult -band 0xffffffffL)) } else { $null }
    message=if ($errorRecord) { $errorRecord.Exception.Message } else { $null }
    package_count_after=@(Get-AppxPackage -Name "TheBrowserCompany.Dia" -ErrorAction SilentlyContinue).Count
  }
}

function Test-AppInstallerVariant([string]$Path, [string]$Label) {
  $errorRecord = $null
  $accepted = $false
  try {
    Add-AppxPackage -AppInstallerFile $Path -ForceTargetApplicationShutdown -ErrorAction Stop
    $accepted = $true
  }
  catch { $errorRecord = $_ }
  $packages = @(Get-AppxPackage -Name "TheBrowserCompany.Dia" -ErrorAction SilentlyContinue)
  foreach ($pkg in $packages) { Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers:$false -ErrorAction SilentlyContinue }
  return [ordered]@{
    label=$Label
    accepted=$accepted
    error_type=if ($errorRecord) { $errorRecord.Exception.GetType().FullName } else { $null }
    hresult=if ($errorRecord) { ('0x{0:X8}' -f ($errorRecord.Exception.HResult -band 0xffffffffL)) } else { $null }
    message=if ($errorRecord) { $errorRecord.Exception.Message } else { $null }
    package_count_after=@(Get-AppxPackage -Name "TheBrowserCompany.Dia" -ErrorAction SilentlyContinue).Count
  }
}

try {
  $baselineDia = @(Get-AppxPackage -Name "TheBrowserCompany.Dia" -ErrorAction SilentlyContinue)
  $baselineDependencies = @(Get-AppxPackage -Name "Microsoft.VCLibs.140.00.UWPDesktop" -ErrorAction SilentlyContinue)
  $shortcut = Join-Path ([Environment]::GetFolderPath("Desktop")) "Dia.lnk"
  $baselineShortcut = Test-Path -LiteralPath $shortcut
  $packageProfile = Join-Path $env:LOCALAPPDATA "Packages\TheBrowserCompany.Dia_ttt1ap7aakyb4"
  $baselinePackageProfile = Test-Path -LiteralPath $packageProfile
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = [Security.Principal.WindowsPrincipal]::new($identity)
  $result.baseline = [ordered]@{
    dia_count=$baselineDia.Count
    dependency_full_names=@($baselineDependencies | ForEach-Object { $_.PackageFullName })
    shortcut_existed=$baselineShortcut
    package_profile_existed=$baselinePackageProfile
    user_name=$env:USERNAME
    process_elevated=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    os_build=[Environment]::OSVersion.Version.Build
    temp_leaf=Split-Path $env:TEMP -Leaf
    temp_acl_sddl=(Get-Acl -LiteralPath $env:TEMP).Sddl
  }
  if ($baselineDia.Count -ne 0) { throw "Dia unexpectedly installed at baseline" }

  $result.artifact_metadata.installer = Download-Exact $installerUrl $installerPath $expected.installer "bootstrap"
  $result.artifact_metadata.appinstaller = Download-Exact $appInstallerUrl $appInstallerPath $expected.appinstaller "appinstaller"
  $result.artifact_metadata.msix = Download-Exact $msixUrl $msixPath $expected.msix "msix"
  $result.artifact_metadata.dependency = Download-Exact $dependencyUrl $dependencyPath $expected.dependency "dependency"

  $result.artifact_metadata.installer.signature = Signature-Summary $installerPath
  $result.artifact_metadata.msix.signature = Signature-Summary $msixPath
  $result.artifact_metadata.dependency.signature = Signature-Summary $dependencyPath
  Add-Test "T01" "provenance" "bootstrap exact hash and Windows signature" ($result.artifact_metadata.installer.signature.status -eq "Valid") $result.artifact_metadata.installer "Only the exact Browser Company signed bootstrap is executable."
  Add-Test "T02" "provenance" "AppInstaller exact hash" $result.artifact_metadata.appinstaller.expected_match $result.artifact_metadata.appinstaller "The descriptor is byte-pinned before use."
  Add-Test "T03" "provenance" "MSIX exact hash and Windows signature" ($result.artifact_metadata.msix.signature.status -eq "Valid") $result.artifact_metadata.msix "The package is signed by the expected Browser Company identity."
  Add-Test "T04" "provenance" "dependency exact hash and Windows signature" ($result.artifact_metadata.dependency.signature.status -eq "Valid") $result.artifact_metadata.dependency "The dependency is signed by Microsoft."

  [xml]$appXml = Get-Content -LiteralPath $appInstallerPath -Raw
  $ns = [Xml.XmlNamespaceManager]::new($appXml.NameTable)
  $ns.AddNamespace("a", "http://schemas.microsoft.com/appx/appinstaller/2018")
  $main = $appXml.SelectSingleNode("/a:AppInstaller/a:MainPackage", $ns)
  $dep = $appXml.SelectSingleNode("/a:AppInstaller/a:Dependencies/a:Package", $ns)
  $descriptor = [ordered]@{
    root_uri=$appXml.AppInstaller.Uri
    root_version=$appXml.AppInstaller.Version
    main_name=$main.GetAttribute("Name")
    main_version=$main.GetAttribute("Version")
    main_publisher=$main.GetAttribute("Publisher")
    main_architecture=$main.GetAttribute("ProcessorArchitecture")
    main_uri=$main.GetAttribute("Uri")
    dependency_name=$dep.GetAttribute("Name")
    dependency_version=$dep.GetAttribute("Version")
    dependency_publisher=$dep.GetAttribute("Publisher")
    dependency_architecture=$dep.GetAttribute("ProcessorArchitecture")
    dependency_uri=$dep.GetAttribute("Uri")
  }
  $result.artifact_metadata.descriptor = $descriptor
  $descriptorPass = $descriptor.main_name -eq "TheBrowserCompany.Dia" -and $descriptor.main_version -eq "0.28.0.380" -and $descriptor.main_architecture -eq "x64" -and $descriptor.main_uri -eq $msixUrl -and $descriptor.dependency_uri -eq $dependencyUrl
  Add-Test "T05" "descriptor-binding" "AppInstaller exact name/version/architecture/URI binding" $descriptorPass $descriptor "All declared identities match the exact downloaded artifacts."

  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $zip = [IO.Compression.ZipFile]::OpenRead($msixPath)
  try {
    $manifestEntry = $zip.GetEntry("AppxManifest.xml")
    $manifestReader = [IO.StreamReader]::new($manifestEntry.Open())
    try { [xml]$manifestXml = $manifestReader.ReadToEnd() } finally { $manifestReader.Dispose() }
  }
  finally { $zip.Dispose() }
  $identityNode = $manifestXml.Package.Identity
  $manifestIdentity = [ordered]@{ name=$identityNode.GetAttribute("Name"); publisher=$identityNode.GetAttribute("Publisher"); version=$identityNode.GetAttribute("Version"); architecture=$identityNode.GetAttribute("ProcessorArchitecture") }
  $result.artifact_metadata.manifest_identity = $manifestIdentity
  $manifestPass = $manifestIdentity.name -eq $descriptor.main_name -and $manifestIdentity.publisher -eq $descriptor.main_publisher -and $manifestIdentity.version -eq $descriptor.main_version -and $manifestIdentity.architecture -eq $descriptor.main_architecture
  Add-Test "T06" "descriptor-binding" "AppInstaller to inner manifest identity binding" $manifestPass $manifestIdentity "The signed package identity matches every descriptor field."

  $result.blockmap = Test-FullBlockMap $msixPath
  Add-Test "T07" "blockmap" "full AppxBlockMap verification" $result.blockmap.passed $result.blockmap "Every declared file/block hash was recomputed from package bytes."

  $tamperedBootstrap = Join-Path $controls "DiaInstaller.tampered.exe"
  Flip-OwnedCopy $installerPath $tamperedBootstrap 65536
  $tamperedBootstrapSignature = Signature-Summary $tamperedBootstrap
  Add-Test "T08" "tamper-rejection" "tampered bootstrap fails Windows signature validation" ($tamperedBootstrapSignature.status -ne "Valid") $tamperedBootstrapSignature "The tampered bootstrap was never executed."

  $tamperedMsix = Join-Path $controls "Dia.tampered.msix"
  Flip-OwnedCopy $msixPath $tamperedMsix 1048576
  $tamperedMsixSignature = Signature-Summary $tamperedMsix
  Add-Test "T09" "tamper-rejection" "tampered MSIX fails Windows signature validation" ($tamperedMsixSignature.status -ne "Valid") $tamperedMsixSignature "The modified package loses its valid signature."
  $tamperedMsixInstall = Test-AddPackageRejected $tamperedMsix "tampered_msix" @($dependencyPath)
  Add-Test "T10" "tamper-rejection" "Windows deployment rejects tampered MSIX" (-not $tamperedMsixInstall.accepted -and $tamperedMsixInstall.package_count_after -eq 0) $tamperedMsixInstall "No tampered package was registered or launched."

  $tamperedDependency = Join-Path $controls "VCLibs.tampered.appx"
  Flip-OwnedCopy $dependencyPath $tamperedDependency 131072
  $tamperedDependencySignature = Signature-Summary $tamperedDependency
  Add-Test "T11" "dependency-trust" "tampered dependency fails Windows signature validation" ($tamperedDependencySignature.status -ne "Valid") $tamperedDependencySignature "The modified dependency loses Microsoft's valid signature."
  $dependencyError = $null
  $dependencyAccepted = $false
  try { Add-AppxPackage -Path $tamperedDependency -ForceApplicationShutdown -ErrorAction Stop; $dependencyAccepted = $true } catch { $dependencyError = $_ }
  $dependencyControl = [ordered]@{ accepted=$dependencyAccepted; hresult=if ($dependencyError) { ('0x{0:X8}' -f ($dependencyError.Exception.HResult -band 0xffffffffL)) } else { $null }; message=if ($dependencyError) { $dependencyError.Exception.Message } else { $null } }
  Add-Test "T12" "dependency-trust" "Windows deployment rejects tampered dependency" (-not $dependencyAccepted) $dependencyControl "No tampered dependency was executed."

  $rawAppInstaller = Get-Content -LiteralPath $appInstallerPath -Raw
  $appInstallerPositive = Test-AppInstallerVariant $appInstallerPath "official_unmodified"
  Add-Test "T13" "descriptor-binding" "unmodified official AppInstaller positive control" ($appInstallerPositive.accepted -and $appInstallerPositive.package_count_after -eq 0) $appInstallerPositive "The same Windows AppInstaller code path used by the mismatch controls accepts the official descriptor and leaves no package after controlled removal."

  $versionRegex = [regex]::new('(<MainPackage[\s\S]*?Version=")0\.28\.0\.380(")')
  $architectureRegex = [regex]::new('(<MainPackage[\s\S]*?ProcessorArchitecture=")x64(")')
  $variants = [ordered]@{
    wrong_name = $rawAppInstaller.Replace('Name="TheBrowserCompany.Dia"', 'Name="TheBrowserCompany.DiaWrong"')
    wrong_publisher = $rawAppInstaller.Replace('E=hello@thebrowser.company, CN=THE BROWSER COMPANY OF NEW YORK INC.', 'CN=BCNY-INTEGRITY-NEGATIVE-CONTROL')
    wrong_version = $versionRegex.Replace($rawAppInstaller, '${1}0.27.0.0${2}', 1)
    wrong_architecture = $architectureRegex.Replace($rawAppInstaller, '${1}arm64${2}', 1)
    wrong_dependency_publisher = $rawAppInstaller.Replace('CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US', 'CN=BCNY-INTEGRITY-NEGATIVE-CONTROL')
  }
  $variantIndex = 14
  foreach ($variant in $variants.GetEnumerator()) {
    $variantPath = Join-Path $controls ("{0}.appinstaller" -f $variant.Key)
    [IO.File]::WriteAllText($variantPath, [string]$variant.Value, [Text.UTF8Encoding]::new($false))
    $variantResult = Test-AppInstallerVariant $variantPath $variant.Key
    Add-Test ("T{0:D2}" -f $variantIndex) "descriptor-binding" ("Windows rejects AppInstaller {0} mismatch" -f $variant.Key) ($appInstallerPositive.accepted -and -not $variantResult.accepted -and $variantResult.package_count_after -eq 0) $variantResult "The official control was accepted while this descriptor mutation produced no installed package."
    $variantIndex++
  }

  $peManifestPath = Join-Path $controls "bootstrap.manifest.xml"
  $mtCommand = Get-Command mt.exe -ErrorAction SilentlyContinue
  if (-not $mtCommand) {
    $mtCommand = Get-ChildItem -Path "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\mt.exe" -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1
  }
  if (-not $mtCommand) { throw "mt.exe not found" }
  $inputResourceArg = '-inputresource:"{0}";#1' -f $installerPath
  $outputManifestArg = '-out:"{0}"' -f $peManifestPath
  $mtPath = if ($mtCommand -is [Management.Automation.ApplicationInfo]) { $mtCommand.Source } else { $mtCommand.FullName }
  $peManifest = (& $mtPath $inputResourceArg $outputManifestArg 2>&1 | Out-String)
  $peManifestText = if (Test-Path -LiteralPath $peManifestPath) { Get-Content -LiteralPath $peManifestPath -Raw } else { "" }
  $asInvoker = $peManifestText.Contains('requestedExecutionLevel level="asInvoker"')
  Add-Test "T19" "temp-boundary" "bootstrap requests asInvoker execution" $asInvoker ([ordered]@{ mt_output=$peManifest.Trim(); requested_execution_level=if ($asInvoker) { "asInvoker" } else { "not_observed" } }) "The bootstrap does not create an automatic elevation boundary around user TEMP."

  $reusePath = Join-Path $env:TEMP "TheBrowserCompany.Dia.0.28.0.380.msix"
  if (Test-Path -LiteralPath $reusePath) { Remove-Item -LiteralPath $reusePath -Force }
  & fsutil.exe hardlink create $reusePath $msixPath | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "failed to create owned official hardlink precondition" }
  $preReuseHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $reusePath).Hash.ToLowerInvariant()
  $hardlinksBefore = @(& fsutil.exe hardlink list $msixPath 2>&1)
  Add-Test "T20" "temp-boundary" "owned same-volume hardlink precondition" ($preReuseHash -eq $expected.msix) ([ordered]@{ predictable_leaf=(Split-Path $reusePath -Leaf); hardlinks=$hardlinksBefore; hash=$preReuseHash }) "Only exact official signed bytes were preplanted; no attacker bytes were executed."

  $listenerPort = 38921
  $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $listenerPort)
  $listener.Start()
  $acceptTask = $listener.AcceptTcpClientAsync()
  $arguments = @("--silent", "--console", "--feed", "http://127.0.0.1:$listenerPort/", "--channel", "stable")
  $first = Start-Process -FilePath $installerPath -ArgumentList $arguments -Wait -PassThru
  Start-Sleep -Seconds 2
  $callbackSeen = $acceptTask.IsCompleted
  if ($callbackSeen) { $client = $acceptTask.Result; $client.Dispose() }
  $listener.Stop(); $listener = $null
  $installed = Get-AppxPackage -Name "TheBrowserCompany.Dia" | Sort-Object Version -Descending | Select-Object -First 1
  if (-not $installed) { throw "signed bootstrap did not install Dia" }
  $packageInstalledByRun = $true
  $processCount = @(Get-Process -Name "Dia" -ErrorAction SilentlyContinue).Count
  $postSourceHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $msixPath).Hash.ToLowerInvariant()
  $firstRun = [ordered]@{ exit_code=$first.ExitCode; callback_seen=$callbackSeen; installed_name=$installed.Name; installed_version=[string]$installed.Version; installed_publisher=$installed.Publisher; installed_signature_kind=[string]$installed.SignatureKind; dia_process_count=$processCount; source_msix_hash_after=$postSourceHash; reuse_path_exists_after=(Test-Path -LiteralPath $reusePath) }
  Add-Test "T21" "cli-channel" "unknown feed/channel arguments cannot override fixed RC source" ($first.ExitCode -eq 0 -and -not $callbackSeen -and $installed.Name -eq "TheBrowserCompany.Dia" -and [string]$installed.Version -eq "0.28.0.380") $firstRun "The only recognized runtime options are silent/console; the local override listener saw no connection."
  Add-Test "T22" "temp-boundary" "official hardlink source was not modified" ($postSourceHash -eq $expected.msix) $firstRun "The predictable cache path did not turn owned source bytes into a write primitive."
  Add-Test "T23" "execution" "silent install does not launch Dia" ($processCount -eq 0) $firstRun "The tested installer path registered the trusted package without executing Dia."

  if (Test-Path -LiteralPath $reusePath) { Remove-Item -LiteralPath $reusePath -Force }
  & fsutil.exe hardlink create $reusePath $msixPath | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "failed to recreate official hardlink for same-version update" }
  $second = Start-Process -FilePath $installerPath -ArgumentList @("--silent", "--console") -Wait -PassThru
  $updated = Get-AppxPackage -Name "TheBrowserCompany.Dia" | Sort-Object Version -Descending | Select-Object -First 1
  $secondRun = [ordered]@{ exit_code=$second.ExitCode; installed_full_name=$updated.PackageFullName; installed_version=[string]$updated.Version; source_msix_hash_after=(Get-FileHash -Algorithm SHA256 -LiteralPath $msixPath).Hash.ToLowerInvariant() }
  Add-Test "T24" "update-behavior" "same-version signed update preserves exact package identity" ($second.ExitCode -eq 0 -and [string]$updated.Version -eq "0.28.0.380" -and $secondRun.source_msix_hash_after -eq $expected.msix) $secondRun "Re-entry did not select a different channel, identity, or package."

  $result.cli_and_temp = [ordered]@{
    decompiled_recognized_switches=@("--silent", "--console")
    supplied_unrecognized_switches=@("--feed", "--channel")
    compiled_channel="release-candidate/8EE7CF18-AF4C-48AF-94B0-4B9300876DA5"
    predictable_manual_cache_leaf="TheBrowserCompany.Dia.0.28.0.380.msix"
    first_run=$firstRun
    second_run=$secondRun
  }

  $lowerSignedAvailable = $false
  $downgradeObservation = [ordered]@{ lower_signed_artifact_available=$lowerSignedAvailable; wrong_version_descriptor_test="T16"; current_version=[string]$updated.Version }
  Add-Test "T25" "downgrade" "no downgrade through mismatched descriptor or unsigned package" (-not $lowerSignedAvailable -and [string]$updated.Version -eq "0.28.0.380") $downgradeObservation "A lower official signed package was not supplied; the mismatched-version descriptor was rejected and no unsigned package was run."
}
catch {
  $failed = $true
  $result.fatal = [ordered]@{ type=$_.Exception.GetType().FullName; hresult=('0x{0:X8}' -f ($_.Exception.HResult -band 0xffffffffL)); message=$_.Exception.Message; script_stack=$_.ScriptStackTrace }
}
finally {
  if ($listener) { try { $listener.Stop() } catch {} }
  try {
    foreach ($process in @(Get-Process -Name "Dia" -ErrorAction SilentlyContinue)) { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue }
    foreach ($pkg in @(Get-AppxPackage -Name "TheBrowserCompany.Dia" -ErrorAction SilentlyContinue)) { Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers:$false -ErrorAction Stop }
    Start-Sleep -Seconds 2
    $baselineNames = @($baselineDependencies | ForEach-Object { $_.PackageFullName })
    foreach ($pkg in @(Get-AppxPackage -Name "Microsoft.VCLibs.140.00.UWPDesktop" -ErrorAction SilentlyContinue)) {
      if ($baselineNames -notcontains $pkg.PackageFullName) { Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers:$false -ErrorAction Stop }
    }
    $shortcut = Join-Path ([Environment]::GetFolderPath("Desktop")) "Dia.lnk"
    if (-not $baselineShortcut -and (Test-Path -LiteralPath $shortcut)) { Remove-Item -LiteralPath $shortcut -Force }
    $packageProfile = Join-Path $env:LOCALAPPDATA "Packages\TheBrowserCompany.Dia_ttt1ap7aakyb4"
    if (-not $baselinePackageProfile -and (Test-Path -LiteralPath $packageProfile)) { Remove-Item -LiteralPath $packageProfile -Recurse -Force }
    $reusePath = Join-Path $env:TEMP "TheBrowserCompany.Dia.0.28.0.380.msix"
    if (Test-Path -LiteralPath $reusePath) { Remove-Item -LiteralPath $reusePath -Force }
    $arcLog = Join-Path $env:TEMP ".arcinstall"
    if (Test-Path -LiteralPath $arcLog) { Remove-Item -LiteralPath $arcLog -Force }
    $diaAfter = @(Get-AppxPackage -Name "TheBrowserCompany.Dia" -ErrorAction SilentlyContinue)
    $dependencyAfter = @(Get-AppxPackage -Name "Microsoft.VCLibs.140.00.UWPDesktop" -ErrorAction SilentlyContinue)
    $shortcutAfter = Test-Path -LiteralPath $shortcut
    $tempCopiesAfter = @(Get-ChildItem -LiteralPath $env:TEMP -Directory -Filter "DiaInstall_*" -ErrorAction SilentlyContinue)
    $dependencyNamesAfter = (@($dependencyAfter | ForEach-Object { $_.PackageFullName }) | Sort-Object) -join "|"
    $dependencyNamesBefore = (@($baselineDependencies | ForEach-Object { $_.PackageFullName }) | Sort-Object) -join "|"
    $packageProfileAfter = Test-Path -LiteralPath $packageProfile
    $cleanupPass = $diaAfter.Count -eq $baselineDia.Count -and $dependencyNamesAfter -eq $dependencyNamesBefore -and $shortcutAfter -eq $baselineShortcut -and $packageProfileAfter -eq $baselinePackageProfile -and @(Get-Process -Name "Dia" -ErrorAction SilentlyContinue).Count -eq 0 -and $tempCopiesAfter.Count -eq 0
    $result.cleanup = [ordered]@{ passed=$cleanupPass; dia_count_after=$diaAfter.Count; dependency_full_names_after=@($dependencyAfter | ForEach-Object { $_.PackageFullName }); shortcut_after=$shortcutAfter; package_profile_after=$packageProfileAfter; dia_process_count_after=@(Get-Process -Name "Dia" -ErrorAction SilentlyContinue).Count; relaunch_temp_directory_count_after=$tempCopiesAfter.Count; predictable_cache_exists_after=(Test-Path -LiteralPath $reusePath); arcinstall_log_exists_after=(Test-Path -LiteralPath $arcLog) }
    Add-Test "T26" "cleanup" "package/process/dependency/shortcut/temp cleanup" $cleanupPass $result.cleanup "The ephemeral runner returned to its exact relevant baseline."
    if (-not $cleanupPass) { $failed = $true }
  }
  catch {
    $failed = $true
    $result.cleanup = [ordered]@{ passed=$false; type=$_.Exception.GetType().FullName; message=$_.Exception.Message }
  }
  $testArray = @($tests)
  $result.test_summary = [ordered]@{ total=$testArray.Count; passed=@($testArray | Where-Object { $_.passed }).Count; failed=@($testArray | Where-Object { -not $_.passed }).Count; approaches=@($testArray.approach | Sort-Object -Unique) }
  if ($result.test_summary.failed -ne 0) { $failed = $true }
  $result | ConvertTo-Json -Depth 14 | Set-Content -LiteralPath (Join-Path $evidence "integrity-result.json") -Encoding utf8
  [ordered]@{ schema=$result.schema; summary=$result.test_summary; fatal=$result.fatal; cleanup=$result.cleanup } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $evidence "summary.json") -Encoding utf8
  Get-ChildItem -LiteralPath $evidence -File | ForEach-Object { $_.Attributes = 'Normal' }
}

Write-Host (Get-Content -LiteralPath (Join-Path $evidence "summary.json") -Raw)
if ($failed) { exit 1 }
