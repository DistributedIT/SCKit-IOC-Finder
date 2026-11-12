# Test-SCKitIOC.ps1
# Version 1.0  (2026-11-12)
#
# Read-only detection sweep for the SCKit / rogue ScreenConnect client campaign
# (Huntress "SCKit Worm", Sophos, Blackpoint, Nov 2026). Built for ConnectWise
# RMM (Asio) running as SYSTEM, but has no Asio dependency.
#
# STDOUT CONTRACT (Asio captures stdout into the custom field SCKitDetected):
#   Exactly one token is written to stdout, nothing else:
#     HIT     one or more indicators found
#     CLEAN   every check ran and found nothing
#     ERROR   no indicators found, but at least one check could not run
#   Exit codes: 0 CLEAN, 1 HIT, 2 ERROR
#
# All detail goes to a log file, never to the console:
#   C:\sckitcheck\SCKitCheck_<hostname>_<yyyyMMdd-HHmmss>.txt   (last 10 kept)
# and a registry stamp:
#   HKLM\SOFTWARE\SCKitCheck   Status, Findings, HitCount, LastRun, LastLog, Version
#
# PARAMETER (Asio text placeholder, substituted before execution):
#   @SCInstanceID@  16 hex chars, the instance ID of YOUR ScreenConnect server
#                   (comma-separate several if you run more than one server).
#                   Found in the legit client service name on any known-good
#                   endpoint: "ScreenConnect Client (xxxxxxxxxxxxxxxx)".
#                   If supplied: a client SERVICE or PROCESS with a different ID
#                                is CRITICAL; leftover folders or uninstall
#                                entries with another ID are INFO only.
#                   If blank:    known rogue IDs are CRITICAL, and two or more
#                                active client services is SUSPICIOUS (HIT).
#                                Vendor support clients can cause that, so
#                                supply the ID to classify properly.
#
# Severity labels in the log:
#   CRITICAL    direct SCKit artifact or known-bad indicator
#   SUSPICIOUS  consistent with SCKit but could have another explanation
#   INFO        logged for context only, does not affect the verdict
# Both CRITICAL and SUSPICIOUS produce HIT.
#
# This script changes nothing on the host except its own log directory and
# registry stamp. Remediation is a separate step.

$SCInstanceIDRaw = '3af6dde13ca48caa'

$ProgressPreference = 'SilentlyContinue'

# Asio launches 32-bit PowerShell. Relaunch 64-bit so HKLM, Program Files and
# CIM report the real view. Child stdout passes straight through to the parent.
if ($env:PROCESSOR_ARCHITEW6432 -eq 'AMD64' -and $PSCommandPath) {
    $sysnativePs = Join-Path $env:SystemRoot 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path -LiteralPath $sysnativePs) {
        $LASTEXITCODE = $null
        & $sysnativePs -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $PSCommandPath 2>$null
        if ($null -ne $LASTEXITCODE) { exit $LASTEXITCODE }
        # child failed to start; continue in the 32-bit process
    }
}

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
$ScriptVersion = '1.0'
$LogDir        = 'C:\sckitcheck'
$LogKeep       = 10
$RegPath       = 'HKLM:\SOFTWARE\SCKitCheck'
$EventLookbackDays = 30
$HostName      = $env:COMPUTERNAME
$RunStamp      = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
$LogFile       = Join-Path $LogDir ("SCKitCheck_{0}_{1}.txt" -f $HostName, $RunStamp)

# Known rogue ScreenConnect client instance IDs (attacker-controlled servers)
$RogueInstanceIDs = @('2588ef5c15954b10', 'ed630cc2c873b091')

# Instance IDs of MSP panels observed issuing the malicious commands (Sophos).
# A client carrying one of these reports to a panel that was compromised.
$CompromisedPanelIDs = @('d905b2b1b165d0a9', '4b8f4089ddaac6a9', 'df1f7ef0cfacd0d8')

# Fixed-location artifacts
$FixedPaths = @(
    @{ Path = 'C:\ProgramData\RelayTrap';            Sev = 'CRITICAL'; Note = 'SCKit toolkit root' },
    @{ Path = 'C:\Windows\Temp\sc.msi';              Sev = 'CRITICAL'; Note = 'Rogue ScreenConnect installer' },
    @{ Path = 'C:\Windows\Temp\sckit-run.bat';       Sev = 'CRITICAL'; Note = 'Base64 dropper' },
    @{ Path = 'C:\Windows\Temp\sckit-decoder.ps1';   Sev = 'CRITICAL'; Note = 'Decoder stage' },
    @{ Path = 'C:\Users\Public\RELAY-TRAP-PROOF.txt'; Sev = 'CRITICAL'; Note = 'Written by TRAP-PROOF.bat' }
)

# Temp-folder artifacts. Wildcards are -like patterns; regex entries are flagged.
$TempFilePatterns = @(
    @{ Pattern = 'sckit-*';                           Sev = 'CRITICAL' },
    @{ Pattern = 'runnew.cmd';                        Sev = 'CRITICAL' },
    @{ Pattern = 'Panel-Lateral*.ps1';                Sev = 'CRITICAL' },
    @{ Pattern = 'ToolboxRelayUploader.exe';          Sev = 'CRITICAL' },
    @{ Pattern = 'Run-Lateral-Full.bat';              Sev = 'CRITICAL' },
    @{ Pattern = 'WithUninstall.ps1';                 Sev = 'CRITICAL' },
    @{ Pattern = 'SilentForceInstall-WithUninstall.ps1'; Sev = 'CRITICAL' },
    @{ Pattern = 'LabConfig.ps1';                     Sev = 'CRITICAL' },
    @{ Pattern = 'Lab-context.json';                  Sev = 'CRITICAL' },
    @{ Pattern = 'TrapWatch.ps1';                     Sev = 'CRITICAL' },
    @{ Pattern = 'RelayTrap.cs';                      Sev = 'CRITICAL' },
    @{ Pattern = 'RelayTrap.exe';                     Sev = 'CRITICAL' },
    @{ Pattern = 'Lite-Alert.ps1';                    Sev = 'CRITICAL' },
    @{ Pattern = 'Stage0Loader.ps1';                  Sev = 'CRITICAL' },
    @{ Pattern = 'TRAP-PROOF.bat';                    Sev = 'CRITICAL' },
    @{ Pattern = 'Stop-LabTrap.*';                    Sev = 'CRITICAL' },
    @{ Pattern = 'Release-Machine.cmd';               Sev = 'CRITICAL' },
    @{ Pattern = 'Recover-ExecutionPolicy.cmd';       Sev = 'CRITICAL' },
    @{ Pattern = 'sc.msi';                            Sev = 'CRITICAL' },
    @{ Pattern = 'sqlite3.exe';                       Sev = 'SUSPICIOUS' }
)
# Keyed loader scripts: k<32 hex>.ps1 or k<guid>.ps1
$TempFileRegex = '^k([0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.ps1$'

$ProcessNames = @(
    @{ Name = 'RelayTrap.exe';            Sev = 'CRITICAL' },
    @{ Name = 'ToolboxRelayUploader.exe'; Sev = 'CRITICAL' },
    @{ Name = 'sqlite3.exe';              Sev = 'SUSPICIOUS' }   # downgraded to INFO unless under Temp or RelayTrap
)
$PSMetaProps = @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')

$BadIPs = @('185.99.255.28', '155.94.150.39', '131.123.40.98')
$BadDomains = @(
    'ns.mo7sen.dev', 'newnewnew.gotdns.org', 'soxnewwork.homedns.org',
    'sc.payproofkit.com', 'cdn007-digitaldownloads.com', 'borertors92.anondns.net'
)

# Strings that make a Defender exclusion or SRP/AppLocker rule SUSPICIOUS.
# 'ScreenConnect' and '\Temp' are logged INFO only: ConnectWise's own AV guidance
# excludes the client folder, and deny rules on \Temp are normal hardening.
$PolicyKeywords = @('RelayTrap', 'sckit-', 'TrapWatch')
$PolicyInfoKeywords = @('ScreenConnect', '\Temp')

# Regex for SCKit artifacts in command lines, task actions and Run values.
# 'sckit-' (with hyphen) so this script's own name and C:\sckitcheck never match.
$ArtifactRegex = 'RelayTrap|sckit-|TrapWatch|Panel-Lateral|EadF\.php'
# Anything referencing this script or its log directory is excluded before matching
$SelfRegex = 'Test-SCKitIOC|C:\\sckitcheck'

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
$Findings    = New-Object System.Collections.ArrayList   # objects: Sev, Check, Detail
$LogLines    = New-Object System.Collections.ArrayList
$CheckErrors = New-Object System.Collections.ArrayList

function Add-Log {
    param([string]$Text)
    [void]$LogLines.Add($Text)
}

function Add-Finding {
    param([string]$Sev, [string]$Check, [string]$Detail)
    [void]$Findings.Add([pscustomobject]@{ Sev = $Sev; Check = $Check; Detail = $Detail })
    Add-Log ("  [{0}] {1}" -f $Sev, $Detail)
}

function Add-CheckError {
    param([string]$Check, [string]$Message)
    [void]$CheckErrors.Add(("{0}: {1}" -f $Check, $Message))
    Add-Log ("  [ERROR] check could not complete: {0}" -f $Message)
}

function Start-Section {
    param([string]$Title)
    Add-Log ''
    Add-Log ("== {0} ==" -f $Title)
}

function Get-SCInstanceIDFromText {
    param([string]$Text)
    if ($Text -match 'ScreenConnect Client \(([0-9a-fA-F]{16})\)') { return $Matches[1].ToLower() }
    return $null
}

# Classify a ScreenConnect client instance ID. Returns $null if it is ours.
# -Active means the ID is backed by a service or running process (strong evidence);
# otherwise it came from a folder, uninstall entry or old event (weak evidence).
function Get-InstanceIDVerdict {
    param([string]$ID, [switch]$Active)
    $idl = $ID.ToLower()
    if ($RogueInstanceIDs -contains $idl)      { return @{ Sev = 'CRITICAL'; Why = 'known rogue SCKit client ID' } }
    if ($CompromisedPanelIDs -contains $idl)   { return @{ Sev = 'CRITICAL'; Why = 'client of a panel observed issuing malicious commands' } }
    if ($OwnedInstanceIDs.Count -gt 0) {
        if ($OwnedInstanceIDs -contains $idl)  { return $null }
        if ($Active) { return @{ Sev = 'CRITICAL'; Why = ("not our instance (ours: {0})" -f ($OwnedInstanceIDs -join ',')) } }
        return @{ Sev = 'INFO'; Why = ("not our instance but no service or process, likely remnant (ours: {0})" -f ($OwnedInstanceIDs -join ',')) }
    }
    return @{ Sev = 'UNKNOWN'; Why = 'owned instance ID not supplied' }
}

# ---------------------------------------------------------------------------
# Placeholder handling
# ---------------------------------------------------------------------------
$OwnedInstanceIDs = @()
if ($SCInstanceIDRaw -and $SCInstanceIDRaw -notmatch '^@.*@$') {
    foreach ($cand in ($SCInstanceIDRaw -split '[,;\s]+')) {
        $c = $cand.Trim().ToLower()
        if (-not $c) { continue }
        if ($c -match '^[0-9a-f]{16}$') { $OwnedInstanceIDs += $c }
        else { Add-Log ("WARNING: SCInstanceID value '{0}' is not 16 hex characters, ignoring it" -f $c) }
    }
}
$OwnedInstanceID = ($OwnedInstanceIDs -join ',')   # display only

# ---------------------------------------------------------------------------
# Completion: log file, registry stamp, single stdout token, exit
# ---------------------------------------------------------------------------
function Complete-Check {
    param([string]$ForcedVerdict, [string]$FatalMessage)

    $critCount = @($Findings | Where-Object { $_.Sev -eq 'CRITICAL' }).Count
    $suspCount = @($Findings | Where-Object { $_.Sev -eq 'SUSPICIOUS' }).Count
    $hitCount  = $critCount + $suspCount

    if ($ForcedVerdict) { $verdict = $ForcedVerdict }
    elseif ($hitCount -gt 0)        { $verdict = 'HIT' }
    elseif ($CheckErrors.Count -gt 0) { $verdict = 'ERROR' }
    else                            { $verdict = 'CLEAN' }

    switch ($verdict) { 'CLEAN' { $code = 0 } 'HIT' { $code = 1 } default { $code = 2 } }

    $summary = ($Findings | Where-Object { $_.Sev -ne 'INFO' } | ForEach-Object { "{0}:{1}" -f $_.Check, $_.Detail }) -join '; '
    if ($summary.Length -gt 1500) { $summary = $summary.Substring(0, 1497) + '...' }

    $header = New-Object System.Collections.ArrayList
    [void]$header.Add('SCKit / Rogue ScreenConnect IOC Check')
    [void]$header.Add(('Version:   {0}' -f $ScriptVersion))
    [void]$header.Add(('Host:      {0}' -f $HostName))
    [void]$header.Add(('Run:       {0}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')))
    [void]$header.Add(('Owned ID:  {0}' -f $(if ($OwnedInstanceID) { $OwnedInstanceID } else { '(not supplied)' })))
    [void]$header.Add('')
    [void]$header.Add(('VERDICT:   {0}' -f $verdict))
    [void]$header.Add(('Critical:  {0}   Suspicious: {1}   Check errors: {2}' -f $critCount, $suspCount, $CheckErrors.Count))
    if ($FatalMessage) { [void]$header.Add(('Fatal:     {0}' -f $FatalMessage)) }
    if ($hitCount -gt 0) {
        [void]$header.Add('')
        [void]$header.Add('FINDINGS:')
        foreach ($f in ($Findings | Where-Object { $_.Sev -ne 'INFO' })) {
            [void]$header.Add(('  [{0}] {1}: {2}' -f $f.Sev, $f.Check, $f.Detail))
        }
        [void]$header.Add('')
        [void]$header.Add('Do NOT connect to this host through ScreenConnect. Use the RMM agent or EDR live response.')
    }
    if ($CheckErrors.Count -gt 0) {
        [void]$header.Add('')
        [void]$header.Add('CHECK ERRORS:')
        foreach ($e in $CheckErrors) { [void]$header.Add(('  {0}' -f $e)) }
    }
    [void]$header.Add('')
    [void]$header.Add('---------------------------------------------------------------- detail')

    $logWritten = $false
    try {
        if (-not (Test-Path -LiteralPath $LogDir)) { New-Item -Path $LogDir -ItemType Directory -Force | Out-Null }
        $allLines = @($header) + @($LogLines)
        Set-Content -LiteralPath $LogFile -Value $allLines -Encoding UTF8
        $logWritten = $true
        # Retention
        $old = Get-ChildItem -LiteralPath $LogDir -Filter 'SCKitCheck_*.txt' -File |
               Sort-Object LastWriteTime -Descending | Select-Object -Skip $LogKeep
        foreach ($o in $old) { Remove-Item -LiteralPath $o.FullName -Force -ErrorAction SilentlyContinue }
    } catch { }

    try {
        if (-not (Test-Path -LiteralPath $RegPath)) { New-Item -Path $RegPath -Force | Out-Null }
        New-ItemProperty -LiteralPath $RegPath -Name 'Status'   -Value $verdict -PropertyType String -Force | Out-Null
        New-ItemProperty -LiteralPath $RegPath -Name 'Findings' -Value $summary -PropertyType String -Force | Out-Null
        New-ItemProperty -LiteralPath $RegPath -Name 'HitCount' -Value $hitCount -PropertyType DWord  -Force | Out-Null
        New-ItemProperty -LiteralPath $RegPath -Name 'LastRun'  -Value (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') -PropertyType String -Force | Out-Null
        New-ItemProperty -LiteralPath $RegPath -Name 'LastLog'  -Value $(if ($logWritten) { $LogFile } else { '' }) -PropertyType String -Force | Out-Null
        New-ItemProperty -LiteralPath $RegPath -Name 'Version'  -Value $ScriptVersion -PropertyType String -Force | Out-Null
    } catch { }

    Write-Output $verdict
    exit $code
}

# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------
try {
    Add-Log ("Started {0} on {1}, PowerShell {2}, 64-bit process: {3}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $HostName, $PSVersionTable.PSVersion, [Environment]::Is64BitProcess)

    # 1. Fixed paths -----------------------------------------------------------
    Start-Section 'Fixed-location artifacts'
    try {
        foreach ($fp in $FixedPaths) {
            if (Test-Path -LiteralPath $fp.Path) {
                Add-Finding $fp.Sev 'Path' ("{0} ({1})" -f $fp.Path, $fp.Note)
            }
        }
        if (Test-Path -LiteralPath 'C:\ProgramData\RelayTrap') {
            try {
                $rtFiles = Get-ChildItem -LiteralPath 'C:\ProgramData\RelayTrap' -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 50
                foreach ($rf in $rtFiles) { Add-Log ("    contents: {0}" -f $rf.FullName) }
            } catch { }
        }
        Add-Log ("  checked {0} fixed paths" -f $FixedPaths.Count)
    } catch { Add-CheckError 'FixedPaths' $_.Exception.Message }

    # 2. Temp folder sweep -------------------------------------------------------
    Start-Section 'Temp folder sweep (top level + 1)'
    try {
        $tempDirs = New-Object System.Collections.ArrayList
        [void]$tempDirs.Add('C:\Windows\Temp')
        [void]$tempDirs.Add('C:\Windows\System32\config\systemprofile\AppData\Local\Temp')
        [void]$tempDirs.Add('C:\Windows\ServiceProfiles\LocalService\AppData\Local\Temp')
        [void]$tempDirs.Add('C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp')
        if (Test-Path -LiteralPath 'C:\Users') {
            foreach ($u in (Get-ChildItem -LiteralPath 'C:\Users' -Directory -ErrorAction SilentlyContinue)) {
                [void]$tempDirs.Add((Join-Path $u.FullName 'AppData\Local\Temp'))
            }
        }
        $scanned = 0
        foreach ($td in $tempDirs) {
            if (-not (Test-Path -LiteralPath $td)) { continue }
            $scanned++
            if ($PSVersionTable.PSVersion.Major -ge 5) {
                $files = @(Get-ChildItem -LiteralPath $td -File -Depth 1 -Force -ErrorAction SilentlyContinue | Select-Object -First 5000)
            } else {
                $files = @(Get-ChildItem -LiteralPath $td -Force -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer } | Select-Object -First 5000)
            }
            if ($files.Count -ge 5000) { Add-Log ("  [INFO] {0} capped at 5000 files" -f $td) }
            foreach ($f in $files) {
                # already reported by the fixed-path check
                $dup = $false
                foreach ($fp in $FixedPaths) { if ($f.FullName -ieq $fp.Path) { $dup = $true } }
                if ($dup) { continue }
                $matched = $false
                foreach ($tp in $TempFilePatterns) {
                    if ($f.Name -like $tp.Pattern) {
                        Add-Finding $tp.Sev 'TempFile' ("{0} ({1} bytes, modified {2})" -f $f.FullName, $f.Length, $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))
                        $matched = $true
                        break
                    }
                }
                if (-not $matched -and $f.Name -match $TempFileRegex) {
                    Add-Finding 'CRITICAL' 'TempFile' ("{0} (keyed SCKit loader name pattern)" -f $f.FullName)
                }
            }
        }
        Add-Log ("  scanned {0} temp directories" -f $scanned)
    } catch { Add-CheckError 'TempSweep' $_.Exception.Message }

    # 3. Scheduled tasks -------------------------------------------------------------
    Start-Section 'Scheduled tasks'
    try {
        $taskCmd = Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue
        if ($taskCmd) {
            $tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue)
            foreach ($t in $tasks) {
                if ($t.TaskName -eq 'TrapWatch') {
                    Add-Finding 'CRITICAL' 'ScheduledTask' ("TrapWatch task present ({0}{1}), state {2}" -f $t.TaskPath, $t.TaskName, $t.State)
                    continue
                }
                foreach ($a in @($t.Actions)) {
                    $actText = ("{0} {1}" -f $a.Execute, $a.Arguments)
                    if ($actText -match $SelfRegex) { continue }
                    if ($actText -match $ArtifactRegex) {
                        Add-Finding 'CRITICAL' 'ScheduledTask' ("{0}{1} runs: {2}" -f $t.TaskPath, $t.TaskName, $actText.Trim())
                    }
                }
            }
            Add-Log ("  enumerated {0} tasks" -f $tasks.Count)
        } else {
            $ErrorActionPreference = 'Continue'
            try { $raw = @(& schtasks.exe /Query /FO CSV /NH 2>$null) } finally { $ErrorActionPreference = 'Stop' }
            $hit = @($raw | Where-Object { $_ -match '\\TrapWatch"' })
            if ($hit.Count -gt 0) { Add-Finding 'CRITICAL' 'ScheduledTask' 'TrapWatch task present (schtasks)' }
            Add-Log '  Get-ScheduledTask unavailable, used schtasks name match only'
        }
    } catch { Add-CheckError 'ScheduledTasks' $_.Exception.Message }

    # 4. Registry Run keys -------------------------------------------------------------
    Start-Section 'Registry Run keys'
    try {
        $runKeys = New-Object System.Collections.ArrayList
        foreach ($rk in @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce')) { [void]$runKeys.Add($rk) }
        # Loaded user hives: local/domain (S-1-5-21) and Entra ID (S-1-12-1) users
        $hku = @(Get-ChildItem -Path 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-(5-21|12-1)-\d+-\d+-\d+-\d+$' })
        foreach ($h in $hku) {
            [void]$runKeys.Add(("Registry::HKEY_USERS\{0}\Software\Microsoft\Windows\CurrentVersion\Run" -f $h.PSChildName))
            [void]$runKeys.Add(("Registry::HKEY_USERS\{0}\Software\Microsoft\Windows\CurrentVersion\RunOnce" -f $h.PSChildName))
        }
        foreach ($rk in $runKeys) {
            if (-not (Test-Path -LiteralPath $rk)) { continue }
            $props = Get-ItemProperty -LiteralPath $rk -ErrorAction SilentlyContinue
            if (-not $props) { continue }
            foreach ($p in $props.PSObject.Properties) {
                if ($PSMetaProps -contains $p.Name) { continue }
                $val = ("{0}" -f $p.Value)
                if ($val -match $SelfRegex) { continue }
                if ($p.Name -eq 'RelayTrapLiteAlert' -or $val -match $ArtifactRegex) {
                    Add-Finding 'CRITICAL' 'RunKey' ("{0}\{1} = {2}" -f $rk, $p.Name, $val)
                }
            }
        }
        Add-Log ("  checked {0} Run/RunOnce keys (HKLM both views plus {1} loaded user hives)" -f $runKeys.Count, $hku.Count)
    } catch { Add-CheckError 'RunKeys' $_.Exception.Message }

    # 5. ScreenConnect client services, folders, uninstall entries ---------------------
    Start-Section 'ScreenConnect client instances'
    try {
        $seenIDs = @{}     # id -> list of where seen
        $activeIDs = @{}   # id -> $true when backed by a service

        $svcs = @(Get-CimInstance -ClassName Win32_Service -Filter "Name LIKE 'ScreenConnect Client (%'" -OperationTimeoutSec 120 -ErrorAction Stop)
        foreach ($s in $svcs) {
            $id = Get-SCInstanceIDFromText $s.Name
            if (-not $id) { continue }
            if (-not $seenIDs.ContainsKey($id)) { $seenIDs[$id] = New-Object System.Collections.ArrayList }
            [void]$seenIDs[$id].Add(("service {0} [{1}/{2}] {3}" -f $s.Name, $s.State, $s.StartMode, $s.PathName))
            $activeIDs[$id] = $true
        }

        foreach ($pfRoot in @('C:\Program Files (x86)', 'C:\Program Files')) {
            if (-not (Test-Path -LiteralPath $pfRoot)) { continue }
            $dirs = @(Get-ChildItem -LiteralPath $pfRoot -Directory -Filter 'ScreenConnect Client (*' -ErrorAction SilentlyContinue)
            foreach ($d in $dirs) {
                $id = Get-SCInstanceIDFromText $d.Name
                if (-not $id) { continue }
                if (-not $seenIDs.ContainsKey($id)) { $seenIDs[$id] = New-Object System.Collections.ArrayList }
                [void]$seenIDs[$id].Add(("folder {0}" -f $d.FullName))
            }
        }

        foreach ($uk in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
            if (-not (Test-Path -LiteralPath $uk)) { continue }
            $entries = @(Get-ChildItem -LiteralPath $uk -ErrorAction SilentlyContinue)
            foreach ($e in $entries) {
                $dn = (Get-ItemProperty -LiteralPath $e.PSPath -Name DisplayName -ErrorAction SilentlyContinue).DisplayName
                if (-not $dn) { continue }
                $id = Get-SCInstanceIDFromText $dn
                if (-not $id) { continue }
                if (-not $seenIDs.ContainsKey($id)) { $seenIDs[$id] = New-Object System.Collections.ArrayList }
                [void]$seenIDs[$id].Add(("uninstall entry '{0}'" -f $dn))
            }
        }

        if ($seenIDs.Count -eq 0) {
            Add-Log '  no ScreenConnect client instances found on this host'
        } else {
            $unknownActive = New-Object System.Collections.ArrayList
            foreach ($id in $seenIDs.Keys) {
                $where = ($seenIDs[$id] -join '; ')
                $v = Get-InstanceIDVerdict $id -Active:($activeIDs.ContainsKey($id))
                if ($null -eq $v) {
                    Add-Finding 'INFO' 'SCInstance' ("{0} is our instance: {1}" -f $id, $where)
                } elseif ($v.Sev -eq 'UNKNOWN') {
                    if ($activeIDs.ContainsKey($id)) { [void]$unknownActive.Add($id) }
                    Add-Finding 'INFO' 'SCInstance' ("{0} ({1}): {2}" -f $id, $v.Why, $where)
                } else {
                    Add-Finding $v.Sev 'SCInstance' ("{0} {1}: {2}" -f $id, $v.Why, $where)
                }
            }
            if ($OwnedInstanceIDs.Count -eq 0 -and $unknownActive.Count -gt 1) {
                Add-Finding 'SUSPICIOUS' 'SCInstance' ("{0} ScreenConnect client services from different instances ({1}). Vendor support clients can explain this; supply SCInstanceID to classify." -f $unknownActive.Count, ($unknownActive -join ', '))
            }
            # SCKit stops the legitimate client and sets it to Manual before swapping in its own
            if ($OwnedInstanceIDs.Count -gt 0) {
                $own = $svcs | Where-Object { $OwnedInstanceIDs -contains (Get-SCInstanceIDFromText $_.Name) }
                foreach ($o in @($own)) {
                    if ($o.State -ne 'Running' -and $o.StartMode -eq 'Manual') {
                        Add-Finding 'SUSPICIOUS' 'SCInstance' ("our client service {0} is {1} with StartMode Manual (SCKit swap pattern)" -f $o.Name, $o.State)
                    }
                }
            }
        }
    } catch { Add-CheckError 'SCInstances' $_.Exception.Message }

    # 6. Processes --------------------------------------------------------------------
    Start-Section 'Running processes'
    try {
        $procs = @(Get-CimInstance -ClassName Win32_Process -OperationTimeoutSec 120 -ErrorAction Stop)
        # Exclude this script's own process tree (RMM agent -> 32-bit PS -> 64-bit PS)
        $selfPids = @{}
        $cur = $PID
        for ($i = 0; $i -lt 4 -and $cur; $i++) {
            $selfPids[[int]$cur] = $true
            $me = $procs | Where-Object { $_.ProcessId -eq $cur } | Select-Object -First 1
            if ($me) { $cur = $me.ParentProcessId } else { $cur = 0 }
        }
        foreach ($p in $procs) {
            if ($selfPids.ContainsKey([int]$p.ProcessId)) { continue }
            $cmd = ("{0}" -f $p.CommandLine)
            if ($cmd -match $SelfRegex) { continue }
            foreach ($pn in $ProcessNames) {
                if ($p.Name -ieq $pn.Name) {
                    $sev = $pn.Sev
                    if ($pn.Name -ieq 'sqlite3.exe') {
                        $exe = ("{0}" -f $p.ExecutablePath)
                        if ($exe -notmatch '\\Temp\\|RelayTrap') { $sev = 'INFO' }
                    }
                    Add-Finding $sev 'Process' ("{0} PID {1} path {2} cmd: {3}" -f $p.Name, $p.ProcessId, $p.ExecutablePath, $cmd)
                }
            }
            if ($p.Name -like 'ScreenConnect.*' -and $p.ExecutablePath) {
                $id = Get-SCInstanceIDFromText $p.ExecutablePath
                if ($id) {
                    $v = Get-InstanceIDVerdict $id -Active
                    if ($v -and $v.Sev -ne 'UNKNOWN') {
                        Add-Finding $v.Sev 'Process' ("{0} PID {1} belongs to instance {2} ({3})" -f $p.Name, $p.ProcessId, $id, $v.Why)
                    }
                }
            }
            if ($cmd -match $ArtifactRegex) {
                Add-Finding 'CRITICAL' 'Process' ("{0} PID {1} cmd: {2}" -f $p.Name, $p.ProcessId, $cmd)
            }
        }
        Add-Log ("  enumerated {0} processes" -f $procs.Count)
    } catch { Add-CheckError 'Processes' $_.Exception.Message }

    # 7. Network ----------------------------------------------------------------------
    Start-Section 'Network connections and DNS cache'
    try {
        $connChecked = $false
        if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
            $conns = @(Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $BadIPs -contains $_.RemoteAddress })
            foreach ($c in $conns) {
                Add-Finding 'CRITICAL' 'Network' ("connection to {0}:{1} state {2} owning PID {3}" -f $c.RemoteAddress, $c.RemotePort, $c.State, $c.OwningProcess)
            }
            $connChecked = $true
        } else {
            $ErrorActionPreference = 'Continue'
            try { $ns = @(& netstat.exe -ano 2>$null) } finally { $ErrorActionPreference = 'Stop' }
            foreach ($line in @($ns)) {
                foreach ($ip in $BadIPs) {
                    if ($line -match ("\s{0}:" -f [regex]::Escape($ip))) { Add-Finding 'CRITICAL' 'Network' ("netstat: {0}" -f $line.Trim()) }
                }
            }
            $connChecked = $true
        }
        $dnsChecked = $false
        if (Get-Command Get-DnsClientCache -ErrorAction SilentlyContinue) {
            $cache = @(Get-DnsClientCache -ErrorAction SilentlyContinue)
            foreach ($entry in $cache) {
                foreach ($d in $BadDomains) {
                    if ($entry.Entry -like ("*{0}" -f $d) -or $entry.Name -like ("*{0}" -f $d)) {
                        Add-Finding 'CRITICAL' 'Network' ("DNS cache entry {0} -> {1}" -f $entry.Entry, $entry.Data)
                    }
                }
                if ($BadIPs -contains ("{0}" -f $entry.Data)) {
                    Add-Finding 'CRITICAL' 'Network' ("DNS cache entry {0} -> {1}" -f $entry.Entry, $entry.Data)
                }
            }
            $dnsChecked = $true
        } else {
            $ErrorActionPreference = 'Continue'
            try { $dd = @(& ipconfig.exe /displaydns 2>$null) } finally { $ErrorActionPreference = 'Stop' }
            $ddText = ($dd -join "`n")
            foreach ($d in $BadDomains) { if ($ddText -match [regex]::Escape($d)) { Add-Finding 'CRITICAL' 'Network' ("DNS cache contains {0}" -f $d) } }
            foreach ($ip in $BadIPs)    { if ($ddText -match [regex]::Escape($ip)) { Add-Finding 'CRITICAL' 'Network' ("DNS cache resolves to {0}" -f $ip) } }
            $dnsChecked = $true
        }
        Add-Log ("  connections checked: {0}, DNS cache checked: {1}" -f $connChecked, $dnsChecked)
    } catch { Add-CheckError 'Network' $_.Exception.Message }

    # 8. Defender exclusions ------------------------------------------------------------
    Start-Section 'Microsoft Defender exclusions'
    try {
        $mp = $null
        if (Get-Command Get-MpPreference -ErrorAction SilentlyContinue) {
            try { $mp = Get-MpPreference -ErrorAction Stop }
            catch { Add-Log ("  [INFO] Defender not operational (third-party AV?): {0}" -f $_.Exception.Message) }
        } else {
            Add-Log '  Get-MpPreference not available (Defender module absent or third-party AV)'
        }
        if ($mp) {
            $excl = @()
            foreach ($x in @($mp.ExclusionPath))      { if ($x) { $excl += [pscustomobject]@{ Type = 'Path';      Value = $x } } }
            foreach ($x in @($mp.ExclusionProcess))   { if ($x) { $excl += [pscustomobject]@{ Type = 'Process';   Value = $x } } }
            foreach ($x in @($mp.ExclusionExtension)) { if ($x) { $excl += [pscustomobject]@{ Type = 'Extension'; Value = $x } } }
            foreach ($e in $excl) {
                $flag = $false
                foreach ($kw in $PolicyKeywords) { if ($e.Value -like ("*{0}*" -f $kw)) { $flag = $true } }
                if ($flag) { Add-Finding 'SUSPICIOUS' 'DefenderExclusion' ("{0} exclusion: {1}" -f $e.Type, $e.Value) }
                else       { Add-Log ("  [INFO] {0} exclusion: {1}" -f $e.Type, $e.Value) }
            }
            Add-Log ("  {0} exclusions total" -f $excl.Count)
        }
    } catch { Add-CheckError 'DefenderExclusions' $_.Exception.Message }

    # 9. SRP / AppLocker rules -------------------------------------------------------------
    Start-Section 'Software Restriction Policy and AppLocker rules'
    try {
        $ruleCount = 0
        # SRP path rules
        $srpBase = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers'
        if (Test-Path -LiteralPath $srpBase) {
            $levels = @(Get-ChildItem -LiteralPath $srpBase -ErrorAction SilentlyContinue)
            foreach ($lvl in $levels) {
                $pathsKey = Join-Path $lvl.PSPath 'Paths'
                if (-not (Test-Path -LiteralPath $pathsKey)) { continue }
                foreach ($rule in @(Get-ChildItem -LiteralPath $pathsKey -ErrorAction SilentlyContinue)) {
                    $ruleCount++
                    $item = ("{0}" -f (Get-ItemProperty -LiteralPath $rule.PSPath -ErrorAction SilentlyContinue).ItemData)
                    $flag = $false
                    foreach ($kw in $PolicyKeywords) { if ($item -like ("*{0}*" -f $kw)) { $flag = $true } }
                    if ($flag) { Add-Finding 'SUSPICIOUS' 'SRPRule' ("SRP level {0} path rule: {1}" -f $lvl.PSChildName, $item) }
                    else       { Add-Log ("  [INFO] SRP level {0} path rule: {1}" -f $lvl.PSChildName, $item) }
                }
            }
        }
        # AppLocker rules (XML stored per rule GUID)
        $alBase = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2'
        if (Test-Path -LiteralPath $alBase) {
            foreach ($coll in @(Get-ChildItem -LiteralPath $alBase -ErrorAction SilentlyContinue)) {
                foreach ($rule in @(Get-ChildItem -LiteralPath $coll.PSPath -ErrorAction SilentlyContinue)) {
                    $ruleCount++
                    $xml = ("{0}" -f (Get-ItemProperty -LiteralPath $rule.PSPath -ErrorAction SilentlyContinue).Value)
                    $flag = $false; $info = $false
                    foreach ($kw in $PolicyKeywords)     { if ($xml -like ("*{0}*" -f $kw)) { $flag = $true } }
                    foreach ($kw in $PolicyInfoKeywords) { if ($xml -like ("*{0}*" -f $kw)) { $info = $true } }
                    if ($flag -or $info) {
                        $snippet = $xml
                        if ($snippet.Length -gt 300) { $snippet = $snippet.Substring(0, 300) + '...' }
                        if ($flag) { Add-Finding 'SUSPICIOUS' 'AppLockerRule' ("{0} rule {1}: {2}" -f $coll.PSChildName, $rule.PSChildName, $snippet) }
                        else       { Add-Log ("  [INFO] AppLocker {0} rule {1} references ScreenConnect/Temp: {2}" -f $coll.PSChildName, $rule.PSChildName, $snippet) }
                    }
                }
            }
        }
        Add-Log ("  {0} SRP/AppLocker rules inspected" -f $ruleCount)
    } catch { Add-CheckError 'SRPAppLocker' $_.Exception.Message }

    # 10. Event logs (bounded) -------------------------------------------------------------
    Start-Section ("Event logs, last {0} days" -f $EventLookbackDays)
    try {
        $since = (Get-Date).AddDays(-$EventLookbackDays)
        # 4698: scheduled task created
        try {
            $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4698; StartTime = $since } -MaxEvents 500 -ErrorAction Stop)
            foreach ($e in $ev) {
                $msg = $e.Message
                if ($msg -match 'TrapWatch|RelayTrap') {
                    Add-Finding 'CRITICAL' 'EventLog' ("Security 4698 at {0}: TrapWatch/RelayTrap task was created" -f $e.TimeCreated.ToString('yyyy-MM-dd HH:mm'))
                }
            }
            Add-Log ("  Security 4698 events reviewed: {0}" -f $ev.Count)
        } catch {
            if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*' -or $_.Exception.Message -match 'No events were found') { Add-Log '  Security 4698 events reviewed: 0' }
            else { Add-CheckError 'EventLog4698' $_.Exception.Message }
        }
        # 7045: service installed
        try {
            $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7045; StartTime = $since } -MaxEvents 500 -ErrorAction Stop)
            foreach ($e in $ev) {
                $msg = $e.Message
                if ($msg -match 'ScreenConnect Client \(([0-9a-fA-F]{16})\)') {
                    $id = $Matches[1].ToLower()
                    $v = Get-InstanceIDVerdict $id
                    if ($v -and $v.Sev -ne 'UNKNOWN' -and $v.Sev -ne 'INFO') {
                        Add-Finding $v.Sev 'EventLog' ("System 7045 at {0}: ScreenConnect client service for instance {1} installed ({2})" -f $e.TimeCreated.ToString('yyyy-MM-dd HH:mm'), $id, $v.Why)
                    } else {
                        Add-Log ("  [INFO] System 7045 at {0}: ScreenConnect client {1} installed" -f $e.TimeCreated.ToString('yyyy-MM-dd HH:mm'), $id)
                    }
                }
                if ($msg -match 'RelayTrap|sckit-') {
                    Add-Finding 'CRITICAL' 'EventLog' ("System 7045 at {0}: service install references RelayTrap/sckit" -f $e.TimeCreated.ToString('yyyy-MM-dd HH:mm'))
                }
            }
            Add-Log ("  System 7045 events reviewed: {0}" -f $ev.Count)
        } catch {
            if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*' -or $_.Exception.Message -match 'No events were found') { Add-Log '  System 7045 events reviewed: 0' }
            else { Add-CheckError 'EventLog7045' $_.Exception.Message }
        }
    } catch { Add-CheckError 'EventLogs' $_.Exception.Message }

    Add-Log ''
    Add-Log ("Finished {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
    Complete-Check
}
catch {
    # Unhandled failure outside the per-check guards. Findings so far still count.
    Add-Log ("FATAL: {0}" -f $_.Exception.Message)
    $forced = ''
    $anyHit = @($Findings | Where-Object { $_.Sev -eq 'CRITICAL' -or $_.Sev -eq 'SUSPICIOUS' }).Count -gt 0
    if (-not $anyHit) { $forced = 'ERROR' }
    Complete-Check -ForcedVerdict $forced -FatalMessage $_.Exception.Message
}
