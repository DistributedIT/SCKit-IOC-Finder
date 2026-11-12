# Test-SCKitIOC.ps1

Read-only PowerShell sweep that checks a Windows endpoint for indicators of the **SCKit** campaign: rogue ScreenConnect clients pushed through compromised ScreenConnect panels, plus the RelayTrap toolkit that rides along with them (Huntress, Sophos, Blackpoint, November 2026).

Built to run from an RMM as SYSTEM. It prints one word, writes a human-readable log on the machine, and leaves a registry stamp. It changes nothing else. Remediation is deliberately out of scope.

## Background

In November 2026 attackers used ScreenConnect's Run Command feature on several MSP panels to install a second, attacker-controlled ScreenConnect client on hundreds of managed endpoints, along with a toolkit (SCKit / RelayTrap) that:

- stops the legitimate client and sets it to Manual start
- persists through a scheduled task, a Run key, Defender exclusions and SRP/AppLocker rules that block the real client's temp folder
- waits for a technician to connect and pushes itself to the technician's workstation
- reads browser cookie databases to steal the technician's ScreenConnect panel session

The suspected entry point is an authentication weakness in the third-party **RMM+** extension (versions 1.0.31 and 1.0.32 with no access key configured). The client-side pivot uses CVE-2026-84869. Running the latest ScreenConnect release does not by itself mean you are clear.

Sources:

- Huntress: https://www.huntress.com/blog/sckit-worm-rogue-screenconnect
- Sophos: https://www.sophos.com/en-us/blog/malicious-screenconnect-deployments-observed
- The Hacker News / Blackpoint: https://thehackernews.com/2026/11/sckit-malware-targets-screenconnect.html
- The Register: https://www.theregister.com/security/2026/11/12/hackers-exploiting-screenconnect-plugin-flaw-to-spread-malware-across-hundreds-of-pcs/5309361

## Output

The script writes exactly one token to stdout and nothing else, so any RMM that captures script output can map it straight into a custom field:

| stdout | Exit code | Meaning |
| --- | --- | --- |
| `HIT` | 1 | One or more indicators found. Treat the machine as compromised until cleared. |
| `CLEAN` | 0 | Every check ran and found nothing. |
| `ERROR` | 2 | No indicators found, but at least one check could not run. Not clean until it completes. |

Detail goes to:

- **Log file:** `C:\sckitcheck\SCKitCheck_<hostname>_<timestamp>.txt`. Verdict, counts and every finding at the top, per-check detail below. The last 10 runs are kept.
- **Registry:** `HKLM\SOFTWARE\SCKitCheck` with `Status`, `Findings` (one-line summary), `HitCount`, `LastRun`, `LastLog`, `Version`.

Each finding in the log carries a severity:

| Label | Meaning | Counts toward HIT |
| --- | --- | --- |
| CRITICAL | Direct SCKit artifact or known-bad indicator | Yes |
| SUSPICIOUS | Fits the pattern but could have another explanation | Yes |
| INFO | Context only | No |

## The canaries

Everything the script looks for, grouped the way the log reports it.

**1. Known malware locations**

- `C:\ProgramData\RelayTrap\` (toolkit root; contents are listed in the log)
- `C:\Windows\Temp\sc.msi` (the rogue client installer)
- `C:\Windows\Temp\sckit-run.bat`, `sckit-decoder.ps1`
- `C:\Users\Public\RELAY-TRAP-PROOF.txt`

**2. Temp folder sweep** (`C:\Windows\Temp`, the SYSTEM / LocalService / NetworkService temps, and every `C:\Users\*\AppData\Local\Temp`, top level plus one subfolder level, capped at 5000 files each)

- `sckit-*`, `Panel-Lateral*.ps1`, `ToolboxRelayUploader.exe`, `runnew.cmd`, `Run-Lateral-Full.bat`, `WithUninstall.ps1`, `SilentForceInstall-WithUninstall.ps1`, `LabConfig.ps1`, `Lab-context.json`, `TrapWatch.ps1`, `RelayTrap.cs`, `RelayTrap.exe`, `Lite-Alert.ps1`, `Stage0Loader.ps1`, `TRAP-PROOF.bat`, `Stop-LabTrap.*`, `Release-Machine.cmd`, `Recover-ExecutionPolicy.cmd`, `sc.msi`
- Keyed loaders named `k` + 32 hex characters + `.ps1`, or `k` + GUID + `.ps1`
- `sqlite3.exe` in a temp folder (SUSPICIOUS; the toolkit uses it to read browser cookie databases)

**3. Scheduled tasks**

- A task named `TrapWatch` (the toolkit runs it as SYSTEM every 10 seconds)
- Any task whose action references `RelayTrap`, `sckit-`, `TrapWatch` or `Panel-Lateral`

**4. Run / RunOnce keys**

- A value named `RelayTrapLiteAlert`
- Any value pointing at the toolkit, in HKLM (native and WOW6432Node) and in every loaded user hive (local, domain and Entra ID SIDs)

**5. ScreenConnect client instances** (services, `Program Files` / `Program Files (x86)` folders, Add/Remove Programs entries)

- Known attacker client instance IDs: `2588ef5c15954b10`, `ed630cc2c873b091` (CRITICAL on any evidence)
- Instance IDs of MSP panels seen issuing the malicious commands: `d905b2b1b165d0a9`, `4b8f4089ddaac6a9`, `df1f7ef0cfacd0d8` (CRITICAL on any evidence)
- With your instance ID supplied: a client **service or running process** from any other instance is CRITICAL; a leftover folder or uninstall entry with no service behind it is INFO
- Without your instance ID: two or more active client services from different instances is SUSPICIOUS
- Your own client service stopped and set to Manual start is SUSPICIOUS (the swap pattern)

**6. Running processes**

- `RelayTrap.exe`, `ToolboxRelayUploader.exe`
- `sqlite3.exe` running from a Temp folder or RelayTrap (INFO elsewhere; scoop, Python, Node and similar ship it)
- Any ScreenConnect process from an instance other than yours
- Any command line referencing the toolkit (`RelayTrap`, `sckit-`, `TrapWatch`, `Panel-Lateral`, `EadF.php`)
- The script's own process tree and anything referencing the script or its log folder are excluded

**7. Network**

- Established connections to `185.99.255.28`, `155.94.150.39`, `131.123.40.98`
- DNS cache entries for `ns.mo7sen.dev`, `newnewnew.gotdns.org`, `soxnewwork.homedns.org`, `sc.payproofkit.com`, `cdn007-digitaldownloads.com`, `borertors92.anondns.net`

**8. Microsoft Defender exclusions**

- Exclusions referencing `RelayTrap`, `sckit-` or `TrapWatch` are SUSPICIOUS
- Everything else is listed as INFO. Exclusions for the ScreenConnect client folder are normal (ConnectWise's own AV guidance recommends them) and are not flagged. Hosts where Defender is disabled by a third-party AV log INFO and do not error.

**9. Software Restriction Policy and AppLocker rules**

- Rules referencing `RelayTrap`, `sckit-` or `TrapWatch` are SUSPICIOUS
- Rules mentioning ScreenConnect or Temp are INFO; deny rules on `%USERPROFILE%\AppData\Local\Temp` are normal hardening

**10. Event logs, last 30 days**

- Security 4698: a `TrapWatch` task was created (CRITICAL even if the task has since been removed)
- System 7045: a ScreenConnect client service for a known-rogue or non-owned instance was installed

Hashes are not used. The toolkit rebuilds its scripts per host, so names, paths, the task and the Run key are the stable indicators.

## Finding your ScreenConnect instance ID

Every client installed from your ScreenConnect server carries the same 16-character hex instance ID. Any client with a different ID is talking to a different server. Supplying yours lets the script tell your client from a rogue one with certainty; without it the script still catches the known rogue IDs but can only call a second client "suspicious."

On any known-good managed machine, any one of these shows it:

- **Services:** the service is named `ScreenConnect Client (xxxxxxxxxxxxxxxx)`. The 16 characters inside the parentheses are the ID.
- **Program Files:** `C:\Program Files (x86)\ScreenConnect Client (xxxxxxxxxxxxxxxx)\`
- **Add/Remove Programs:** the entry is named the same way.
- **PowerShell:**

  ```powershell
  Get-Service 'ScreenConnect Client (*' | Select-Object Name
  ```

Use only the 16 characters inside the parentheses. Do not include the parentheses. Case does not matter.

If you run more than one ScreenConnect server, collect the ID from a client of each one.

## Where to put the instance ID

Near the top of the script:

```powershell
$SCInstanceIDRaw = '@SCInstanceID@'
```

Two options:

**RMM parameter (preferred).** Leave the line alone and have your RMM substitute the value at run time. The script tolerates an unsubstituted `@SCInstanceID@` literal or a blank by falling back to the no-ID behavior.

- ConnectWise RMM (Asio): add a script parameter named `SCInstanceID`; Asio replaces the `@SCInstanceID@` text before execution.
- ConnectWise Automate: replace the placeholder with the Automate variable syntax your script uses (for example `@SCInstanceID@` as an Automate script variable of the same name, or `%scinstanceid%` from an EDF), or hardcode as below.
- Other RMMs: however your platform injects text into a script body, or hardcode as below.

**Hardcode.** Replace the whole placeholder, keep the quotes:

```powershell
$SCInstanceIDRaw = 'a1b2c3d4e5f60718'
```

Several servers, comma-separated in the same string:

```powershell
$SCInstanceIDRaw = 'a1b2c3d4e5f60718,0f1e2d3c4b5a6978'
```

Do not commit a hardcoded copy to a public repository.

## Deploying from an RMM

1. Run as SYSTEM (needed for `C:\Windows\Temp`, the systemprofile temp, other users' hives and the Security log).
2. Map script stdout to a text custom field, for example `SCKitDetected`. The script emits only `HIT`, `CLEAN` or `ERROR`.
3. Also alert on exit code 1 or 2 if your platform supports it.
4. Test on one known-clean machine first and confirm the field populates. Then run once across everything, then every 4 hours for the first couple of weeks (reinfection within minutes of lifting isolation has been observed), then daily.
5. Build a dynamic group or filter on `SCKitDetected = HIT` and alert on membership. That group is also your "do not connect via ScreenConnect" list.
6. Deploy and run the script through the RMM agent or EDR live response. Never push it through a ScreenConnect session to a suspected host; the toolkit targets the connecting technician.

Platform notes:

- **ConnectWise RMM (Asio)** launches 32-bit PowerShell. The script relaunches itself 64-bit through `Sysnative` so registry and Program Files paths resolve correctly. Asio populates a custom field by capturing stdout; there is no in-script field setter.
- **ConnectWise Automate** can run the script as a Script Execute step and capture `%shellresult%`, or map the exit code. If you use an EDF for the result, write it from the captured stdout.
- The script has no `param()` block, by design, because some RMM script runners mishandle them. Configuration lives in the variables at the top.

## Testing in a lab

Create harmless fakes on a lab VM (as administrator), run the script, and expect `HIT`:

```powershell
New-Item -ItemType Directory -Path 'C:\ProgramData\RelayTrap\trapbins\test' -Force | Out-Null
Set-Content 'C:\Windows\Temp\sckit-run.bat' 'rem fake'
Set-Content 'C:\Users\Public\RELAY-TRAP-PROOF.txt' 'fake'
schtasks /Create /TN TrapWatch /TR "cmd.exe /c exit" /SC ONCE /ST 23:59 /RU SYSTEM /F
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'RelayTrapLiteAlert' -Value 'cmd.exe /c exit' -PropertyType String -Force | Out-Null
New-Item -ItemType Directory -Path 'C:\Program Files (x86)\ScreenConnect Client (2588ef5c15954b10)' -Force | Out-Null
```

Cleanup:

```powershell
Remove-Item 'C:\ProgramData\RelayTrap' -Recurse -Force
Remove-Item 'C:\Windows\Temp\sckit-run.bat', 'C:\Users\Public\RELAY-TRAP-PROOF.txt' -Force
schtasks /Delete /TN TrapWatch /F
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'RelayTrapLiteAlert'
Remove-Item 'C:\Program Files (x86)\ScreenConnect Client (2588ef5c15954b10)' -Recurse -Force
```

The Security 4698 event for the fake TrapWatch task stays in the log for 30 days and will keep that one CRITICAL alive on the lab machine.

## Known limitations

- Detection only. Nothing is removed.
- Indicators are current as of 12 November 2026. The attacker infrastructure and rogue instance IDs will change; update the lists at the top of the script as new reporting lands.
- A client install from a different legitimate ScreenConnect server (a vendor's support tool, a co-managed IT provider) is flagged CRITICAL when your instance ID is supplied. That is intentional during an active campaign; confirm and document it rather than loosening the check.
- The panel side (Run Command history, Toolbox items, installed extensions such as RMM+) cannot be seen from the endpoint. Audit that separately.

## License

MIT. Use it, fork it, improve it. No warranty; verify against your own environment before relying on it.
