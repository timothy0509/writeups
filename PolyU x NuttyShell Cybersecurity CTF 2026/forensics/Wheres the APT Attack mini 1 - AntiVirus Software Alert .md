# Challenge 18 (Part 1) - Incident Response / SOC Analysis Write-up

## Challenge Overview
The challenge provides an Incident Response (IR) package hosted externally, protected by the password `infected`. The package contains a Windows memory image, event logs, and registry hives. 

**Objective:** Identify the following four pieces of information:
1. The time when the antivirus software protection was disabled (`DisableTime`).
2. The corresponding Event ID (`EventID`).
3. The Hostname of the infected machine (`HostName`).
4. The RAM dump file creation time (`SystemTime`).

**Flag Format:** `PUCTF26{DisableTime_EventID_HostName_SystemTime}`

---

## Solution Steps

### Step 1: Extracting the Artifacts
We downloaded the provided 7z archive from the external mirror and verified its SHA256 hash (`45fbe29bb5dc27ec8d32281e79a2203d2cdb888e8c06e09b2c77b8982c933847`). The archive was extracted using the provided password: `infected`.

This yielded a forensic image containing `.evtx` event logs, a raw memory dump (`hkctf-night01_memdump.mem`), and registry hive files.

### Step 2: Finding Antivirus Disablement (DisableTime & EventID) & Hostname
To find when the antivirus was disabled, we analyzed the Windows Event Logs. Specifically, we looked at the Windows Defender operational logs:
`Microsoft-Windows-Windows Defender%4Operational.evtx`

When Windows Defender's real-time protection is disabled, it logs **Event ID 5001**.
We parsed this log file and located the 5001 event. Extracting the XML data from this event provided two crucial pieces of information:
- **DisableTime:** The `<TimeCreated>` node showed `2026-02-26 15:58:36.709755+00:00`. We formatted this as `2026-02-26T15:58:36`.
- **Hostname:** The `<Computer>` tag in the event log explicitly listed the machine's hostname as `hkctf-night01`.

**Current findings:**
- DisableTime: `2026-02-26T15:58:36`
- EventID: `5001`
- HostName: `hkctf-night01`

### Step 3: Finding RAM Dump Creation Time (SystemTime)
Next, we needed to determine the exact time the memory dump was taken. We used **Volatility 3** to analyze the raw memory image (`hkctf-night01_memdump.mem`).

By running the `windows.info` plugin, Volatility scans for the `_KUSER_SHARED_DATA` structure, which contains global system information including the current system time at the moment the snapshot was taken.
The `SystemTime` parsed from the 64-bit `KSYSTEM_TIME` value in this structure gave us the creation time:
- **SystemTime:** `2026-02-26 16:12:32`

Formatted for the flag: `2026-02-26T16:12:32`

### Step 4: Assembling the Flag
With all four pieces of information recovered, we constructed the final flag according to the required format `PUCTF26{DisableTime_EventID_HostName_SystemTime}`:

**Flag:** `PUCTF26{2026-02-26T15:58:36_5001_hkctf-night01_2026-02-26T16:12:32}`