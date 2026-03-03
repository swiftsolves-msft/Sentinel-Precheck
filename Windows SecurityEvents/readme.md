# Measure SecurityEvents from Windows Server

Leverage the following PowerShell script to collect locally on the the Windows Server 

## Measure-SecurityEvents.ps1

```
<#
.SYNOPSIS
    Microsoft Sentinel - Windows Security Event Log Sizer
    Parameterized version - run with -Collection Minimal / Common / All

.EXAMPLE
    .\SentinelSizer.ps1 -Collection All
    .\SentinelSizer.ps1 -Collection Minimal
    .\SentinelSizer.ps1 -Collection Common
#>

param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("Minimal", "Common", "All")]
    [string]$Collection = "All"
)

# ================== EVENT ID LISTS & SETTINGS =================
$daysBack = 1
$ids = $null

switch ($Collection) {
    "Minimal" {
        Write-Host "=== Minimal Collection (Microsoft Sentinel recommended - Security log only) ===" -ForegroundColor Cyan
        $ids = 1102,4624,4625,4657,4663,4688,4700,4702,4719,4720,4722,4723,4724,4727,4728,4732,4735,4737,4739,4740,4754,4755,4756,4767,4799,4825,4946,4948,4956,5024,5033
        $daysBack = 7
    }
    "Common" {
        Write-Host "=== Common Collection (Microsoft Sentinel recommended - full) ===" -ForegroundColor Cyan
        $ids = 1,299,300,324,340,403,404,410,411,412,413,431,500,501,1100,1102,1107,1108,4608,4610,4611,4614,4622,4624,4625,4634,4647,4648,4649,4657,4661,4662,4663,4665,4666,4667,4688,4670,4672,4673,4674,4675,4689,4697,4700,4702,4704,4705,4716,4717,4718,4719,4720,4722,4723,4724,4725,4726,4727,4728,4729,4733,4732,4735,4737,4738,4739,4740,4742,4744,4745,4746,4750,4751,4752,4754,4755,4756,4757,4760,4761,4762,4764,4767,4768,4771,4774,4778,4779,4781,4793,4797,4798,4799,4800,4801,4802,4803,4825,4826,4870,4886,4887,4888,4893,4898,4902,4904,4905,4907,4931,4932,4933,4946,4948,4956,4985,5024,5033,5059,5136,5137,5140,5145,5632,6144,6145,6272,6273,6278,6416,6423,6424,8001,8002,8003,8004,8005,8006,8007,8222,26401,30004
        $daysBack = 7
    }
    "All" {
        Write-Host "=== All Security Events (NO ID filtering - every event in the log) ===" -ForegroundColor Cyan
        $daysBack = 1
    }
}

# ================== EVENT COLLECTION =================
Write-Host "`nCollecting events from Security log to analyze present Event Ids, final Output will be Daily GB (last $daysBack day(s))..." -ForegroundColor Cyan

if ($Collection -eq "All") {
    # Single fast query - no ID filter
    $events = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        StartTime = (Get-Date).AddDays(-$daysBack)
    } -ErrorAction SilentlyContinue

} else {
    # Bulletproof per-ID query (handles AppLocker IDs that don't exist)
    $allEvents = @()
    foreach ($id in $ids) {
        $single = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = $id
            StartTime = (Get-Date).AddDays(-$daysBack)
        } -ErrorAction SilentlyContinue
        $allEvents += if ($null -eq $single) { @() } else { $single }
    }
    $events = $allEvents
}

$events = if ($null -eq $events) { @() } else { $events }
$eventsPerDay = $events.Count
$dailyAverage = if ($daysBack -gt 0) { [math]::Round($eventsPerDay / $daysBack, 0) } else { 0 }

Write-Host "✅ Total events found : $eventsPerDay" -ForegroundColor Green
Write-Host "📅 Average per day   : ~$dailyAverage events/day" -ForegroundColor Green

# ================== ZERO-EVENT REPORT (only for Minimal/Common) =================
if ($Collection -ne "All" -and $ids) {
    $eventCounts = @{}
    $events | Group-Object Id | ForEach-Object { $eventCounts[$_.Name] = $_.Count }
    $zeroIDs = $ids | Where-Object { $eventCounts[$_] -eq 0 } | Sort-Object

    if ($zeroIDs.Count -gt 0) {
        Write-Host "`n⚠️  Event IDs with ZERO events:" -ForegroundColor Yellow
        $zeroIDs | ForEach-Object { Write-Host "   • $_" -ForegroundColor Yellow }
        Write-Host "`n(Note: 8001-8222 are AppLocker events and will always be zero in Security log)" -ForegroundColor DarkYellow
    }
}

# ================== SIZE CALCULATION (JSON for AMA/Sentinel) =================
if ($events.Count -gt 0) {
    Write-Host "`nCalculating average event size (JSON - accurate for Sentinel)..." -ForegroundColor Cyan

    # Sample up to 5000 events for speed (still extremely accurate)
    $sample = if ($events.Count -gt 5000) { $events | Get-Random -Count 5000 } else { $events }

    $sizeStats = $sample | ForEach-Object {
        $jsonSize = (ConvertTo-Json -InputObject $_ -Depth 10 -Compress).Length
        [PSCustomObject]@{ JsonBytes = $jsonSize }
    }

    $avgJsonBytes = ($sizeStats.JsonBytes | Measure-Object -Average).Average
    $avgKB        = [math]::Round($avgJsonBytes / 1KB, 2)

    Write-Host "Average event size : $avgKB KB" -ForegroundColor Green

    # ================== FINAL SENTINEL ESTIMATE =================
    $gbPerDay  = ($eventsPerDay / $daysBack * $avgKB) / 1MB
    $gbRounded = [math]::Round($gbPerDay, 2)

    Write-Host "`n========================================" -ForegroundColor Magenta
    Write-Host "📊 SENTINEL ESTIMATE - $Collection Collection" -ForegroundColor Magenta
    Write-Host "========================================" -ForegroundColor Magenta
    Write-Host "Events per day       : ~$dailyAverage" -ForegroundColor White
    Write-Host "Avg size per event   : $avgKB KB" -ForegroundColor White
    Write-Host "Daily ingestion      : $gbRounded GB/day" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Magenta

    Write-Host "`nTip: After ingestion, use this KQL for real billed size:" -ForegroundColor Gray
    Write-Host "SecurityEvent | summarize AvgBilledBytes = avg(_BilledSize) by EventID" -ForegroundColor Gray
} else {
    Write-Host "`nNo events found in the last $daysBack day(s)." -ForegroundColor Yellow
}

Write-Host "`nScript complete. Re-run with: -Collection Minimal / Common / All" -ForegroundColor Gray
```

Once completed you can use the following KQL query a **week later** after data is collected to analyze it's ingestion:

```
SecurityEvent
| where TimeGenerated > ago(7d) // ← Change 7d to 1d / 30d / etc. as needed
// ================== ADD YOUR COMPUTER FILTER HERE ==================
| where Computer contains "YOUR COMPUTER NAME HERE" // ← EDIT THIS LINE
// Examples:
// | where Computer == "DC01.contoso.com"
// | where Computer startswith "WEB"
// | where Computer in ("SRV01", "SRV02", "SRV03")
// | where Computer matches regex "WEB-.*"
// ==================================================================
| summarize
TotalEvents = count(),
AvgBilledBytes = avg(_BilledSize)
by EventID
| extend
EventsPerDay = TotalEvents / 7.0,
GBPerDay = (TotalEvents / 7.0 * AvgBilledBytes) / (1024 * 1024 * 1024) // ← FIXED: explicit bytes instead of 1GB
| project
EventID,
TotalEvents,
EventsPerDay = round(EventsPerDay, 2),
AvgBilledBytes = round(AvgBilledBytes, 0),
GBPerDay = round(GBPerDay, 4)
| order by GBPerDay desc
```

If you want a all up number GBsPerDay per Server:

```
SecurityEvent
| where TimeGenerated > ago(7d) // ← Change 7d to 1d / 30d / 90d etc. as needed
// ================== EDIT COMPUTER FILTER HERE ==================
| where Computer contains "YOUR COMPUTER NAME HERE" // ← CHANGE THIS LINE
// Examples:
// | where Computer == "DC01.contoso.com"
// | where Computer startswith "WEB"
// | where Computer in ("SRV01", "SRV02", "APP01")
// ==================================================================
| summarize
TotalEvents = count(),
TotalBilledBytes = sum(_BilledSize), // Most accurate for billing
AvgBilledBytes = avg(_BilledSize)
by Computer
| extend DaysObserved = 7.0 // ← Fixed: separate extend step
| extend
EventsPerDay = TotalEvents / DaysObserved,
GBPerDay = TotalBilledBytes / (DaysObserved * 1024 * 1024 * 1024)
| project
Computer,
TotalEvents,
EventsPerDay = round(EventsPerDay, 0),
AvgEventSizeKB = round(AvgBilledBytes / 1024, 2),
TotalGB_Last7d = round(TotalBilledBytes / (1024*1024*1024), 3),
EstimatedGBPerDay = round(GBPerDay, 4) // ← THIS IS YOUR DAILY TOTAL
| order by EstimatedGBPerDay desc
```
