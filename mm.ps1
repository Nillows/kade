[CmdletBinding()]
param(
    # How often the screen refreshes
    [ValidateRange(2, 3600)]
    [int]$IntervalSeconds = 5,

    # How often a permanent CSV snapshot is written
    [ValidateRange(1, 1440)]
    [int]$LogIntervalMinutes = 5,

    # GDI/USER counters don't need to be queried every screen refresh
    [ValidateRange(5, 3600)]
    [int]$GuiRefreshSeconds = 30,

    [ValidateRange(5, 100)]
    [int]$TopMemory = 20,

    [ValidateRange(5, 100)]
    [int]$TopGrowth = 15,

    [string]$LogDirectory = "$env:USERPROFILE\Desktop\MemoryLeakMonitor"
)

# ---------------------------------------------------------------------------
# Native Windows APIs
#
# GetPerformanceInfo:
#   System-wide RAM, commit, kernel pools, handles, threads, process count.
#
# GetGuiResources:
#   Per-process GDI and USER object counts.
#
# This avoids continuously querying WMI/CIM.
# ---------------------------------------------------------------------------

if (-not ([System.Management.Automation.PSTypeName]'ResourceMonitorNative').Type) {

    Add-Type @"
using System;
using System.Runtime.InteropServices;

public static class ResourceMonitorNative
{
    [StructLayout(LayoutKind.Sequential)]
    public struct PERFORMANCE_INFORMATION
    {
        public uint cb;

        public UIntPtr CommitTotal;
        public UIntPtr CommitLimit;
        public UIntPtr CommitPeak;

        public UIntPtr PhysicalTotal;
        public UIntPtr PhysicalAvailable;

        public UIntPtr SystemCache;

        public UIntPtr KernelTotal;
        public UIntPtr KernelPaged;
        public UIntPtr KernelNonpaged;

        public UIntPtr PageSize;

        public uint HandleCount;
        public uint ProcessCount;
        public uint ThreadCount;
    }

    [DllImport("psapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetPerformanceInfo(
        out PERFORMANCE_INFORMATION pPerformanceInformation,
        uint cb
    );

    [DllImport("user32.dll", SetLastError = true)]
    public static extern uint GetGuiResources(
        IntPtr hProcess,
        uint uiFlags
    );
}
"@
}


# ---------------------------------------------------------------------------
# Read system-wide memory/resource information
# ---------------------------------------------------------------------------

function Get-SystemResourceInfo {

    $pi = New-Object ResourceMonitorNative+PERFORMANCE_INFORMATION

    $pi.cb = [Runtime.InteropServices.Marshal]::SizeOf($pi)

    $ok = [ResourceMonitorNative]::GetPerformanceInfo(
        [ref]$pi,
        $pi.cb
    )

    if (-not $ok) {
        throw "GetPerformanceInfo failed. Win32 error: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }

    $pageSize = [double]$pi.PageSize.ToUInt64()

    $physicalTotal     = [double]$pi.PhysicalTotal.ToUInt64()     * $pageSize
    $physicalAvailable = [double]$pi.PhysicalAvailable.ToUInt64() * $pageSize

    [pscustomobject]@{
        PhysicalTotalBytes     = $physicalTotal
        PhysicalAvailableBytes = $physicalAvailable
        PhysicalUsedBytes      = $physicalTotal - $physicalAvailable

        CommitBytes             = [double]$pi.CommitTotal.ToUInt64() * $pageSize
        CommitLimitBytes        = [double]$pi.CommitLimit.ToUInt64() * $pageSize
        CommitPeakBytes         = [double]$pi.CommitPeak.ToUInt64() * $pageSize

        SystemCacheBytes        = [double]$pi.SystemCache.ToUInt64() * $pageSize

        KernelTotalBytes        = [double]$pi.KernelTotal.ToUInt64() * $pageSize
        PagedPoolBytes          = [double]$pi.KernelPaged.ToUInt64() * $pageSize
        NonpagedPoolBytes       = [double]$pi.KernelNonpaged.ToUInt64() * $pageSize

        HandleCount             = [uint64]$pi.HandleCount
        ProcessCount            = [uint64]$pi.ProcessCount
        ThreadCount             = [uint64]$pi.ThreadCount
    }
}


# ---------------------------------------------------------------------------
# Setup logging
# ---------------------------------------------------------------------------

New-Item `
    -Path $LogDirectory `
    -ItemType Directory `
    -Force `
    -ErrorAction Stop |
    Out-Null

$sessionStart = Get-Date
$sessionTag   = $sessionStart.ToString("yyyyMMdd-HHmmss")

$systemLog = Join-Path `
    $LogDirectory `
    "system-$sessionTag.csv"

$processLog = Join-Path `
    $LogDirectory `
    "processes-$sessionTag.csv"


# ---------------------------------------------------------------------------
# Internal state
# ---------------------------------------------------------------------------

$baseline = @{}
$previous = @{}
$guiCache = @{}

$systemBaseline = $null

$lastLog = [datetime]::MinValue
$snapshotNumber = 0


try {

    [Console]::CursorVisible = $false

    try {
        $Host.UI.RawUI.WindowTitle = "Windows Memory Leak Monitor v2"
    }
    catch {
    }


    while ($true) {

        $now = Get-Date

        # First iteration logs immediately.
        # Subsequent snapshots occur every LogIntervalMinutes.
        $logDue =
            ($lastLog -eq [datetime]::MinValue) -or
            (($now - $lastLog).TotalMinutes -ge $LogIntervalMinutes)


        # ===================================================================
        # SYSTEM-WIDE RESOURCES
        # ===================================================================

        $sys = Get-SystemResourceInfo

        if ($null -eq $systemBaseline) {
            $systemBaseline = $sys
        }


        # ===================================================================
        # PROCESS RESOURCES
        # ===================================================================

        $current = @{}

        $rows = @(
            foreach ($p in Get-Process -ErrorAction SilentlyContinue) {

                try {

                    $name = $p.ProcessName
                    $pidNumber = $p.Id


                    # -------------------------------------------------------
                    # Build a process identity that survives PID reuse.
                    # -------------------------------------------------------

                    try {
                        $startTime = $p.StartTime

                        $key = "{0}:{1}" -f `
                            $pidNumber,
                            $startTime.ToUniversalTime().Ticks
                    }
                    catch {
                        $startTime = $null

                        $key = "{0}:{1}" -f `
                            $pidNumber,
                            $name
                    }


                    # -------------------------------------------------------
                    # Standard process memory/resources
                    # -------------------------------------------------------

                    $privateMB = [double]$p.PrivateMemorySize64 / 1MB
                    $workingMB = [double]$p.WorkingSet64 / 1MB

                    $handles = $p.HandleCount

                    try {
                        $threads = $p.Threads.Count
                    }
                    catch {
                        $threads = $null
                    }


                    # -------------------------------------------------------
                    # GDI + USER resources
                    #
                    # GDI:
                    #   Bitmaps, brushes, pens, fonts, device contexts, etc.
                    #
                    # USER:
                    #   Windows, menus, cursors, hooks and other USER32
                    #   resources.
                    #
                    # Refresh these less frequently to reduce overhead.
                    # A CSV snapshot always forces a fresh reading.
                    # -------------------------------------------------------

                    $refreshGui = $false

                    if (-not $guiCache.ContainsKey($key)) {
                        $refreshGui = $true
                    }
                    elseif (
                        ($now - $guiCache[$key].Updated).TotalSeconds `
                            -ge $GuiRefreshSeconds
                    ) {
                        $refreshGui = $true
                    }
                    elseif ($logDue) {
                        $refreshGui = $true
                    }


                    if ($refreshGui) {

                        try {

                            $processHandle = $p.Handle

                            $gdiObjects = [ResourceMonitorNative]::GetGuiResources(
                                $processHandle,
                                0
                            )

                            $userObjects = [ResourceMonitorNative]::GetGuiResources(
                                $processHandle,
                                1
                            )

                            $guiCache[$key] = @{
                                GDI     = [int64]$gdiObjects
                                USER    = [int64]$userObjects
                                Updated = $now
                            }
                        }
                        catch {

                            $guiCache[$key] = @{
                                GDI     = $null
                                USER    = $null
                                Updated = $now
                            }
                        }
                    }


                    $gdi  = $guiCache[$key].GDI
                    $user = $guiCache[$key].USER


                    # -------------------------------------------------------
                    # Baseline when this particular process first appeared
                    # -------------------------------------------------------

                    if (-not $baseline.ContainsKey($key)) {

                        $baseline[$key] = @{
                            PrivateMB = $privateMB
                            Handles   = $handles
                            GDI       = $gdi
                            USER      = $user
                            FirstSeen = $now
                        }
                    }


                    # If GUI data wasn't accessible on the first pass but
                    # becomes available later, establish the GUI baseline then.
                    if (
                        ($null -eq $baseline[$key].GDI) -and
                        ($null -ne $gdi)
                    ) {
                        $baseline[$key].GDI = $gdi
                    }

                    if (
                        ($null -eq $baseline[$key].USER) -and
                        ($null -ne $user)
                    ) {
                        $baseline[$key].USER = $user
                    }


                    # -------------------------------------------------------
                    # Change since previous refresh
                    # -------------------------------------------------------

                    if ($previous.ContainsKey($key)) {

                        $deltaMB =
                            $privateMB -
                            $previous[$key].PrivateMB

                        $handleDelta =
                            $handles -
                            $previous[$key].Handles
                    }
                    else {
                        $deltaMB = 0
                        $handleDelta = 0
                    }


                    # -------------------------------------------------------
                    # Cumulative growth since this process was first observed
                    # -------------------------------------------------------

                    $growthMB =
                        $privateMB -
                        $baseline[$key].PrivateMB

                    $handleGrowth =
                        $handles -
                        $baseline[$key].Handles


                    if (
                        ($null -ne $gdi) -and
                        ($null -ne $baseline[$key].GDI)
                    ) {
                        $gdiGrowth =
                            $gdi -
                            $baseline[$key].GDI
                    }
                    else {
                        $gdiGrowth = $null
                    }


                    if (
                        ($null -ne $user) -and
                        ($null -ne $baseline[$key].USER)
                    ) {
                        $userGrowth =
                            $user -
                            $baseline[$key].USER
                    }
                    else {
                        $userGrowth = $null
                    }


                    # -------------------------------------------------------
                    # Approximate rate of memory growth
                    #
                    # Don't calculate it until the process has been monitored
                    # for at least five minutes; very short-term rates are
                    # misleading.
                    # -------------------------------------------------------

                    $hoursObserved =
                        ($now - $baseline[$key].FirstSeen).TotalHours

                    if ($hoursObserved -ge (5.0 / 60.0)) {

                        $mbPerHour =
                            $growthMB /
                            $hoursObserved
                    }
                    else {
                        $mbPerHour = $null
                    }


                    # Data retained only until the next refresh.
                    $current[$key] = @{
                        PrivateMB = $privateMB
                        Handles   = $handles
                    }


                    [pscustomobject]@{

                        Name = $name
                        PID  = $pidNumber

                        StartTime = if ($null -ne $startTime) {
                            $startTime.ToString("yyyy-MM-dd HH:mm:ss")
                        }
                        else {
                            ""
                        }

                        FirstSeen =
                            $baseline[$key].FirstSeen.ToString(
                                "yyyy-MM-dd HH:mm:ss"
                            )

                        PrivateMB =
                            [math]::Round($privateMB, 1)

                        WorkingMB =
                            [math]::Round($workingMB, 1)

                        DeltaMB =
                            [math]::Round($deltaMB, 1)

                        GrowthMB =
                            [math]::Round($growthMB, 1)

                        MBperHour = if ($null -ne $mbPerHour) {
                            [math]::Round($mbPerHour, 1)
                        }
                        else {
                            $null
                        }

                        Handles = $handles

                        HandleDelta = $handleDelta

                        HandleGrowth = $handleGrowth

                        GDI = $gdi

                        GDIGrowth = $gdiGrowth

                        USER = $user

                        USERGrowth = $userGrowth

                        Threads = $threads

                        ProcessKey = $key
                    }
                }

                catch {
                    # Process may have exited or access may have been denied
                    # while we were reading it.
                }

                finally {

                    # If obtaining p.Handle caused .NET to open a process
                    # handle, explicitly release it rather than waiting for
                    # garbage collection.
                    try {
                        $p.Dispose()
                    }
                    catch {
                    }
                }
            }
        )


        # ===================================================================
        # PRUNE EXITED PROCESSES
        #
        # Prevents this monitor itself from slowly accumulating historical
        # entries as applications start and stop.
        # ===================================================================

        foreach ($key in @($baseline.Keys)) {

            if (-not $current.ContainsKey($key)) {
                $baseline.Remove($key)
                $guiCache.Remove($key)
            }
        }


        # ===================================================================
        # CALCULATE SYSTEM NUMBERS
        # ===================================================================

        $ramUsedGB  = $sys.PhysicalUsedBytes / 1GB
        $ramTotalGB = $sys.PhysicalTotalBytes / 1GB
        $ramFreeGB  = $sys.PhysicalAvailableBytes / 1GB

        if ($sys.PhysicalTotalBytes -gt 0) {
            $ramPct =
                100 *
                $sys.PhysicalUsedBytes /
                $sys.PhysicalTotalBytes
        }
        else {
            $ramPct = 0
        }


        $commitGB      = $sys.CommitBytes / 1GB
        $commitLimitGB = $sys.CommitLimitBytes / 1GB
        $commitPeakGB  = $sys.CommitPeakBytes / 1GB

        if ($sys.CommitLimitBytes -gt 0) {
            $commitPct =
                100 *
                $sys.CommitBytes /
                $sys.CommitLimitBytes
        }
        else {
            $commitPct = 0
        }


        $pagedMB =
            $sys.PagedPoolBytes / 1MB

        $nonpagedMB =
            $sys.NonpagedPoolBytes / 1MB


        # Growth since this monitoring session started

        $commitGrowthGB =
            ($sys.CommitBytes -
             $systemBaseline.CommitBytes) / 1GB

        $pagedGrowthMB =
            ($sys.PagedPoolBytes -
             $systemBaseline.PagedPoolBytes) / 1MB

        $nonpagedGrowthMB =
            ($sys.NonpagedPoolBytes -
             $systemBaseline.NonpagedPoolBytes) / 1MB

        $systemHandleGrowth =
            [int64]$sys.HandleCount -
            [int64]$systemBaseline.HandleCount


        # ===================================================================
        # DISPLAY
        # ===================================================================

        Clear-Host

        Write-Host "WINDOWS MEMORY / RESOURCE LEAK MONITOR v2"
        Write-Host (
            "Updated: {0}   Runtime: {1:N1} min   Refresh: {2}s   Ctrl+C to quit" `
            -f `
            $now.ToString("yyyy-MM-dd HH:mm:ss"),
            ($now - $sessionStart).TotalMinutes,
            $IntervalSeconds
        )

        Write-Host ("=" * 118)


        Write-Host (
            "RAM:       {0,6:N1} / {1:N1} GB used ({2:N1}%)   Free: {3:N1} GB" `
            -f `
            $ramUsedGB,
            $ramTotalGB,
            $ramPct,
            $ramFreeGB
        )


        Write-Host (
            "Commit:    {0,6:N1} / {1:N1} GB ({2:N1}%)   Peak: {3:N1} GB   Since start: {4:+0.0;-0.0;0.0} GB" `
            -f `
            $commitGB,
            $commitLimitGB,
            $commitPct,
            $commitPeakGB,
            $commitGrowthGB
        )


        Write-Host (
            "Pools:     Paged {0:N0} MB ({1:+0;-0;0})   Nonpaged {2:N0} MB ({3:+0;-0;0})" `
            -f `
            $pagedMB,
            $pagedGrowthMB,
            $nonpagedMB,
            $nonpagedGrowthMB
        )


        Write-Host (
            "Objects:   Handles {0:N0} ({1:+0;-0;0})   Processes {2:N0}   Threads {3:N0}" `
            -f `
            $sys.HandleCount,
            $systemHandleGrowth,
            $sys.ProcessCount,
            $sys.ThreadCount
        )


        Write-Host (
            "Logging:   Every {0} min -> {1}" `
            -f `
            $LogIntervalMinutes,
            $LogDirectory
        )


        Write-Host ""
        Write-Host "TOP PROCESSES BY PRIVATE MEMORY"
        Write-Host ""

        $rows |
            Sort-Object PrivateMB -Descending |
            Select-Object -First $TopMemory `
                Name,
                PID,
                PrivateMB,
                WorkingMB,
                GrowthMB,
                Handles,
                GDI,
                USER,
                Threads |
            Format-Table -AutoSize


        Write-Host ""
        Write-Host "FASTEST-GROWING PROCESSES SINCE FIRST OBSERVED"
        Write-Host ""

        $rows |
            Sort-Object GrowthMB -Descending |
            Select-Object -First $TopGrowth `
                Name,
                PID,
                PrivateMB,
                GrowthMB,
                MBperHour,
                Handles,
                HandleGrowth,
                GDI,
                GDIGrowth,
                USER,
                USERGrowth |
            Format-Table -AutoSize


        # ===================================================================
        # FIVE-MINUTE SNAPSHOT LOGGING
        # ===================================================================

        if ($logDue) {

            $snapshotNumber++


            # ---------------------------------------------------------------
            # System log -- one row per snapshot
            # ---------------------------------------------------------------

            [pscustomobject]@{

                Timestamp =
                    $now.ToString("yyyy-MM-dd HH:mm:ss")

                Snapshot =
                    $snapshotNumber

                MonitorRuntimeMinutes =
                    [math]::Round(
                        ($now - $sessionStart).TotalMinutes,
                        1
                    )

                RAMUsedGB =
                    [math]::Round($ramUsedGB, 3)

                RAMTotalGB =
                    [math]::Round($ramTotalGB, 3)

                RAMFreeGB =
                    [math]::Round($ramFreeGB, 3)

                RAMPct =
                    [math]::Round($ramPct, 1)

                CommitGB =
                    [math]::Round($commitGB, 3)

                CommitLimitGB =
                    [math]::Round($commitLimitGB, 3)

                CommitPct =
                    [math]::Round($commitPct, 1)

                CommitPeakGB =
                    [math]::Round($commitPeakGB, 3)

                CommitGrowthGB =
                    [math]::Round($commitGrowthGB, 3)

                PagedPoolMB =
                    [math]::Round($pagedMB, 1)

                PagedPoolGrowthMB =
                    [math]::Round($pagedGrowthMB, 1)

                NonpagedPoolMB =
                    [math]::Round($nonpagedMB, 1)

                NonpagedPoolGrowthMB =
                    [math]::Round($nonpagedGrowthMB, 1)

                SystemCacheMB =
                    [math]::Round(
                        $sys.SystemCacheBytes / 1MB,
                        1
                    )

                Handles =
                    $sys.HandleCount

                HandleGrowth =
                    $systemHandleGrowth

                Processes =
                    $sys.ProcessCount

                Threads =
                    $sys.ThreadCount
            } |
                Export-Csv `
                    -Path $systemLog `
                    -Append `
                    -NoTypeInformation


            # ---------------------------------------------------------------
            # Process log
            #
            # Every running process receives one row per snapshot.
            # ---------------------------------------------------------------

            $rows |
                Select-Object `
                    @{N='Timestamp'; E={$now.ToString("yyyy-MM-dd HH:mm:ss")}},
                    @{N='Snapshot'; E={$snapshotNumber}},
                    Name,
                    PID,
                    StartTime,
                    FirstSeen,
                    PrivateMB,
                    WorkingMB,
                    DeltaMB,
                    GrowthMB,
                    MBperHour,
                    Handles,
                    HandleDelta,
                    HandleGrowth,
                    GDI,
                    GDIGrowth,
                    USER,
                    USERGrowth,
                    Threads,
                    ProcessKey |
                Export-Csv `
                    -Path $processLog `
                    -Append `
                    -NoTypeInformation


            $lastLog = $now
        }


        # Previous refresh only.
        # Replacing this hashtable prevents unbounded accumulation.
        $previous = $current


        Start-Sleep -Seconds $IntervalSeconds
    }
}

finally {

    [Console]::CursorVisible = $true

    Write-Host ""
    Write-Host "Monitor stopped."
    Write-Host "System log:  $systemLog"
    Write-Host "Process log: $processLog"
}