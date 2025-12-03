# check_so_page_size_full_with_progress.ps1
# Full diagnostic scanner with progress indicators (Option D)

# -------------------------------
# Configurations - EDIT THESE
# -------------------------------
$readelf = "D:\AndroidStudioSDK\Sdk\ndk\29.0.14206865\toolchains\llvm\prebuilt\windows-x86_64\bin\llvm-readelf.exe"
$apkExtractRoot = "D:\stc-work\project\ir-android\ir-mobile-android\app\Production\release\universal_extracted"
$reportFile = "D:\stc-work\16kb-issue\output\so_page_size_report.txt"

# nested archive extraction depth
$maxNestedDepth = 2

# dex search patterns
$dexPatterns = @(
    "JNI_OnLoad",
    "RegisterNatives",
    "System.loadLibrary",
    "System.load",
    "dlopen",
    "native ",
    "JNIEXPORT",
    "JNINativeMethod"
)

# file signatures
$signatures = @{
    "ELF"  = [byte[]](0x7F,0x45,0x4C,0x46)
    "ZIP"  = [byte[]](0x50,0x4B,0x03,0x04)
    "GZIP" = [byte[]](0x1F,0x8B)
    "LZ4"  = [byte[]](0x04,0x22,0x4D,0x18)
    "XZ"   = [byte[]](0xFD,0x37,0x7A,0x58)
}

# -------------------------------
# Pre-checks & setup
# -------------------------------
if (-not (Test-Path $apkExtractRoot)) {
    Write-Error "apkExtractRoot does not exist: $apkExtractRoot"
    return
}

$reportDir = Split-Path -Parent $reportFile
if (-not (Test-Path $reportDir)) { New-Item -ItemType Directory -Path $reportDir -Force | Out-Null }

# remove previous report
if (Test-Path $reportFile) { Remove-Item $reportFile -Force }

# write header
Add-Content -Path $reportFile -Value ("Scan started: " + (Get-Date).ToString("o"))
Add-Content -Path $reportFile -Value ("Root: " + $apkExtractRoot)
Add-Content -Path $reportFile -Value ""

Write-Host "Starting enhanced diagnostic scan (with progress)..." -ForegroundColor Cyan

# -------------------------------
# Counters & trackers
# -------------------------------
$script:totalSoFiles   = 0
$script:count4KB      = 0
$script:count16KB     = 0
$script:totalArchives = 0
$script:possibleNativeFiles = 0
$script:hiddenElfCount = 0
$script:scannedDexFiles = 0
$script:dexMatches = 0
$script:scannedExtensions = New-Object System.Collections.Generic.HashSet[string]

# temp workspace
$tempRoot = Join-Path $env:TEMP ("apk_scan_" + [System.Guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $tempRoot | Out-Null

# try load compression assembly
try { Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue } catch {}

# spinner chars
$spinner = @("|","/","-","\") 
$spinIndex = 0

# small helper to update spinner
function Get-Spinner { 
    $global:spinIndex = ($global:spinIndex + 1) % $spinner.Length
    return $spinner[$global:spinIndex]
}

# write log function
function Write-Log {
    param([string]$msg, [ConsoleColor]$color = "White")
    Write-Host $msg -ForegroundColor $color
    Add-Content -Path $reportFile -Value $msg
}

# read header bytes
function Read-FileHeader {
    param([string]$path, [int]$count = 8)
    try {
        $bytes = Get-Content -Path $path -Encoding Byte -TotalCount $count -ErrorAction Stop
        return ,$bytes
    } catch {
        return $null
    }
}

# signature match
function Match-Signature {
    param([byte[]]$buf, [byte[]]$sig)
    if (-not $buf) { return $false }
    if ($buf.Length -lt $sig.Length) { return $false }
    for ($i=0; $i -lt $sig.Length; $i++) {
        if ($buf[$i] -ne $sig[$i]) { return $false }
    }
    return $true
}

# run readelf safely
function Run-Readelf {
    param([string]$soPath)
    try {
        $out = & "$readelf" $soPath 2>&1
        return $out
    } catch {
        $ex = $_
        return @("ERROR: readelf failed: " + $ex.Exception.Message)
    }
}

# check .so and update counters
function Check-SoFile {
    param([string]$soPath, [string]$parentArchive = "")

    if (-not (Test-Path $soPath)) {
        Write-Log ("[SKIP] missing: " + $soPath) "Yellow"
        return
    }

    $script:totalSoFiles++
    try {
        $ext = (Get-Item $soPath).Extension
        $script:scannedExtensions.Add($ext) | Out-Null
    } catch {}

    $label = if ($parentArchive) { "[SO] " + $soPath + " (inside " + $parentArchive + ")" } else { "[SO] " + $soPath }
    Write-Log $label "Cyan"

    $out = Run-Readelf $soPath

    $requires16KB = $false
    foreach ($line in $out) {
        if ($line -match "0x4000") { $requires16KB = $true; break }
    }

    if ($requires16KB) {
        Write-Log ("[16KB] " + $soPath) "Red"
        $script:count16KB++
    } else {
        Write-Log ("[4KB]  " + $soPath) "Green"
        $script:count4KB++
    }

    # append readelf output to report (optional)
    Add-Content -Path $reportFile -Value ("--- readelf for: " + $soPath)
    Add-Content -Path $reportFile -Value ($out -join "`n")
    Add-Content -Path $reportFile -Value ""
}

# extract archive -> destDir, return $true/$false
function Extract-Archive-To {
    param([string]$archivePath, [string]$destDir)
    try {
        if (Get-Command Expand-Archive -ErrorAction SilentlyContinue) {
            Expand-Archive -LiteralPath $archivePath -DestinationPath $destDir -Force -ErrorAction Stop
        } else {
            [System.IO.Compression.ZipFile]::ExtractToDirectory($archivePath, $destDir)
        }
        return $true
    } catch {
        $ex = $_
        Write-Log ("[ERROR] Failed to extract " + $archivePath + ": " + $ex.Exception.Message) "Yellow"
        return $false
    }
}

# Scan a folder (non-recursively) for .so and archives, recursively scanning extracted archives when found
function Scan-Folder-For-Native {
    param([string]$folder, [int]$depth = 0)

    if ($depth -gt $maxNestedDepth) { return }

    Write-Log ("[DIR] " + $folder) "Magenta"

    # direct .so files in this folder (non-recursive)
    $soFiles = Get-ChildItem -Path $folder -Filter *.so -File -ErrorAction SilentlyContinue
    $i = 0
    $total = $soFiles.Count
    foreach ($s in $soFiles) {
        $i++
        $pct = [int](($i / [double]($total) * 100))
        Write-Progress -Activity "Scanning .so in folder" -Status (Get-Spinner) -PercentComplete $pct -CurrentOperation $s.FullName
        Check-SoFile $s.FullName
    }

    # archives within this folder (non-recursive)
    $archives = Get-ChildItem -Path $folder -Include *.jar,*.aar,*.zip -File -ErrorAction SilentlyContinue
    $j = 0
    $totalA = $archives.Count
    foreach ($a in $archives) {
        $j++
        $pctA = [int](($j / [double]($totalA) * 100))
        Write-Progress -Activity "Processing archives in folder" -Status (Get-Spinner) -PercentComplete $pctA -CurrentOperation $a.FullName

        $script:totalArchives++
        Write-Log ("[ARCHIVE FOUND] " + $a.FullName) "Cyan"

        $tmp = Join-Path $tempRoot ([System.Guid]::NewGuid().ToString())
        New-Item -ItemType Directory -Path $tmp | Out-Null
        $ok = Extract-Archive-To $a.FullName $tmp
        if ($ok) {
            # scan extracted folder recursively for .so and nested archives
            Scan-Folder-For-Native $tmp ($depth + 1)
        }
        Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }

    # clear progress when finishing folder
    Write-Progress -Activity "Scanning .so in folder" -Completed
}

# detect signatures by reading header
function Detect-CompressedContainers {
    param([string]$filePath)
    $hdr = Read-FileHeader $filePath 16
    if (-not $hdr) { return $null }

    foreach ($k in $signatures.Keys) {
        $sig = $signatures[$k]
        if (Match-Signature $hdr $sig) { return $k }
    }

    # scan first 4k bytes for PK (embedded zip)
    try {
        $raw = Get-Content -Path $filePath -Encoding Byte -TotalCount 4096 -ErrorAction SilentlyContinue
        for ($i=0; $i -lt ($raw.Length - 1); $i++) {
            if ($raw[$i] -eq 0x50 -and $raw[$i+1] -eq 0x4B) { return "ZIP-EMBED" }
        }
    } catch {}

    return $null
}

# analyze an arbitrary file for embedded ELF or containers
function Analyze-ArbitraryFile {
    param([string]$filePath)

    $script:possibleNativeFiles++
    Write-Log ("[ANALYZE] " + $filePath) "Yellow"

    try {
        $container = Detect-CompressedContainers $filePath
        if ($container -eq "ELF") {
            $script:hiddenElfCount++
            Write-Log ("[HIDDEN ELF] raw ELF magic in " + $filePath) "Magenta"
            Check-SoFile $filePath "[HIDDEN ELF]"
            return
        } elseif ($container -in @("ZIP","ZIP-EMBED")) {
            Write-Log ("[ZIP] Attempt extracting embedded zip from " + $filePath) "Yellow"
            $tmp = Join-Path $tempRoot ([System.Guid]::NewGuid().ToString())
            New-Item -ItemType Directory -Path $tmp | Out-Null
            $ok = $false
            if ($container -eq "ZIP") {
                $ok = Extract-Archive-To $filePath $tmp
            } else {
                # attempt to copy and open as zip
                $tmpZip = Join-Path $tmp "embedded.zip"
                Copy-Item -Path $filePath -Destination $tmpZip -Force
                $ok = Extract-Archive-To $tmpZip $tmp
            }
            if ($ok) { Scan-Folder-For-Native $tmp 0 }
            Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
            return
        } elseif ($container -in @("GZIP")) {
            Write-Log ("[GZIP] Attempt decompress: " + $filePath) "Yellow"
            $tmpOut = Join-Path $tempRoot ([System.Guid]::NewGuid().ToString() + ".bin")
            try {
                $inStream = [System.IO.File]::OpenRead($filePath)
                $gz = New-Object System.IO.Compression.GzipStream($inStream, [System.IO.Compression.CompressionMode]::Decompress)
                $outFs = [System.IO.File]::OpenWrite($tmpOut)
                $buffer = New-Object byte[] 8192
                while (($read = $gz.Read($buffer,0,$buffer.Length)) -gt 0) {
                    $outFs.Write($buffer,0,$read)
                }
                $gz.Close(); $inStream.Close(); $outFs.Close()
                Scan-Folder-For-Native (Split-Path $tmpOut -Parent) 0
                Remove-Item $tmpOut -Force -ErrorAction SilentlyContinue
            } catch {
                $ex = $_
                Write-Log ("[ERROR] gzip decompress failed: " + $filePath + " (" + $ex.Exception.Message + ")") "Yellow"
            }
            return
        } else {
            # scan first 128KB for embedded ELF
            try {
                $raw = Get-Content -Path $filePath -Encoding Byte -TotalCount 131072 -ErrorAction SilentlyContinue
                for ($i=0; $i -lt ($raw.Length - 4); $i++) {
                    if ($raw[$i] -eq 0x7F -and $raw[$i+1] -eq 0x45 -and $raw[$i+2] -eq 0x4C -and $raw[$i+3] -eq 0x46) {
                        Write-Log ("[EMBEDDED ELF] offset " + $i + " in " + $filePath) "Magenta"
                        $tmpFile = Join-Path $tempRoot ("embedded_" + [System.Guid]::NewGuid().ToString() + ".so")
                        $fs = [System.IO.File]::OpenWrite($tmpFile)
                        $fs.Write($raw, $i, $raw.Length - $i)
                        $fs.Close()
                        Check-SoFile $tmpFile ("[EMBEDDED in " + (Split-Path $filePath -Leaf) + "]")
                        Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue
                        break
                    }
                }
            } catch {
                $ex = $_
                Write-Log ("[ERROR] could not inspect bytes: " + $filePath + " (" + $ex.Exception.Message + ")") "Yellow"
            }
        }
    } catch {
        $ex = $_
        Write-Log ("[ERROR] Analyze failed: " + $filePath + " (" + $ex.Exception.Message + ")") "Yellow"
    }
}

# scan dex for JNI strings
function Scan-Dex-For-JNI {
    param([string]$dexPath)
    if (-not (Test-Path $dexPath)) { return }
    $script:scannedDexFiles++
    Write-Log ("[DEX] Scanning: " + $dexPath) "Cyan"

    foreach ($p in $dexPatterns) {
        # try Select-String first
        try {
            $matches = Select-String -Path $dexPath -Pattern $p -SimpleMatch -ErrorAction SilentlyContinue
            if ($matches) {
                foreach ($m in $matches) {
                    Write-Log ("[DEX MATCH] pattern: '" + $p + "' in " + $dexPath + " -> " + $m.Line.Trim()) "Yellow"
                    $script:dexMatches++
                }
            }
        } catch {
            # fallback: binary read and ASCII search
            try {
                $bytes = Get-Content -Path $dexPath -Encoding Byte -ErrorAction SilentlyContinue
                $txt = [System.Text.Encoding]::ASCII.GetString($bytes)
                if ($txt.IndexOf($p,[StringComparison]::InvariantCultureIgnoreCase) -ge 0) {
                    Write-Log ("[DEX MATCH-BYTES] pattern: '" + $p + "' in " + $dexPath) "Yellow"
                    $script:dexMatches++
                }
            } catch {
                $ex = $_
                Write-Log ("[ERROR] Could not search dex: " + $dexPath + " (" + $ex.Exception.Message + ")") "Yellow"
            }
        }
    }
}

# -------------------------------
# Execution phases with progress indicators
# -------------------------------

# Phase 1: scan direct .so files recursively
Write-Log ("--- PHASE 1: Scanning direct .so files (recursive) ---") "Magenta"
$soFilesAll = Get-ChildItem -Path $apkExtractRoot -Recurse -Filter *.so -File -ErrorAction SilentlyContinue
$totalSo = $soFilesAll.Count
Write-Log ("Found " + $totalSo + " direct .so file(s).") "Yellow"
$index = 0
foreach ($s in $soFilesAll) {
    $index++
    $pct = if ($totalSo -gt 0) { [int](($index / [double]$totalSo) * 100) } else { 100 }
    Write-Progress -Activity "Phase 1: Scanning direct .so files" -Status ("Scanning " + (Get-Spinner)) -PercentComplete $pct -CurrentOperation $s.FullName
    Write-Log ("[FOUND .so] " + $s.FullName) "Gray"
    Check-SoFile $s.FullName
}
Write-Progress -Activity "Phase 1: Scanning direct .so files" -Completed

# Phase 2: scan archives across root (jar/aar/zip)
Write-Log ("`n--- PHASE 2: Scanning archives (jar/aar/zip) ---") "Magenta"
$archivesAll = Get-ChildItem -Path $apkExtractRoot -Recurse -Include *.jar,*.aar,*.zip -File -ErrorAction SilentlyContinue
$totalArchives = $archivesAll.Count
Write-Log ("Found " + $totalArchives + " archive(s) at root to inspect.") "Yellow"
$idx = 0
foreach ($a in $archivesAll) {
    $idx++
    $pct2 = if ($totalArchives -gt 0) { [int](($idx / [double]$totalArchives) * 100) } else { 100 }
    Write-Progress -Activity "Phase 2: Processing archives" -Status ("Processing " + (Get-Spinner)) -PercentComplete $pct2 -CurrentOperation $a.FullName
    Write-Log ("[ARCHIVE] " + $a.FullName) "Gray"
    $tmpA = Join-Path $tempRoot ([System.Guid]::NewGuid().ToString())
    New-Item -ItemType Directory -Path $tmpA | Out-Null
    if (Extract-Archive-To $a.FullName $tmpA) {
        Scan-Folder-For-Native $tmpA 0
    }
    Remove-Item $tmpA -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Progress -Activity "Phase 2: Processing archives" -Completed

# Phase 3: deep scan arbitrary assets/res/raw/META-INF/root
Write-Log ("`n--- PHASE 3: Deep scan of assets / res/raw / META-INF / root ---") "Magenta"
$deepDirs = @((Join-Path $apkExtractRoot "assets"), (Join-Path $apkExtractRoot "res\raw"), (Join-Path $apkExtractRoot "META-INF"), $apkExtractRoot)
$filesToCheck = New-Object System.Collections.ArrayList
foreach ($d in $deepDirs) {
    if (Test-Path $d) {
        Write-Log ("Queuing files under: " + $d) "Gray"
        $items = Get-ChildItem -Path $d -Recurse -File -ErrorAction SilentlyContinue
        foreach ($it in $items) { [void]$filesToCheck.Add($it) }
    }
}
$totalDeep = $filesToCheck.Count
Write-Log ("Total candidate files for deep analysis: " + $totalDeep) "Yellow"
$k = 0
foreach ($f in $filesToCheck) {
    $k++
    $pct3 = if ($totalDeep -gt 0) { [int](($k / [double]$totalDeep) * 100) } else { 100 }
    Write-Progress -Activity "Phase 3: Deep scan" -Status ("Scanning " + (Get-Spinner)) -PercentComplete $pct3 -CurrentOperation $f.FullName
    Analyze-ArbitraryFile $f.FullName
}
Write-Progress -Activity "Phase 3: Deep scan" -Completed

# Phase 4: scan .dex files for JNI/native strings
Write-Log ("`n--- PHASE 4: Scanning .dex files for JNI/native references ---") "Magenta"
$dexFiles = Get-ChildItem -Path $apkExtractRoot -Recurse -Include *.dex -File -ErrorAction SilentlyContinue
$totalDex = $dexFiles.Count
Write-Log ("Found " + $totalDex + " .dex file(s).") "Yellow"
$di = 0
foreach ($d in $dexFiles) {
    $di++
    $pct4 = if ($totalDex -gt 0) { [int](($di / [double]$totalDex) * 100) } else { 100 }
    Write-Progress -Activity "Phase 4: Scanning DEX files" -Status ("Searching " + (Get-Spinner)) -PercentComplete $pct4 -CurrentOperation $d.FullName
    Scan-Dex-For-JNI $d.FullName
}
Write-Progress -Activity "Phase 4: Scanning DEX files" -Completed

# Phase 5: quick text-scan of jars/classes for patterns
Write-Log ("`n--- PHASE 5: Quick text-scan in .jar/.class for JNI strings ---") "Magenta"
$codeCandidates = Get-ChildItem -Path $apkExtractRoot -Recurse -Include *.jar,*.class -File -ErrorAction SilentlyContinue
$totalCode = $codeCandidates.Count
$ci = 0
foreach ($c in $codeCandidates) {
    $ci++
    $pct5 = if ($totalCode -gt 0) { [int](($ci / [double]$totalCode) * 100) } else { 100 }
    Write-Progress -Activity "Phase 5: Text-scan code archives" -Status ("Scanning " + (Get-Spinner)) -PercentComplete $pct5 -CurrentOperation $c.FullName
    Write-Log ("[CODE-SCAN] " + $c.FullName) "Gray"
    foreach ($p in $dexPatterns) {
        try {
            $matches = Select-String -Path $c.FullName -Pattern $p -SimpleMatch -ErrorAction SilentlyContinue
            if ($matches) {
                foreach ($m in $matches) {
                    Write-Log ("[CODE-STR MATCH] " + $p + " in " + $c.FullName + " -> " + $m.Line.Trim()) "Yellow"
                }
            }
        } catch {}
    }
}
Write-Progress -Activity "Phase 5: Text-scan code archives" -Completed

# -------------------------------
# Final Summary
# -------------------------------
$extensionList = $script:scannedExtensions | Sort-Object | ForEach-Object { "`t- " + ($_ -replace '^$','[no-ext]') }
$extensionListString = $extensionList -join "`n"

$summary = @"
`nScan Summary ($(Get-Date -Format o)):
Total direct .so files scanned: $($script:totalSoFiles)
4 KB page size: $($script:count4KB)
16 KB page size: $($script:count16KB)
Total archives processed (found/extracted): $($script:totalArchives)
Total files analyzed in deep scan (Section 3): $($script:possibleNativeFiles)
Hidden ELF binaries confirmed and checked: $($script:hiddenElfCount)
Total .dex files scanned: $($script:scannedDexFiles)
Total dex/native string matches: $($script:dexMatches)

Extensions scanned (sample):
$extensionListString

Temp workspace: $tempRoot
Report file: $reportFile
"@

Write-Log $summary "Yellow"
Add-Content -Path $reportFile -Value ("Scan finished: " + (Get-Date).ToString("o"))
Write-Host "Scan complete. Report saved to: $reportFile" -ForegroundColor Cyan

# Uncomment to remove temp extraction artifacts automatically
# Remove-Item $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
