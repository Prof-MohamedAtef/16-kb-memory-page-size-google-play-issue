# check_so_page_size_full_with_dex.ps1
# Full diagnostic scanner:
# - scans .so files (including inside archives)
# - runs llvm-readelf -l to detect 16KB (0x4000) alignment
# - scans .dex files for JNI/native strings
# - attempts detection of hidden ELF inside arbitrary files (assets/.bin/.dat)
# - scans nested archives (jar/aar/zip)
# - writes a detailed report

# -------------------------------
# Configurations - EDIT THESE
# -------------------------------
$readelf = "D:\AndroidStudioSDK\Sdk\ndk\29.0.14206865\toolchains\llvm\prebuilt\windows-x86_64\bin\llvm-readelf.exe"
$apkExtractRoot = "D:\stc-work\project\ir-android\ir-mobile-android\app\release\aab_extract\universal_extracted"
$reportFile = "D:\stc-work\16kb-issue\output\so_page_size_report.txt"

# Maximum nested archive extraction depth
$maxNestedDepth = 2

# Patterns to search inside .dex and other text-containing files for JNI/native usage
$dexPatterns = @(
    "JNI_OnLoad",
    "RegisterNatives",
    "System.loadLibrary",
    "System.load",
    "dlopen",
    "native ",
    "native$",
    "JNIEXPORT",
    "JNINativeMethod"
)

# Signatures for binary format detection (hex bytes => decimal array)
$signatures = @{
    "ELF"   = [byte[]](0x7F,0x45,0x4C,0x46)           # 7F 'E' 'L' 'F'
    "ZIP"   = [byte[]](0x50,0x4B,0x03,0x04)           # PK..
    "GZIP"  = [byte[]](0x1F,0x8B)                     # \x1F\x8B
    "LZ4"   = [byte[]](0x04,0x22,0x4D,0x18)           # LZ4 frame (common header)
    "BR"    = [byte[]](0xCE,0xB2,0xCF,0x81)           # brotli uncommon; fallback by extension
    "XZ"    = [byte[]](0xFD,0x37,0x7A,0x58)           # xz
}

# -------------------------------
# Setup
# -------------------------------
if (-not (Test-Path $apkExtractRoot)) {
    Write-Error "apkExtractRoot path does not exist: $apkExtractRoot"
    return
}

# Ensure output folder exists
$reportDir = Split-Path -Parent $reportFile
if (-not (Test-Path $reportDir)) { New-Item -ItemType Directory -Path $reportDir -Force | Out-Null }

# Clean previous report
if (Test-Path $reportFile) { Remove-Item $reportFile -Force }

Add-Content -Path $reportFile -Value ("Scan started: " + (Get-Date).ToString("o"))
Add-Content -Path $reportFile -Value ("Root: " + $apkExtractRoot)
Add-Content -Path $reportFile -Value ""

Write-Host "Starting enhanced diagnostic scan..." -ForegroundColor Cyan

# -------------------------------
# Counters & tracking
# -------------------------------
$script:totalSoFiles = 0
$script:count4KB = 0
$script:count16KB = 0
$script:totalArchives = 0
$script:possibleNativeFiles = 0
$script:hiddenElfCount = 0

$script:scannedDexFiles = 0
$script:dexMatches = 0

$script:scannedExtensions = New-Object System.Collections.Generic.HashSet[string]

# Temp workspace base
$tempRoot = Join-Path $env:TEMP ("apk_scan_" + [System.Guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $tempRoot | Out-Null

# Add-Type for zip handling
try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
} catch {
    # continue; Expand-Archive is available in PS 5+
}

# -------------------------------
# Helpers
# -------------------------------

function Write-Log {
    param($msg, [string]$color = "White")
    Write-Host $msg -ForegroundColor $color
    Add-Content -Path $reportFile -Value $msg
}

function Read-FileHeader {
    param([string]$path, [int]$count = 8)
    try {
        $bytes = Get-Content -Path $path -Encoding Byte -TotalCount $count -ErrorAction Stop
        return ,$bytes
    } catch {
        return $null
    }
}

function Match-Signature {
    param([byte[]]$buf, [byte[]]$sig)
    if (-not $buf) { return $false }
    if ($buf.Length -lt $sig.Length) { return $false }
    for ($i=0; $i -lt $sig.Length; $i++) {
        if ($buf[$i] -ne $sig[$i]) { return $false }
    }
    return $true
}

# Safely run readelf and return output lines (or error text)
function Run-Readelf {
    param([string]$soPath)
    try {
        # Use call operator and pass path as argument - avoids quoting problems
        $out = & $readelf -l $soPath 2>&1
        return $out
    } catch {
        return @("ERROR: readelf failed: " + $_.Exception.Message)
    }
}

# Check .so file and update counters
function Check-SoFile {
    param([string]$soPath, [string]$parentArchive = "")

    if (-not (Test-Path $soPath)) {
        Write-Log ("[SKIP] .so missing: " + $soPath) "Yellow"
        return
    }

    $script:totalSoFiles++
    $script:scannedExtensions.Add((Split-Path $soPath -LeafExtension) | Out-Null ; (Get-Item $soPath).Extension) | Out-Null

    $label = if ($parentArchive) { "[SO] " + $soPath + " (inside " + $parentArchive + ")" } else { "[SO] " + $soPath }
    Write-Log $label "Cyan"

    $out = Run-Readelf $soPath

    # Check for 0x4000 alignment anywhere in readelf output
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

    # Add the readelf output to report for traceability (optional — comment if too verbose)
    Add-Content -Path $reportFile -Value ("--- readelf for: " + $soPath)
    Add-Content -Path $reportFile -Value ($out -join "`n")
    Add-Content -Path $reportFile -Value ""
}

# Extract archive to folder (safe) and return extracted path or $null
function Extract-Archive-To {
    param([string]$archivePath, [string]$destDir)
    try {
        # Prefer ZipFile if available
        if (Get-Command Expand-Archive -ErrorAction SilentlyContinue) {
            Expand-Archive -LiteralPath $archivePath -DestinationPath $destDir -Force -ErrorAction Stop
        } else {
            [System.IO.Compression.ZipFile]::ExtractToDirectory($archivePath, $destDir)
        }
        return $true
    } catch {
        $err = $_.Exception.Message
        Write-Log ("[ERROR] Failed to extract " + $archivePath + ": " + $err) "Yellow"
        return $false
    }
}

# Recursively scan a folder for .so and nested archives (depth limited)
function Scan-Folder-For-Native {
    param([string]$folder, [int]$depth = 0)

    if ($depth -lt 0) { return }

    # Log directory
    Write-Log ("[DIR] " + $folder) "Magenta"

    # Process direct .so files
    Get-ChildItem -Path $folder -Filter *.so -File -ErrorAction SilentlyContinue | ForEach-Object {
        Check-SoFile $_.FullName
    }

    # Find archives to extract (.jar, .aar, .zip)
    $archives = Get-ChildItem -Path $folder -Include *.jar,*.aar,*.zip -File -Recurse -Depth 0 -ErrorAction SilentlyContinue 2>$null
    foreach ($archive in $archives) {
        $script:totalArchives++
        Write-Log ("[ARCHIVE FOUND] " + $archive.FullName) "Cyan"

        $tmp = Join-Path $tempRoot ([System.Guid]::NewGuid().ToString())
        New-Item -ItemType Directory -Path $tmp | Out-Null
        $ok = Extract-Archive-To $archive.FullName $tmp
        if ($ok) {
            # Scan extracted contents
            Scan-Folder-For-Native $tmp ($depth + 1)
            # If depth allowed, scan nested archives
            if ($depth -lt $maxNestedDepth) {
                Get-ChildItem -Path $tmp -Include *.jar,*.aar,*.zip -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                    $nestedTmp = Join-Path $tempRoot ([System.Guid]::NewGuid().ToString())
                    New-Item -ItemType Directory -Path $nestedTmp | Out-Null
                    if (Extract-Archive-To $_.FullName $nestedTmp) {
                        Scan-Folder-For-Native $nestedTmp ($depth + 1)
                    }
                    Remove-Item $nestedTmp -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        }
        Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Find any file that contains ELF magic in a folder (no extension assumption)
function Detect-ELF-In-Files {
    param([string]$folder)
    Get-ChildItem -Path $folder -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        $f = $_.FullName
        $hdr = Read-FileHeader $f 4
        if ($hdr) {
            if (Match-Signature $hdr $signatures["ELF"]) {
                # Found hidden ELF
                $script:hiddenElfCount++
                Write-Log ("[HIDDEN ELF FOUND] " + $f) "Magenta"
                # Check this as an ELF binary
                Check-SoFile $f "[HIDDEN ELF]"
            } else {
                # record extension scanned
                try { $script:scannedExtensions.Add($_.Extension) | Out-Null } catch {}
            }
        }
    }
}

# Scan .dex for JNI/native strings
function Scan-Dex-For-JNI {
    param([string]$dexPath)
    if (-not (Test-Path $dexPath)) { return }
    $script:scannedDexFiles++

    Write-Log ("[DEX] Scanning: " + $dexPath) "Cyan"

    # Try text search for patterns - many strings are embedded in dex as plain ASCII
    foreach ($p in $dexPatterns) {
        try {
            $matches = Select-String -Path $dexPath -Pattern $p -SimpleMatch -Raw -ErrorAction SilentlyContinue
            if ($matches) {
                foreach ($m in $matches) {
                    Write-Log ("[DEX MATCH] pattern: '" + $p + "' in " + $dexPath + " -> " + $m.Line.Trim()) "Yellow"
                    $script:dexMatches++
                }
            }
        } catch {
            # If Select-String fails on binary, fallback to manual byte scanning for ASCII string
            try {
                $bytes = Get-Content -Path $dexPath -Encoding Byte -ErrorAction SilentlyContinue
                $txt = [System.Text.Encoding]::ASCII.GetString($bytes)
                if ($txt.IndexOf($p, [StringComparison]::InvariantCultureIgnoreCase) -ge 0) {
                    Write-Log ("[DEX MATCH-BYTES] pattern: '" + $p + "' in " + $dexPath) "Yellow"
                    $script:dexMatches++
                }
            } catch {
                Write-Log ("[ERROR] Could not search dex file: " + $dexPath + " (" + $_.Exception.Message + ")") "Yellow"
            }
        }
    }
}

# Try to detect compressed ELF inside a file by checking for nested zip/elf/gzip signatures in its bytes
function Detect-CompressedContainers {
    param([string]$filePath)
    $hdr = Read-FileHeader $filePath 16
    if (-not $hdr) { return $null }

    # quick checks
    foreach ($k in $signatures.Keys) {
        $sig = $signatures[$k]
        if (Match-Signature $hdr $sig) {
            return $k
        }
    }

    # also check for "PK" at offset >0 (embedded zip)
    try {
        $raw = Get-Content -Path $filePath -Encoding Byte -TotalCount 4096 -ErrorAction SilentlyContinue
        for ($i=0; $i -lt ($raw.Length - 4); $i++) {
            if ($raw[$i] -eq 0x50 -and $raw[$i+1] -eq 0x4B) {
                return "ZIP-EMBED"
            }
        }
    } catch { }

    return $null
}

# Analyze arbitrary file (assets, .bin, .dat, etc.) for hidden ELF or compressed containers
function Analyze-ArbitraryFile {
    param([string]$filePath)

    $script:possibleNativeFiles++
    Write-Log ("[ANALYZE] " + $filePath) "Yellow"
    try {
        $container = Detect-CompressedContainers $filePath
        if ($container -eq "ELF") {
            $script:hiddenElfCount++
            Write-Log ("[FOUND ELF-MAGIC] " + $filePath) "Magenta"
            Check-SoFile $filePath "[HIDDEN ELF]"
            return
        } elseif ($container -in @("ZIP","ZIP-EMBED")) {
            Write-Log ("[FOUND ZIP] Attempt extracting embedded zip from " + $filePath) "Yellow"
            $tmp = Join-Path $tempRoot ([System.Guid]::NewGuid().ToString())
            New-Item -ItemType Directory -Path $tmp | Out-Null
            # Try to extract directly if it is a zip
            $ok = $false
            try {
                if ($container -eq "ZIP") {
                    $ok = Extract-Archive-To $filePath $tmp
                } else {
                    # For zip embed, we try naive strategy: copy the file and attempt to open as zip (may fail)
                    $tmpZip = Join-Path $tmp "embedded.zip"
                    Copy-Item -Path $filePath -Destination $tmpZip -Force
                    $ok = Extract-Archive-To $tmpZip $tmp
                }
            } catch {
                $ok = $false
            }
            if ($ok) {
                Scan-Folder-For-Native $tmp 0
            }
            Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
            return
        } elseif ($container -in @("GZIP","LZ4","BR","XZ")) {
            Write-Log ("[FOUND COMPRESSED] type=" + $container + " for " + $filePath + " (not automatically decompressing all formats).") "Yellow"
            # attempt to extract gzip only (common)
            if ($container -eq "GZIP") {
                $tmpFile = Join-Path $tempRoot ([System.Guid]::NewGuid().ToString())
                try {
                    # Use System.IO.Compression.GzipStream via .NET to decompress first chunk to file
                    $inStream = [System.IO.File]::OpenRead($filePath)
                    $gz = New-Object System.IO.Compression.GzipStream($inStream, [System.IO.Compression.CompressionMode]::Decompress)
                    $outFile = Join-Path $tempRoot "decompressed.bin"
                    $outFs = [System.IO.File]::OpenWrite($outFile)
                    $buffer = New-Object byte[] 8192
                    while (($read = $gz.Read($buffer,0,$buffer.Length)) -gt 0) {
                        $outFs.Write($buffer,0,$read)
                    }
                    $gz.Close(); $inStream.Close(); $outFs.Close()
                    Scan-Folder-For-Native (Split-Path $outFile -Parent) 0
                    Remove-Item $outFile -Force -ErrorAction SilentlyContinue
                } catch {
                    Write-Log ("[ERROR] Failed to decompress gzip: " + $filePath + " (" + $_.Exception.Message + ")") "Yellow"
                }
            }
            return
        } else {
            # No container detected; test for raw ELF within file by scanning many bytes for ELF header
            try {
                $raw = Get-Content -Path $filePath -Encoding Byte -TotalCount 131072 -ErrorAction SilentlyContinue
                for ($i=0; $i -lt ($raw.Length - 4); $i++) {
                    if ($raw[$i] -eq 0x7F -and $raw[$i+1] -eq 0x45 -and $raw[$i+2] -eq 0x4C -and $raw[$i+3] -eq 0x46) {
                        # found embedded ELF at offset $i
                        Write-Log ("[EMBEDDED ELF] Found ELF header at offset " + $i + " in " + $filePath) "Magenta"
                        # Extract the tail starting at offset and write a temp file to check
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
                Write-Log ("[ERROR] Could not inspect large file bytes: " + $filePath + " (" + $_.Exception.Message + ")") "Yellow"
            }
        }
    } catch {
        Write-Log ("[ERROR] Analyze failed: " + $filePath + " (" + $_.Exception.Message + ")") "Yellow"
    }
}

# -------------------------------
# Execution steps
# -------------------------------

# 1) Standard .so files in all subfolders
Write-Log ("--- STEP 1: Scan standard .so files recursively ---") "Magenta"
$soFiles = Get-ChildItem -Path $apkExtractRoot -Recurse -Filter *.so -File -ErrorAction SilentlyContinue
Write-Log ("Found " + $soFiles.Count + " direct .so file(s) under root.") "Yellow"
foreach ($s in $soFiles) {
    try {
        $script:scannedExtensions.Add($s.Extension) | Out-Null
        Write-Log ("Found .so file: " + $s.FullName) "Gray"
        Check-SoFile $s.FullName
    } catch {
        Write-Log ("[ERROR] scanning .so: " + $s.FullName + " (" + $_.Exception.Message + ")") "Yellow"
    }
}

# 2) Find and extract jar/aar/zip archives and scan inside (nested extraction)
Write-Log ("`n--- STEP 2: Scan archives (jar/aar/zip) and nested contents ---") "Magenta"
$archives = Get-ChildItem -Path $apkExtractRoot -Recurse -Include *.jar,*.aar,*.zip -File -ErrorAction SilentlyContinue
Write-Log ("Found " + $archives.Count + " archive(s) to inspect.") "Yellow"
foreach ($a in $archives) {
    try {
        $script:scannedExtensions.Add($a.Extension) | Out-Null
        Write-Log ("Archive: " + $a.FullName) "Gray"
        $tmp = Join-Path $tempRoot ([System.Guid]::NewGuid().ToString())
        New-Item -ItemType Directory -Path $tmp | Out-Null
        if (Extract-Archive-To $a.FullName $tmp) {
            Scan-Folder-For-Native $tmp 0
        }
        Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Log ("[ERROR] processing archive: " + $a.FullName + " (" + $_.Exception.Message + ")") "Yellow"
    }
}

# 3) Deep scan of assets / res/raw / META-INF / root for embedded ELF or compressed containers
Write-Log ("`n--- STEP 3: Deep scan arbitrary assets/.bin/.dat and META-INF for hidden native code ---") "Magenta"
$deepDirs = @((Join-Path $apkExtractRoot "assets"), (Join-Path $apkExtractRoot "res\raw"), (Join-Path $apkExtractRoot "META-INF"), $apkExtractRoot)
$filesToCheck = @()
foreach ($d in $deepDirs) {
    if (Test-Path $d) {
        Write-Log ("Queueing files under: " + $d) "Gray"
        $items = Get-ChildItem -Path $d -Recurse -File -ErrorAction SilentlyContinue
        foreach ($it in $items) { $filesToCheck += $it }
    }
}
Write-Log ("Total candidate files for deep analysis: " + $filesToCheck.Count) "Yellow"
foreach ($f in $filesToCheck) {
    Analyze-ArbitraryFile $f.FullName
}

# 4) Scan .dex files for JNI/native references
Write-Log ("`n--- STEP 4: Scanning .dex files for JNI/native references ---") "Magenta"
$dexFiles = Get-ChildItem -Path $apkExtractRoot -Recurse -Include *.dex -File -ErrorAction SilentlyContinue
Write-Log ("Found " + $dexFiles.Count + " .dex file(s).") "Yellow"
foreach ($d in $dexFiles) {
    try {
        $script:scannedExtensions.Add($d.Extension) | Out-Null
        Scan-Dex-For-JNI $d.FullName
    } catch {
        Write-Log ("[ERROR] scanning dex: " + $d.FullName + " (" + $_.Exception.Message + ")") "Yellow"
    }
}

# 5) Extra: Also try scanning .class/.jar content strings (if present)
Write-Log ("`n--- STEP 5: Extra string scan for .class/.jar files (simple text search) ---") "Magenta"
$codeArchives = Get-ChildItem -Path $apkExtractRoot -Recurse -Include *.jar,*.class -File -ErrorAction SilentlyContinue
foreach ($c in $codeArchives) {
    try {
        Write-Log ("Text-scan: " + $c.FullName) "Gray"
        foreach ($p in $dexPatterns) {
            try {
                $matches = Select-String -Path $c.FullName -Pattern $p -SimpleMatch -ErrorAction SilentlyContinue
                if ($matches) {
                    foreach ($m in $matches) {
                        Write-Log ("[CODE-STR MATCH] " + $p + " in " + $c.FullName + " -> " + $m.Line.Trim()) "Yellow"
                    }
                }
            } catch { }
        }
    } catch { }
}

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
Write-Host "Scan complete. Report: $reportFile" -ForegroundColor Cyan

# Cleanup temp root - comment this line if you need to inspect extracted files
# Remove-Item $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
