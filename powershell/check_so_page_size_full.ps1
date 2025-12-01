# -------------------------------
# Configurations
# -------------------------------
$readelf = "D:\AndroidStudioSDK\Sdk\ndk\29.0.14206865\toolchains\llvm\prebuilt\windows-x86_64\bin\llvm-readelf.exe"
$apkExtractRoot = "D:\stc-work\project\ir-android\ir-mobile-android\app\release\aab_extract\universal_extracted"
$reportFile = "D:\stc-work\16kb-issue\output\so_page_size_report.txt"

# Clear previous report
if (Test-Path $reportFile) { Remove-Item $reportFile }

Write-Host "Starting full scan of APK extracted folder..." -ForegroundColor Cyan
Add-Content -Path $reportFile -Value "Starting full scan of APK extracted folder: $apkExtractRoot"

# Counters (Declared here, accessible via $script: scope)
$totalSoFiles = 0
$count4KB = 0
$count16KB = 0
$totalArchives = 0
$possibleNativeFiles = 0

# -------------------------------
# Helper function: Check .so page alignment
# -------------------------------
function Check-SoFile {
    param (
        [string]$soPath,
        [string]$parentArchive = ""
    )

    if (!(Test-Path $soPath)) {
        Write-Host "[SKIP] $soPath does not exist" -ForegroundColor Yellow
        return
    }

    # FIX: Use $script: scope to increment the counter defined at the top level
    $script:totalSoFiles++
    $label = if ($parentArchive) { "[SO FILE] $soPath (inside $parentArchive)" } else { "[SO FILE] $soPath" }

    Write-Host $label -ForegroundColor Cyan
    Add-Content -Path $reportFile -Value $label

    try {
        # Use quotes around path in case of spaces
        $output = & "$readelf" -l "`"$soPath`"" 2>&1

        $requires16KB = $false
        foreach ($line in $output) {
            # Check for the 0x4000 (16KB) alignment flag
            if ($line -match "0x4000") { $requires16KB = $true; break }
        }

        if ($requires16KB) {
            $msg = "[16KB] $soPath"
            if ($parentArchive) { $msg += " (inside $parentArchive)" }
            Write-Host $msg -ForegroundColor Red
            Add-Content -Path $reportFile -Value $msg
            # FIX: Use $script: scope
            $script:count16KB++
        } else {
            $msg = "[4KB]  $soPath"
            if ($parentArchive) { $msg += " (inside $parentArchive)" }
            Write-Host $msg -ForegroundColor Green
            Add-Content -Path $reportFile -Value $msg
            # FIX: Use $script: scope
            $script:count4KB++
        }

    } catch {
        $ex = $_
        # Keep existing fix for the parsing error: Delimit the variable name $soPath
        $errMsg = "Error reading ${soPath}: $($ex.Exception.Message)"
        Write-Host $errMsg -ForegroundColor Yellow
        Add-Content -Path $reportFile -Value $errMsg
    }
}

# -------------------------------
# Helper function: Log directory and files
# -------------------------------
function Log-DirectoryFiles {
    param([string]$dirPath)
    Write-Host "`n[SCAN DIR] $dirPath" -ForegroundColor Magenta
    Add-Content -Path $reportFile -Value "`n[SCAN DIR] $dirPath"

    Get-ChildItem -Path $dirPath -File | ForEach-Object {
        Write-Host "  File: $($_.FullName)" -ForegroundColor Gray
        Add-Content -Path $reportFile -Value ("  File: $($_.FullName)")
    }
}

# -------------------------------
# 1. Scan all .so files recursively in APK folder
# -------------------------------
Write-Host "`n--- 1. Scanning .so files in APK folder ---`n" -ForegroundColor Magenta
Add-Content -Path $reportFile -Value "`n--- 1. Scanning .so files in APK folder ---`n"

$soFiles = Get-ChildItem -Path $apkExtractRoot -Recurse -Filter *.so -File
foreach ($so in $soFiles) {
    Log-DirectoryFiles $so.DirectoryName
    Check-SoFile $so.FullName
}

# -------------------------------
# 2. Scan .so files inside .jar/.aar archives
# -------------------------------
Write-Host "`n--- 2. Scanning .so files inside .jar/.aar archives ---`n" -ForegroundColor Magenta
Add-Content -Path $reportFile -Value "`n--- 2. Scanning .so files inside .jar/.aar archives ---`n"

$archives = Get-ChildItem -Path $apkExtractRoot -Recurse -Include *.jar, *.aar -File
foreach ($archive in $archives) {
    # FIX: Use $script: scope
    $script:totalArchives++
    Write-Host "`n[ARCHIVE] $($archive.FullName)" -ForegroundColor Cyan
    Add-Content -Path $reportFile -Value "`n[ARCHIVE] $($archive.FullName)"

    $tempDir = Join-Path $env:TEMP ("apk_temp_" + [System.Guid]::NewGuid().ToString())
    New-Item -ItemType Directory -Path $tempDir | Out-Null

    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory($archive.FullName, $tempDir)

        Get-ChildItem -Path $tempDir -Recurse -Directory | ForEach-Object { Log-DirectoryFiles $_.FullName }

        $soFilesInArchive = Get-ChildItem -Path $tempDir -Recurse -Filter *.so -File
        foreach ($so in $soFilesInArchive) {
            Check-SoFile $so.FullName $archive.FullName
        }

        if ($soFilesInArchive.Count -eq 0) {
            $msg = "[INFO] No .so files found in archive: $($archive.FullName)"
            Write-Host $msg -ForegroundColor Yellow
            Add-Content -Path $reportFile -Value $msg
        }

    } catch {
        $ex = $_
        $errMsg = "Error extracting $($archive.FullName): $($ex.Exception.Message)"
        Write-Host $errMsg -ForegroundColor Yellow
        Add-Content -Path $reportFile -Value $errMsg
    } finally {
        Remove-Item $tempDir -Recurse -Force
    }
}

# -------------------------------
# 3. Detect potential native code inside assets/.bin/.dat
# -------------------------------
Write-Host "`n--- 3. Detecting potential native code in assets/.bin/.dat ---`n" -ForegroundColor Magenta
Add-Content -Path $reportFile -Value "`n--- 3. Detecting potential native code in assets/.bin/.dat ---`n"

$nativeFiles = Get-ChildItem -Path $apkExtractRoot -Recurse -Include *.bin, *.dat -File
foreach ($file in $nativeFiles) {
    Write-Host "[POSSIBLE NATIVE] $($file.FullName)" -ForegroundColor Yellow
    Add-Content -Path $reportFile -Value "[POSSIBLE NATIVE] $($file.FullName)"
    # FIX: Use $script: scope
    $script:possibleNativeFiles++
}

# -------------------------------
# 4. Summary
# -------------------------------
$summary = @"
`nScan Summary:
Total .so files scanned: $totalSoFiles
4 KB page size: $count4KB
16 KB page size: $count16KB
Total archives scanned: $totalArchives
Potential native content files (.bin/.dat): $possibleNativeFiles
"@

Write-Host $summary -ForegroundColor Yellow
Add-Content -Path $reportFile -Value $summary

if ($count16KB -gt 0) {
    Write-Host "⚠️ Warning: Some .so files require 16 KB pages! This may cause issues on Android 14+ devices." -ForegroundColor Red
    Add-Content -Path $reportFile -Value "⚠️ Warning: Some .so files require 16 KB pages! This may cause issues on Android 14+ devices."
} else {
    Write-Host "✅ All .so files use 4 KB pages. No issues detected." -ForegroundColor Green
    Add-Content -Path $reportFile -Value "✅ All .so files use 4 KB pages. No issues detected."
}

Write-Host "`nReport saved to $reportFile" -ForegroundColor Cyan