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

# Counters (Accessed via $script: scope inside functions)
$totalSoFiles = 0 # Total number of confirmed ELF binaries checked (standard .so + hidden ELF)
$count4KB = 0
$count16KB = 0
$totalArchives = 0
$possibleNativeFiles = 0 # Total number of files checked in the deep scan (Section 3)
$hiddenElfCount = 0 # Count of files confirmed to be hidden ELF binaries

# Directories to scan deeply for hidden native code in Section 3
$deepScanDirs = @(
    (Join-Path $apkExtractRoot "assets"),
    # FIX: Nested Join-Path call to join three components correctly
    (Join-Path $apkExtractRoot (Join-Path "res" "raw")),
    $apkExtractRoot # In case non-standard files are at the root
)
# File extensions to ignore in the deep scan (common config/asset files)
# .zip REMOVED to allow deeper analysis on suspicious archives in Section 3.
$ignoreExtensions = @(".txt", ".xml", ".json", ".properties", ".config", ".dex", ".classes", ".ttf", ".png", ".jpg", ".webp")

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
            $script:count16KB++
        } else {
            $msg = "[4KB]  $soPath"
            if ($parentArchive) { $msg += " (inside $parentArchive)" }
            Write-Host $msg -ForegroundColor Green
            Add-Content -Path $reportFile -Value $msg
            $script:count4KB++
        }

    } catch {
        $ex = $_
        # Fix for ParserError: Delimit the variable name $soPath
        $errMsg = "Error reading ${soPath}: $($ex.Exception.Message)"
        Write-Host $errMsg -ForegroundColor Yellow
        Add-Content -Path $reportFile -Value $errMsg
    }
}

# -------------------------------
# Helper function: Analyze potential native file header
# -------------------------------
function Analyze-PossibleNativeFile {
    param([string]$filePath)

    $isElf = $false

    # Log the file name being checked
    $fileLogMsg = "[POSSIBLE NATIVE] Analyzing $($filePath)"
    Write-Host $fileLogMsg -ForegroundColor Yellow
    Add-Content -Path $reportFile -Value $fileLogMsg
    
    # Increment the script counter for files checked in this section
    $script:possibleNativeFiles++

    try {
        # Read the first 4 bytes to check the ELF Magic Number
        $header = Get-Content -Path $filePath -Encoding Byte -TotalCount 4 -ErrorAction Stop

        # ELF Magic Bytes: 0x7F, 0x45 ('E'), 0x4C ('L'), 0x46 ('F')
        if (($header[0] -eq 0x7F) -and 
            ($header[1] -eq 0x45) -and 
            ($header[2] -eq 0x4C) -and 
            ($header[3] -eq 0x46)) 
        {
            $isElf = $true
            $msg = "[SUCCESS] Confirmed hidden ELF binary via Magic Number. Running page check..."
            Write-Host $msg -ForegroundColor Magenta
            Add-Content -Path $reportFile -Value $msg
            
            $script:hiddenElfCount++
            
            # Use the existing Check-SoFile function for page size analysis
            Check-SoFile $filePath "[HIDDEN ELF]"

        }

    } catch {
        $msg = "[ERROR] Could not read file header for check: $($_.Exception.Message)"
        Write-Host $msg -ForegroundColor Red
        Add-Content -Path $reportFile -Value $msg
    }

    if (-not $isElf) {
        $msg = "[SKIP] File is not an ELF binary (likely data/asset)."
        Write-Host $msg -ForegroundColor Gray
        Add-Content -Path $reportFile -Value $msg
    }
    Write-Host "" # Newline for separation
    Add-Content -Path $reportFile -Value ""
}

# -------------------------------
# Helper function: Log directory and files
# --------------------------------
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
Write-Host "`n--- 1. Scanning standard .so files in APK folder ---`n" -ForegroundColor Magenta
Add-Content -Path $reportFile -Value "`n--- 1. Scanning standard .so files in APK folder ---`n"

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
$foundArchiveCount = $archives.Count
$initialArchiveMsg = "[INFO] Found $foundArchiveCount archive(s) (.jar/.aar) to scan."
Write-Host $initialArchiveMsg -ForegroundColor Yellow
Add-Content -Path $reportFile -Value $initialArchiveMsg

if ($foundArchiveCount -gt 0) {
    Write-Host "Listing found archives:" -ForegroundColor Yellow
    Add-Content -Path $reportFile -Value "Listing found archives:"
    
    foreach ($archive in $archives) {
        # Log the name of the found archive
        $archiveNameMsg = "  - $($archive.FullName)"
        Write-Host $archiveNameMsg -ForegroundColor Gray
        Add-Content -Path $reportFile -Value $archiveNameMsg
        
        # Increment the global counter for the summary (only counted if processing begins)
        $script:totalArchives++ 
        Write-Host "`n[ARCHIVE] Processing $($archive.FullName)" -ForegroundColor Cyan
        Add-Content -Path $reportFile -Value "`n[ARCHIVE] Processing $($archive.FullName)"

        $tempDir = Join-Path $env:TEMP ("apk_temp_" + [System.Guid]::NewGuid().ToString())
        New-Item -ItemType Directory -Path $tempDir | Out-Null

        try {
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            [System.IO.Compression.ZipFile]::ExtractToDirectory($archive.FullName, $tempDir)

            $soFilesInArchive = Get-ChildItem -Path $tempDir -Recurse -Filter *.so -File
            $soCountInArchive = $soFilesInArchive.Count
            
            # Enhanced Logging: Report the count of .so files found
            $summaryMsg = "[INFO] Found $soCountInArchive .so file(s) inside $($archive.Name)."
            Write-Host $summaryMsg -ForegroundColor Yellow
            Add-Content -Path $reportFile -Value $summaryMsg

            if ($soCountInArchive -gt 0) {
                foreach ($so in $soFilesInArchive) {
                    # Enhanced Logging: Report the specific .so file being processed
                    $soFileMsg = "  - Processing extracted file: $($so.BaseName)$($so.Extension)"
                    Write-Host $soFileMsg -ForegroundColor Gray
                    Add-Content -Path $reportFile -Value $soFileMsg
                    
                    # Check the file page size
                    Check-SoFile $so.FullName $archive.FullName
                }
            }
        } catch {
            $ex = $_
            $errMsg = "Error extracting $($archive.FullName): $($ex.Exception.Message)"
            Write-Host $errMsg -ForegroundColor Red
            Add-Content -Path $reportFile -Value $errMsg
        } finally {
            # Added -ErrorAction SilentlyContinue to prevent logging errors if temp folder is already gone
            Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}


# -------------------------------
# 3. Detect and Analyze potential native code in arbitrary locations
# -------------------------------
Write-Host "`n--- 3. DETAILED SCAN: Analyzing ALL files in known data paths for hidden ELF binaries ---`n" -ForegroundColor Magenta
Add-Content -Path $reportFile -Value "`n--- 3. DETAILED SCAN: Analyzing ALL files in known data paths for hidden ELF binaries ---`n"

$filesToAnalyze = @()
foreach ($dir in $deepScanDirs) {
    if (Test-Path $dir) {
        # Get all files recursively in the deep scan directory
        $filesToAnalyze += Get-ChildItem -Path $dir -Recurse -File
    }
}

# Filter out common, non-native file types for efficiency
$filesToAnalyze = $filesToAnalyze | Where-Object { 
    $_.Extension -notin $ignoreExtensions -and $_.Name -notmatch "resources.arsc"
} | Select-Object -Unique

$nativeFileCount = $filesToAnalyze.Count

$nativeSummaryMsg = "[INFO] Found $nativeFileCount file(s) to analyze for hidden native code."
Write-Host $nativeSummaryMsg -ForegroundColor Yellow
Add-Content -Path $reportFile -Value $nativeSummaryMsg

if ($nativeFileCount -gt 0) {
    Write-Host "Starting detailed analysis for potential native files (checking ELF signature):" -ForegroundColor Yellow
    Add-Content -Path $reportFile -Value "Starting detailed analysis for potential native files (checking ELF signature):"
    
    foreach ($file in $filesToAnalyze) {
        # Call the new analysis function for each potential native file
        Analyze-PossibleNativeFile $file.FullName
    }
}


# -------------------------------
# 4. Summary
# -------------------------------
$summary = @"
`nScan Summary:
Total ELF binaries scanned (Standard .so + Hidden ELF): $totalSoFiles
4 KB page size: $count4KB
16 KB page size: $count16KB
Total archives scanned: $totalArchives
Total files analyzed in Deep Scan (Section 3): $possibleNativeFiles
Hidden ELF binaries confirmed and checked in Section 3: $hiddenElfCount
"@

Write-Host $summary -ForegroundColor Yellow
Add-Content -Path $reportFile -Value $summary

if ($count16KB -gt 0) {
    Write-Host "⚠️ Warning: Some ELF binaries require 16 KB pages! This may cause issues on Android 14+ devices. Check the report for file names." -ForegroundColor Red
    Add-Content -Path $reportFile -Value "⚠️ Warning: Some ELF binaries require 16 KB pages! This may cause issues on Android 14+ devices. Check the report for file names."
} else {
    Write-Host "✅ All ELF binaries (Standard .so and confirmed Hidden ELF) use 4 KB pages. No 16KB issues detected." -ForegroundColor Green
    Add-Content -Path $reportFile -Value "✅ All ELF binaries (Standard .so and confirmed Hidden ELF) use 4 KB pages. No 16KB issues detected."
}

Write-Host "`nReport saved to $reportFile" -ForegroundColor Cyan