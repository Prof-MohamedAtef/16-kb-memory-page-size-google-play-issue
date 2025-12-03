# ===============================
# Full APK ELF & DEX Diagnostic Script (Option D)
# ===============================

# -------------------------------
# Configurations
# -------------------------------
$readelf = "D:\AndroidStudioSDK\Sdk\ndk\29.0.14206865\toolchains\llvm\prebuilt\windows-x86_64\bin\llvm-readelf.exe"
$apkExtractRoot = "D:\stc-work\project\ir-android\ir-mobile-android\app\Production\release\universal_extracted"
$reportFile = "D:\stc-work\16kb-issue\output\so_page_size_report.txt"

# Clear previous report
if (Test-Path $reportFile) { Remove-Item $reportFile }

Write-Host "Starting FULL DIAGNOSTIC scan of APK extracted folder..." -ForegroundColor Cyan
Add-Content -Path $reportFile -Value "Starting FULL DIAGNOSTIC scan of APK extracted folder: $apkExtractRoot"

# -------------------------------
# Counters
# -------------------------------
$script:totalSoFiles = 0
$script:count4KB = 0
$script:count16KB = 0
$script:totalArchives = 0
$script:possibleNativeFiles = 0
$script:hiddenElfCount = 0
$script:totalDexFiles = 0
$script:dexNativeHints = 0

# Scanned extensions
$scannedExtensions = New-Object System.Collections.Generic.HashSet[string]

# Deep scan directories for hidden ELF
$deepScanDirs = @(
    (Join-Path $apkExtractRoot "assets"),
    (Join-Path $apkExtractRoot (Join-Path "res" "raw")),
    (Join-Path $apkExtractRoot "META-INF"),
    $apkExtractRoot
)

# -------------------------------
# Spinner Helper
# -------------------------------
$spinnerChars = "/-\|"
function Show-Spinner {
    param([string]$Message, [int]$Delay = 100)
    for ($i=0; $i -lt $spinnerChars.Length; $i++) {
        Write-Host -NoNewline "`r$($spinnerChars[$i]) $Message"
        Start-Sleep -Milliseconds $Delay
    }
}

# -------------------------------
# Check .so file page alignment
# -------------------------------
function Check-SoFile {
    param (
        [string]$soPath,
        [string]$parentArchive = ""
    )

    if (!(Test-Path $soPath)) {
        Write-Host "[SKIP] ${soPath} does not exist" -ForegroundColor Yellow
        return
    }

    $script:totalSoFiles++
    $label = if ($parentArchive) { "[SO FILE] ${soPath} (inside ${parentArchive})" } else { "[SO FILE] ${soPath}" }
    Write-Host $label -ForegroundColor Cyan
    Add-Content -Path $reportFile -Value $label

    try {
        $output = & "$readelf" -l "`"$soPath`"" 2>&1

        $requires16KB = $false
        foreach ($line in $output) {
            if ($line -match "0x4000") { $requires16KB = $true; break }
        }

        if ($requires16KB) {
            $msg = "[16KB] ${soPath}"
            if ($parentArchive) { $msg += " (inside ${parentArchive})" }
            Write-Host $msg -ForegroundColor Red
            Add-Content -Path $reportFile -Value $msg
            $script:count16KB++
        } else {
            $msg = "[4KB]  ${soPath}"
            if ($parentArchive) { $msg += " (inside ${parentArchive})" }
            Write-Host $msg -ForegroundColor Green
            Add-Content -Path $reportFile -Value $msg
            $script:count4KB++
        }

        # Log readelf output for hidden ELF summary
        if ($parentArchive -like "*HIDDEN ELF*") {
            Add-Content -Path $reportFile -Value ("[HIDDEN ELF READ-ELF OUTPUT] ${soPath}")
            Add-Content -Path $reportFile -Value $output
        }

    } catch {
        $ex = $_
        $errMsg = "Error reading ${soPath}: $($ex.Exception.Message)"
        Write-Host $errMsg -ForegroundColor Yellow
        Add-Content -Path $reportFile -Value $errMsg
    }
}

# -------------------------------
# Analyze potential native files (hidden ELF)
# -------------------------------
function Analyze-PossibleNativeFile {
    param([string]$filePath)

    $script:possibleNativeFiles++
    $fileLogMsg = "[POSSIBLE NATIVE] Analyzing ${filePath}"
    Write-Host $fileLogMsg -ForegroundColor Yellow
    Add-Content -Path $reportFile -Value $fileLogMsg

    try {
        $header = Get-Content -Path $filePath -Encoding Byte -TotalCount 4 -ErrorAction Stop
        if (($header[0] -eq 0x7F) -and ($header[1] -eq 0x45) -and ($header[2] -eq 0x4C) -and ($header[3] -eq 0x46)) {
            $msg = "[SUCCESS] Hidden ELF detected at ${filePath}"
            Write-Host $msg -ForegroundColor Magenta
            Add-Content -Path $reportFile -Value $msg

            $script:hiddenElfCount++
            Check-SoFile $filePath "[HIDDEN ELF]"
        }
    } catch {
        $ex = $_
        $errMsg = "[ERROR] Could not read ${filePath}: $($ex.Exception.Message)"
        Write-Host $errMsg -ForegroundColor Red
        Add-Content -Path $reportFile -Value $errMsg
    }
}

# -------------------------------
# Scan all .so files recursively in APK folder
# -------------------------------
Write-Host "`n--- 1. Scanning standard .so files ---`n" -ForegroundColor Magenta
Add-Content -Path $reportFile -Value "`n--- 1. Scanning standard .so files ---`n"

$soFiles = Get-ChildItem -Path $apkExtractRoot -Recurse -Filter *.so -File
$totalSo = $soFiles.Count
$counter = 0
foreach ($so in $soFiles) {
    $counter++
    Show-Spinner "Scanning standard .so files (${counter}/${totalSo})"
    [void]$scannedExtensions.Add($so.Extension)
    Check-SoFile $so.FullName
}

# -------------------------------
# Scan .so files inside .jar/.aar archives
# -------------------------------
Write-Host "`n--- 2. Scanning .so files inside .jar/.aar archives ---`n" -ForegroundColor Magenta
Add-Content -Path $reportFile -Value "`n--- 2. Scanning .so files inside .jar/.aar archives ---`n"

$archives = Get-ChildItem -Path $apkExtractRoot -Recurse -Include *.jar, *.aar -File
$totalArchivesCount = $archives.Count
$archiveCounter = 0
foreach ($archive in $archives) {
    $archiveCounter++
    Show-Spinner "Processing archives (${archiveCounter}/${totalArchivesCount})"

    [void]$scannedExtensions.Add($archive.Extension)
    $script:totalArchives++
    Write-Host "[ARCHIVE] ${archive.FullName}" -ForegroundColor Cyan
    Add-Content -Path $reportFile -Value "[ARCHIVE] ${archive.FullName}"

    $tempDir = Join-Path $env:TEMP ("apk_temp_" + [System.Guid]::NewGuid().ToString())
    New-Item -ItemType Directory -Path $tempDir | Out-Null

    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory($archive.FullName, $tempDir)

        $soFilesInArchive = Get-ChildItem -Path $tempDir -Recurse -Filter *.so -File
        foreach ($so in $soFilesInArchive) {
            Check-SoFile $so.FullName $archive.FullName
        }
    } catch {
        $ex = $_
        $errMsg = "Error extracting ${archive}: $($ex.Exception.Message)"
        Write-Host $errMsg -ForegroundColor Red
        Add-Content -Path $reportFile -Value $errMsg
    } finally {
        Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# -------------------------------
# Deep scan for hidden ELF binaries
# -------------------------------
Write-Host "`n--- 3. Deep scan for hidden ELF binaries ---`n" -ForegroundColor Magenta
Add-Content -Path $reportFile -Value "`n--- 3. Deep scan for hidden ELF binaries ---`n"

foreach ($dir in $deepScanDirs) {
    if (Test-Path $dir) {
        $files = Get-ChildItem -Path $dir -Recurse -File
        $totalFiles = $files.Count
        $fileCounter = 0
        foreach ($file in $files) {
            $fileCounter++
            Show-Spinner "Analyzing hidden/native files (${fileCounter}/${totalFiles})"
            [void]$scannedExtensions.Add($file.Extension)
            Analyze-PossibleNativeFile $file.FullName
        }
    }
}

# -------------------------------
# Scan .dex files for embedded native strings
# -------------------------------
Write-Host "`n--- 4. Scanning .dex files for JNI/native hints ---`n" -ForegroundColor Magenta
Add-Content -Path $reportFile -Value "`n--- 4. Scanning .dex files for JNI/native hints ---`n"

$dexFiles = Get-ChildItem -Path $apkExtractRoot -Recurse -Filter *.dex -File
$script:totalDexFiles = $dexFiles.Count
$dexCounter = 0
foreach ($dex in $dexFiles) {
    $dexCounter++
    Show-Spinner "Scanning DEX files (${dexCounter}/${script:totalDexFiles})"
    [void]$scannedExtensions.Add($dex.Extension)
    $content = Get-Content -Path $dex.FullName -Encoding Byte -ErrorAction SilentlyContinue
    $nativeMatches = ($content | ForEach-Object { $_ } | Select-String -Pattern "lib.*\.so")
    $matchCount = $nativeMatches.Count
    if ($matchCount -gt 0) {
        $script:dexNativeHints += $matchCount
        Write-Host "[DEX NATIVE HINT] ${dex.FullName} -> $matchCount matches" -ForegroundColor Cyan
        Add-Content -Path $reportFile -Value "[DEX NATIVE HINT] ${dex.FullName} -> $matchCount matches"
    }
}

# -------------------------------
# Final Summary
# -------------------------------
$extensionList = $scannedExtensions | Sort-Object | ForEach-Object { "`t- $_" }
$extensionListString = $extensionList -join "`n"

$summary = @"
`nScan Summary:
Total direct .so files scanned: $script:totalSoFiles
4 KB page size: $script:count4KB
16 KB page size: $script:count16KB
Total archives processed: $script:totalArchives
Total files analyzed in deep scan: $script:possibleNativeFiles
Hidden ELF binaries confirmed: $script:hiddenElfCount
Total .dex files scanned: $script:totalDexFiles
Total dex/native string matches: $script:dexNativeHints

Extensions scanned:
$extensionListString
"@

Write-Host $summary -ForegroundColor Yellow
Add-Content -Path $reportFile -Value $summary

if ($script:count16KB -gt 0) {
    $warnMsg = "⚠️ FATAL WARNING: Some ELF binaries require 16 KB pages!"
    Write-Host $warnMsg -ForegroundColor Red
    Add-Content -Path $reportFile -Value $warnMsg
} else {
    $okMsg = "✅ All ELF binaries use 4 KB pages. No 16 KB issues detected."
    Write-Host $okMsg -ForegroundColor Green
    Add-Content -Path $reportFile -Value $okMsg
}

Write-Host "`nReport saved to ${reportFile}" -ForegroundColor Cyan