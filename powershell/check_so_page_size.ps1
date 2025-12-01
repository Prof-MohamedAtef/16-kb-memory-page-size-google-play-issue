# -------------------------------
# Configurations
# -------------------------------
$readelf = "D:\AndroidStudioSDK\Sdk\ndk\29.0.14206865\toolchains\llvm\prebuilt\windows-x86_64\bin\llvm-readelf.exe"
$apkExtractRoot = "D:\stc-work\project\ir-android\ir-mobile-android\app\release\aab_extract\universal_extracted"
$reportFile = "D:\stc-work\scripts\so_page_size_report.txt"

# Clear previous report
if (Test-Path $reportFile) { Remove-Item $reportFile }

Write-Host "Scanning entire APK extract folder..." -ForegroundColor Cyan
Add-Content -Path $reportFile -Value "Scanning entire APK extract folder: $apkExtractRoot"

# Counters
$total = 0
$count4KB = 0
$count16KB = 0

# -------------------------------
# Helper function: Check .so page alignment
# -------------------------------
function Check-SoFile {
    param (
        [string]$soPath,
        [string]$parentArchive = ""
    )
    $global:total++

    try {
        $output = & $readelf -l $soPath
        $alignments = $output | Select-String -Pattern "Align"

        $requires16KB = $false
        foreach ($line in $alignments) {
            if ($line -match "0x4000") {
                $requires16KB = $true
                break
            }
        }

        if ($requires16KB) {
            $msg = if ($parentArchive -ne "") { "[16KB] $soPath (inside $parentArchive)" } else { "[16KB] $soPath" }
            Write-Host $msg -ForegroundColor Red
            $global:count16KB++
        } else {
            $msg = if ($parentArchive -ne "") { "[4KB]  $soPath (inside $parentArchive)" } else { "[4KB]  $soPath" }
            Write-Host $msg -ForegroundColor Green
            $global:count4KB++
        }

        Add-Content -Path $reportFile -Value $msg
    } catch {
        Write-Host "Error reading $soPath: $_" -ForegroundColor Yellow
        Add-Content -Path $reportFile -Value "Error reading $soPath: $_"
    }
}

# -------------------------------
# 1. Scan all .so files recursively in APK folder
# -------------------------------
Get-ChildItem -Path $apkExtractRoot -Recurse -Filter *.so | ForEach-Object {
    Check-SoFile $_.FullName
}

# -------------------------------
# 2. Scan .so files inside .jar and .aar archives
# -------------------------------
Get-ChildItem -Path $apkExtractRoot -Recurse -Include *.jar, *.aar | ForEach-Object {
    $archive = $_.FullName
    Write-Host "`nProcessing archive: $archive" -ForegroundColor Cyan
    Add-Content -Path $reportFile -Value "`nProcessing archive: $archive"

    # Create a temporary folder for extraction
    $tempDir = Join-Path $env:TEMP ("apk_temp_" + [System.Guid]::NewGuid().ToString())
    New-Item -ItemType Directory -Path $tempDir | Out-Null

    try {
        Expand-Archive -LiteralPath $archive -DestinationPath $tempDir -Force

        # Check for .so files inside extracted archive
        Get-ChildItem -Path $tempDir -Recurse -Filter *.so | ForEach-Object {
            Check-SoFile $_.FullName $archive
        }
    } catch {
        Write-Host "Error extracting $archive: $_" -ForegroundColor Yellow
        Add-Content -Path $reportFile -Value "Error extracting $archive: $_"
    } finally {
        # Clean up temporary folder
        Remove-Item $tempDir -Recurse -Force
    }
}

# -------------------------------
# 3. Optional: Detect potential native code inside assets/.bin/.dat files
# -------------------------------
Get-ChildItem -Path $apkExtractRoot -Recurse -Include *.bin, *.dat | ForEach-Object {
    $file = $_.FullName
    Add-Content -Path $reportFile -Value "Possible native content file: $file"
}

# -------------------------------
# 4. Summary
# -------------------------------
$summary = @"
`nScan Summary:
Total .so files scanned: $total
4 KB page size: $count4KB
16 KB page size: $count16KB
"@

Write-Host $summary -ForegroundColor Yellow
Add-Content -Path $reportFile -Value $summary

if ($count16KB -gt 0) {
    Write-Host "⚠ Warning: Some .so files require 16 KB pages! This may cause issues on Android 14+ devices." -ForegroundColor Red
    Add-Content -Path $reportFile -Value "⚠ Warning: Some .so files require 16 KB pages! This may cause issues on Android 14+ devices."
} else {
    Write-Host "All .so files use 4 KB pages. No issues detected." -ForegroundColor Green
    Add-Content -Path $reportFile -Value "All .so files use 4 KB pages. No issues detected."
}

Write-Host "`nReport saved to $reportFile" -ForegroundColor Cyan
