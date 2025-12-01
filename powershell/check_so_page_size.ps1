# Path to llvm-readelf.exe
$readelf = "D:\AndroidStudioSDK\Sdk\ndk\29.0.14206865\toolchains\llvm\prebuilt\windows-x86_64\bin\llvm-readelf.exe"

# Root folder containing all lib folders
$libRoot = "D:\stc-work\project\ir-android\ir-mobile-android\app\release\aab_extract\universal_extracted\lib"

# Output report file
$reportFile = "D:\stc-work\16kb-issue\output\so_page_size_report.txt"

# Clear previous report
if (Test-Path $reportFile) { Remove-Item $reportFile }

Write-Host "Scanning all .so files under $libRoot..." -ForegroundColor Cyan
Add-Content -Path $reportFile -Value "Scanning all .so files under $libRoot..."

# Counters
$total = 0
$count4KB = 0
$count16KB = 0

# Recursively get all .so files
Get-ChildItem -Path $libRoot -Recurse -Filter *.so | ForEach-Object {
    $total++
    $file = $_.FullName

    # Run readelf on each .so file
    $output = & $readelf -l $file

    # Extract all Align values
    $alignments = $output | Select-String -Pattern "Align"

    $requires16KB = $false

    foreach ($line in $alignments) {
        if ($line -match "0x4000") {
            $requires16KB = $true
            break
        }
    }

    if ($requires16KB) {
        $msg = "[16KB] $file"
        Write-Host $msg -ForegroundColor Red
        $count16KB++
    } else {
        $msg = "[4KB]  $file"
        Write-Host $msg -ForegroundColor Green
        $count4KB++
    }

    # Append to report file
    Add-Content -Path $reportFile -Value $msg
}

# Summary
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
