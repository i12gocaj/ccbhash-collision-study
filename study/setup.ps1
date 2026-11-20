param([string]$Python = 'python')
$ErrorActionPreference = 'Stop'
$StudyRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Push-Location -LiteralPath $StudyRoot
try {
    & $Python -c "import sys; assert sys.version_info[:2] == (3,12), 'Use Python 3.12 for the documented environment'"
    if ($LASTEXITCODE -ne 0) { throw 'Python 3.12 is required.' }
    & $Python -m pip install --target (Join-Path $StudyRoot '.tools/python') -r study/requirements.txt
    if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed.' }
    $SourcePath = Join-Path $StudyRoot 'ccbhash-src/ccbhash.py'
    if (-not (Test-Path -LiteralPath $SourcePath)) {
        & git clone https://github.com/pblprz/ccbhash.git ccbhash-src
        if ($LASTEXITCODE -ne 0) { throw 'Source download failed.' }
        & git -C ccbhash-src checkout --detach fd40d49973f5129c171dc5849ec6a8bb5fdd88a0
        if ($LASTEXITCODE -ne 0) { throw 'Source checkout failed.' }
    }
    if ((Get-FileHash -LiteralPath $SourcePath -Algorithm SHA256).Hash.ToLowerInvariant() -notin @('a1d7857c84b262ef50d84e068400e9e2b715e2ec13d1ce6357a12545dd0d1b45','5522164c0b595db171c74b298b79db23c7dff6185d0232c9c449deacf2946193')) {
        throw 'The object of study has changed.'
    }
    if (-not (Test-Path -LiteralPath 'references/binrankbench/tests/test_data/binaries')) {
        & git clone https://github.com/valbucci/binrankbench.git references/binrankbench
        if ($LASTEXITCODE -ne 0) { throw 'Fixture download failed.' }
        & git -C references/binrankbench checkout --detach 6cfda141e0d8ce76d58f1c5e8fc9969b4ba8d8a3
        if ($LASTEXITCODE -ne 0) { throw 'Fixture checkout failed.' }
    }
    $RadareRoot = Join-Path $StudyRoot '.tools/radare'
    New-Item -ItemType Directory -Force -Path $RadareRoot | Out-Null
    $RadareZip = Join-Path $RadareRoot 'radare2-5.8.8-w64.zip'
    if (-not (Test-Path -LiteralPath $RadareZip)) {
        Invoke-WebRequest -Uri 'https://github.com/radareorg/radare2/releases/download/5.8.8/radare2-5.8.8-w64.zip' -OutFile $RadareZip
    }
    if ((Get-FileHash -LiteralPath $RadareZip -Algorithm SHA256).Hash.ToLowerInvariant() -ne 'aa94bde159d57b11b461a1f3e0b8133c0e3a3b9776ddd1d682ea0007196e28d4') {
        throw 'Unexpected radare2 ZIP checksum.'
    }
    $RadareVersionDir = Join-Path $RadareRoot '5.8.8'
    if (-not (Test-Path -LiteralPath $RadareVersionDir)) {
        Expand-Archive -LiteralPath $RadareZip -DestinationPath $RadareVersionDir
    }
    & $Python study/provenance.py --check-inputs
    if ($LASTEXITCODE -ne 0) { throw 'Input verification failed.' }
    $RuntimeDownloads = @(
        @{ Url='https://github.com/radareorg/radare2/releases/download/6.0.4/radare2-6.0.4-w64.zip'; Archive='.tools/radare/radare2-6.0.4-w64.zip'; Destination='.tools/radare/6.0.4'; Hash='43f133563e9611ed69c4ee295dbd4eb8ff39b154585b56fcf0e33e3568b81fa6' },
        @{ Url='https://github.com/radareorg/radare2/releases/download/6.0.4/radare2-6.0.4-wasi.zip'; Archive='.tools/radare/radare2-6.0.4-wasi.zip'; Destination='.tools/radare/6.0.4-wasi'; Hash='11ba96d1bfa97f6ee41a9a06c2ef39772b3521df110979365490901e3c523ec0' },
        @{ Url='https://www.python.org/ftp/python/3.9.0/python-3.9.0-embed-amd64.zip'; Archive='.tools/python39/python-3.9.0-embed-amd64.zip'; Destination='.tools/python39/runtime'; Hash='a96fba43060e5c39f98376ae201283b07d20aa1c0532940c9f02c855a7ec13a3' }
        @{ Url='https://ziglang.org/download/0.14.1/zig-x86_64-windows-0.14.1.zip'; Archive='.tools/zig/zig-0.14.1.zip'; Destination='.tools/zig/0.14.1'; Hash='554f5378228923ffd558eac35e21af020c73789d87afeabf4bfd16f2e6feed2c' }
    )
    foreach ($RuntimeDownload in $RuntimeDownloads) {
        $ArchivePath = Join-Path $StudyRoot $RuntimeDownload.Archive
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $ArchivePath) | Out-Null
        if (-not (Test-Path -LiteralPath $ArchivePath)) { Invoke-WebRequest -Uri $RuntimeDownload.Url -OutFile $ArchivePath }
        if ((Get-FileHash -LiteralPath $ArchivePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $RuntimeDownload.Hash) { throw 'Unexpected runtime archive checksum.' }
        $DestinationPath = Join-Path $StudyRoot $RuntimeDownload.Destination
        if (-not (Test-Path -LiteralPath $DestinationPath)) { Expand-Archive -LiteralPath $ArchivePath -DestinationPath $DestinationPath }
    }
    $SevenZipPath = Join-Path $StudyRoot '.tools/7zip/7zr.exe'
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $SevenZipPath) | Out-Null
    if (-not (Test-Path -LiteralPath $SevenZipPath)) {
        Invoke-WebRequest -Uri 'https://github.com/ip7z/7zip/releases/download/26.03/7zr.exe' -OutFile $SevenZipPath
    }
    if ((Get-FileHash -LiteralPath $SevenZipPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne 'ad4c82fadcbdf93c03b4fc440f300509c7d60c5c2f4d183e35d9d70d6957037d') { throw 'Unexpected 7zr checksum.' }
    & $Python study/prepare_wasi.py
    if ($LASTEXITCODE -ne 0) { throw 'WASI preparation failed.' }
    & $Python study/wasi_launcher.py --compile
    if ($LASTEXITCODE -ne 0) { throw 'WASI compilation failed.' }
    & $Python study/prepare_native.py
    if ($LASTEXITCODE -ne 0) { throw 'Graph accelerator compilation failed.' }
    Write-Output 'Pinned inputs, Python 3.9.0 and both radare2 evaluation environments are ready.'
} finally { Pop-Location }
