param([string]$Python = 'python', [switch]$ReextractControlled, [switch]$SkipPdf)
$ErrorActionPreference = 'Stop'
$StudyRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Push-Location -LiteralPath $StudyRoot
try {
    & $Python study/provenance.py --check-inputs
    if ($LASTEXITCODE -ne 0) { throw 'Input verification failed.' }
    foreach ($StudyScript in @('fixtures.py','run_core.py','run_controlled.py','run_corpus.py','run_fresh_corpus.py','run_integration.py','run_adversarial.py','run_strata.py','run_robustness.py','run_contracts.py','verify_results.py','run_audit.py','verify_extensions.py')) {
        Write-Output "Running study/$StudyScript"
        $StudyArguments = @("study/$StudyScript")
        if ($StudyScript -eq 'run_controlled.py' -and $ReextractControlled) { $StudyArguments += '--force' }
        & $Python @StudyArguments
        if ($LASTEXITCODE -ne 0) { throw "Failed: $StudyScript" }
        if ($StudyScript -eq 'run_fresh_corpus.py') {
            & $Python study/run_fresh_corpus.py --version 6.0.4-wasi
            if ($LASTEXITCODE -ne 0) { throw 'Failed: fresh corpus 6.0.4 WASI' }
        }
        if ($StudyScript -eq 'run_contracts.py') {
            & (Join-Path $StudyRoot '.tools/python39/runtime/python.exe') study/run_interpreter_check.py
            if ($LASTEXITCODE -ne 0) { throw 'Failed: Python 3.9.0 parity' }
        }
    }
    foreach ($StudyScript in @('run_compiled.py','verify_compiled.py','verify_large_model.py','verify_large_reference.py','download_parallel.py','run_large.py','export_large.py','verify_large.py')) {
        Write-Output "Running study/$StudyScript"
        & $Python "study/$StudyScript"
        if ($LASTEXITCODE -ne 0) { throw "Failed: $StudyScript" }
    }
    & $Python study/publication_audit.py
    if ($LASTEXITCODE -ne 0) { throw 'Logic and mathematics publication review failed.' }
    & $Python study/close_review.py
    if ($LASTEXITCODE -ne 0) { throw 'Protocol completion check failed.' }
    & $Python study/check_manuscript.py
    if ($LASTEXITCODE -ne 0) { throw 'Manuscript result tables differ from evidence.' }
    & $Python study/plot_results.py
    if ($LASTEXITCODE -ne 0) { throw 'Figure generation failed.' }
    if (-not $SkipPdf) {
        & $Python study/build_pdf.py
        if ($LASTEXITCODE -ne 0) { throw 'PDF generation failed.' }
        Write-Output 'Newly generated PDF requires visual review; build_pdf.py marks it pending.'
    }
    & $Python study/provenance.py
    if ($LASTEXITCODE -ne 0) { throw 'Provenance generation failed.' }
    Write-Output 'All defined campaigns and independent checks completed.'
} finally { Pop-Location }
