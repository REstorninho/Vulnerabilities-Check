
# ╔══════════════════════════════════════════════════════════════════╗
# ║  windows-full-audit.ps1 — Auditoria Completa + CVE Dashboard   ║
# ║  Combina: windows-audit.ps1 + vuln-check.ps1                   ║
# ║  Uso: powershell -ExecutionPolicy Bypass -File windows-full-audit.ps1 ║
# ╚══════════════════════════════════════════════════════════════════╝
#
# FASES:
#   1  — Download de ferramentas (winPEAS, Seatbelt, PrivescCheck,
#         Trivy, Grype, OSV-Scanner, Watson, WES-NG)
#   2  — Scans de segurança → ficheiros .txt:
#          01_sysinfo      — sistema, hotfixes, processos
#          02_users_groups — utilizadores, grupos, sessões
#          03_network      — portas, firewall, shares, Wi-Fi
#          04_winpeas      — privesc automático (winPEAS)
#          05_seatbelt     — hardening checks (Seatbelt/SharpUp)
#          06_privesc      — PrivescCheck (tasks, serviços, ACLs)
#          07_trivy        — CVE scan filesystem (texto)
#          08_nvd_cve      — NVD API lookup básico
#          09_registry     — registry sensível (LSA, WDigest, UAC, SMBv1)
#          10_services     — serviços (unquoted paths, DLL hijack, tasks)
#          11_patch_gap    — WES-NG + MSRC API + Watson/inline CVEs
#          12_app_vulns    — OSV-Scanner + Grype + PURL/NVD + inventário
#   3  — Inventário JSON estruturado (registry + FileVersionInfo)
#   4  — CVE/CWE JSON (Trivy JSON + Grype JSON + NVD API)
#   5  — App updates JSON (winget + choco + scoop)
#   6  — Relatório HTML unificado com duas tabs:
#          "Audit"         — findings, privesc, hardening (do windows-audit)
#          "CVE Dashboard" — tabela CVE/CWE interactiva, inventário,
#                            updates com comandos clicáveis (do vuln-check)
#
# tools\ e reports\ ficam JUNTO DO SCRIPT — persistem entre execuções.

param(
    [Alias("h")] [switch]$Help,
    [Alias("o")] [string]$Output       = "",
    [Alias("s")] [switch]$SkipDownload,
    [Alias("q")] [switch]$Quick,
    [Alias("n")] [switch]$NoNvd,
    [switch]$NoBrowser,
    [switch]$AvExclusion,
    [switch]$DeepScan,
    [switch]$Force,
    [string]$NvdApiKey = $env:NVD_API_KEY,
    [string]$Compare   = "",
    [ValidateSet("","critical","high","medium")]
    [string]$FailOn    = ""
)

$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference    = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ─── Helpers de output ────────────────────────────────────────────
# Counters globais para logging estruturado
$Global:ErrorCount    = 0
$Global:WarnCount     = 0
$Global:CurrentPhase  = "init"

function Write-Info  { param($m) Write-Host "[+] $m" -ForegroundColor Green }
function Write-Warn  {
    param($m, $extra = $null)
    Write-Host "[!] $m" -ForegroundColor Yellow
    Write-LogJsonl -Level "WARN" -Message $m -Extra $extra
    $Global:WarnCount++
}
function Write-Err   {
    param($m, $extra = $null)
    Write-Host "[X] $m" -ForegroundColor Red
    Write-LogJsonl -Level "ERROR" -Message $m -Extra $extra
    $Global:ErrorCount++
}
function Write-Step  {
    param($m)
    $Global:CurrentPhase = $m
    Write-Host "`n══════ $m ══════" -ForegroundColor Cyan
    Write-LogJsonl -Level "INFO" -Message "Fase iniciada: $m"
}
function Write-Sec   {
    param($m)
    $Global:CurrentPhase = $m
    Write-Host "`n─── $m ───" -ForegroundColor Cyan
}

# ─── Sistema de Logging Estruturado (JSON Lines) ──────────────────
# Escreve em audit_events.log (tudo) e audit_errors.log (só ERROR/WARN)
# Filtrar com PowerShell:
#   Get-Content audit_events.log | ConvertFrom-Json | Where-Object Level -eq "ERROR"
function Write-LogJsonl {
    param(
        [string]$Level,
        [string]$Message,
        [hashtable]$Extra = $null
    )
    # Só escreve se paths estão definidos e directório existe
    if (-not $Global:EventLog -or -not (Test-Path (Split-Path $Global:EventLog -Parent))) { return }
    $obj = [ordered]@{
        timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        level     = $Level
        phase     = $Global:CurrentPhase
        message   = $Message
    }
    if ($Extra) {
        foreach ($k in $Extra.Keys) { $obj[$k] = $Extra[$k] }
    }
    # Compact JSON numa linha
    $line = $obj | ConvertTo-Json -Depth 5 -Compress
    try {
        Add-Content -Path $Global:EventLog -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue
        if ($Level -eq "ERROR" -or $Level -eq "WARN") {
            Add-Content -Path $Global:ErrorLog -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue
        }
    } catch {}
}

# Wrapper para correr scriptblocks e logar excepções
function Invoke-LoggedBlock {
    param(
        [string]$Label,
        [scriptblock]$ScriptBlock,
        [string]$Phase = $null
    )
    if ($Phase) { $Global:CurrentPhase = $Phase }
    try {
        & $ScriptBlock
    } catch {
        Write-Err "$Label : $($_.Exception.Message)" @{
            exception = $_.Exception.GetType().Name
            script_line = $_.InvocationInfo.ScriptLineNumber
        }
    }
}

if ($Help) {
    Write-Host @"

  ╔══════════════════════════════════════════════════════════════════╗
  ║    windows-full-audit.ps1 — Auditoria Completa + CVE Dashboard  ║
  ╚══════════════════════════════════════════════════════════════════╝

  USO:
    powershell -ExecutionPolicy Bypass -File windows-full-audit.ps1 [OPÇÕES]

  OPÇÕES:
    -Help (-h)          Esta mensagem
    -Output DIR (-o)    Output personalizado (default: <script_dir>\reports\<host>_<date>\)
    -SkipDownload (-s)  Usar ferramentas em cache (não descarregar)
    -Quick (-q)         Salta winPEAS e Seatbelt (mais rápido)
    -NoNvd (-n)         Salta consulta NVD (modo offline)
    -NoBrowser          Não abre relatório no browser
    -AvExclusion        Adiciona Tools\ às exclusões do Defender durante o scan
    -DeepScan           Activa Trivy secret+misconfig (mais lento, encontra secrets)
    -Force              Re-download de ferramentas mesmo que existam
    -NvdApiKey KEY      NVD API key (tambem via env var NVD_API_KEY)
                        Com key: rate limit 5/30s -> 50/30s (10x mais rapido)
                        Obter em: https://nvd.nist.gov/developers/request-an-api-key
    -Compare FILE       Comparar com cve_results.json de run anterior
    -FailOn LEVEL       Exit code != 0 quando ha findings (CI/CD)
                        Valores: critical, high, medium
                        Codes: 0=clean, 1=erro, 2=critical, 3=high, 4=medium

  EXEMPLOS:
    powershell -ExecutionPolicy Bypass -File windows-full-audit.ps1
    powershell -ExecutionPolicy Bypass -File windows-full-audit.ps1 -Quick -NoNvd
    powershell -ExecutionPolicy Bypass -File windows-full-audit.ps1 -AvExclusion
    powershell -ExecutionPolicy Bypass -File windows-full-audit.ps1 -NvdApiKey "abc123"
    powershell -ExecutionPolicy Bypass -File windows-full-audit.ps1 -Compare "reports\host_20260515_1030\cve_results.json"
    powershell -ExecutionPolicy Bypass -File windows-full-audit.ps1 -FailOn critical
    powershell -ExecutionPolicy Bypass -File windows-full-audit.ps1 -Force
"@ -ForegroundColor Cyan
    exit 0
}

# ═══════════════════════════════════════════════════════════════════
# CONFIGURAÇÃO DE PATHS
# ═══════════════════════════════════════════════════════════════════
$Target    = $env:COMPUTERNAME
$Date      = Get-Date -Format "yyyyMMdd_HHmm"
$ScriptDir = $PSScriptRoot
if (-not $ScriptDir) { $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $ScriptDir) { $ScriptDir = (Get-Location).Path }

$Tools = "$ScriptDir\tools"

if ($Output -ne "") { $Out = $Output }
else                { $Out = "$ScriptDir\reports\${Target}_${Date}" }

$Report      = "$Out\REPORT_${Target}_${Date}.html"
$InvFile     = "$Out\inventory.json"
$CveFile     = "$Out\cve_results.json"
$AppUpdFile  = "$Out\app_updates.json"
$TrivyJson   = "$Out\trivy_raw.json"
$GrypeJson   = "$Out\12_grype.json"
# Exports adicionais (#1) e diff (#3)
$CveCsv      = "$Out\cve_results.csv"
$CveSarif    = "$Out\cve_results.sarif"
$DiffFile    = "$Out\diff_vs_previous.json"
# Logs estruturados (JSON Lines)
$Global:EventLog = "$Out\audit_events.log"
$Global:ErrorLog = "$Out\audit_errors.log"

New-Item -ItemType Directory -Force -Path $Out, $Tools | Out-Null

# Inicializar logs — após mkdir
"# audit_events.log - JSON Lines, todos os eventos" | Out-File $Global:EventLog -Encoding UTF8 -Force
"# audit_errors.log - so ERROR e WARN" | Out-File $Global:ErrorLog -Encoding UTF8 -Force
Write-LogJsonl -Level "INFO" -Message "Script iniciado" -Extra @{
    version = "1.0"
    args    = ($PSBoundParameters.Keys -join ",")
    pid     = $PID
}

# Trap global — captura excepções não tratadas
trap {
    Write-LogJsonl -Level "ERROR" -Message "Excepção não-tratada: $($_.Exception.Message)" -Extra @{
        exception   = $_.Exception.GetType().Name
        script_line = $_.InvocationInfo.ScriptLineNumber
        command     = $_.InvocationInfo.Line.Trim()
    }
    $Global:ErrorCount++
    continue  # Não terminar — deixar o script tentar continuar
}

# Cache global Trivy/Grype DBs — persiste entre runs (#4)
# Poupa ~600MB de download por run
$env:TRIVY_CACHE_DIR    = "$Tools\trivy-cache"
$env:GRYPE_DB_CACHE_DIR = "$Tools\grype-cache"
New-Item -ItemType Directory -Force -Path $env:TRIVY_CACHE_DIR, $env:GRYPE_DB_CACHE_DIR | Out-Null

# Validar -Compare
if ($Compare -ne "" -and -not (Test-Path $Compare)) {
    Write-Err "-Compare: ficheiro não encontrado: $Compare"
    exit 1
}

# ─── Admin + contadores ───────────────────────────────────────────
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

$TotalCrit = 0; $TotalHigh = 0
$AllCves   = [System.Collections.Generic.HashSet[string]]::new()
$AllCwes   = [System.Collections.Generic.HashSet[string]]::new()

# ─── Hotfixes instalados (para patch gap) ─────────────────────────
$hotfixes = Get-HotFix -ErrorAction SilentlyContinue | ForEach-Object { $_.HotFixID }

Write-Host @"
`n╔══════════════════════════════════════════════════╗
║   windows-full-audit — Auditoria Completa        ║
╠══════════════════════════════════════════════════╣
║  Host    : $Target
║  OS      : $([System.Environment]::OSVersion.VersionString)
║  Date    : $Date
║  Admin   : $IsAdmin
║  Tools   : $Tools
║  Output  : $Out
╚══════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

if (-not $IsAdmin) { Write-Warn "Sem Admin — cobertura limitada. Recomendado: Run as Administrator" }
if ($Quick)        { Write-Warn "Modo rápido — winPEAS e Seatbelt serão saltados" }
if ($NoNvd)        { Write-Warn "NVD lookup desactivado" }

# ═══════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════

function Safe-Download {
    param([string]$Url, [string]$Dest, [int]$MinBytes = 10240)

    $attempts = @(
        # 1: IWR com proxy do sistema
        { Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing -TimeoutSec 90 `
            -Proxy ([System.Net.WebRequest]::GetSystemWebProxy().GetProxy($Url)) `
            -ProxyUseDefaultCredentials -ErrorAction Stop },
        # 2: IWR sem proxy explícito
        { Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing -TimeoutSec 90 -ErrorAction Stop },
        # 3: .NET WebClient (proxy do sistema automático)
        {
            $wc = New-Object System.Net.WebClient
            $wc.UseDefaultCredentials = $true
            $wc.Proxy = [System.Net.WebRequest]::GetSystemWebProxy()
            $wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
            $wc.DownloadFile($Url, $Dest)
        },
        # 4: BITS (Background Intelligent Transfer Service) — usa canal diferente, contorna alguns firewalls
        {
            $job = Start-BitsTransfer -Source $Url -Destination $Dest -Asynchronous -ErrorAction Stop
            $timeout = 90; $elapsed = 0
            while ($job.JobState -notin @("Transferred","Error","Cancelled") -and $elapsed -lt $timeout) {
                Start-Sleep -Seconds 2; $elapsed += 2
            }
            if ($job.JobState -eq "Transferred") { Complete-BitsTransfer -BitsJob $job }
            else { Remove-BitsTransfer -BitsJob $job -ErrorAction SilentlyContinue; throw "BITS timeout/error" }
        }
    )

    foreach ($attempt in $attempts) {
        try {
            & $attempt
            if ((Test-Path $Dest) -and (Get-Item $Dest).Length -ge $MinBytes) { return $true }
            Remove-Item $Dest -Force -ErrorAction SilentlyContinue
        } catch {}
    }

    Write-Warn "  Download falhou: $Url"
    return $false
}

function Ensure-Tool {
    param([string]$Name, [string]$Dest, [string[]]$Urls, [int]$MinBytes = 10240)
    if ((Test-Path $Dest) -and -not $Force) {
        $sz = [math]::Round((Get-Item $Dest).Length / 1KB)
        Write-Info "$Name — cache OK ($sz KB)"; return $true
    }
    Write-Info "A descarregar $Name..."
    foreach ($url in $Urls) {
        if (Safe-Download -Url $url -Dest $Dest -MinBytes $MinBytes) {
            Write-Info "  $Name OK"; return $true
        }
    }
    Write-Warn "  $Name — download falhou"; return $false
}
# Get-GitHubRelease — descarrega asset ZIP de release do GitHub
# Se objects.githubusercontent.com estiver bloqueado (firewall corporativo),
# mostra instruções de instalação manual em vez de tentar métodos que vão falhar.
function Get-GitHubRelease {
    param(
        [string]$Repo,
        [string]$AssetFilter,
        [string]$Dest,
        [int]$MinBytes    = 10240,
        [string]$FallbackVer = "",
        [string]$FallbackUrl = "",
        [string]$ManualDest = ""   # path onde copiar manualmente (para a mensagem de ajuda)
    )

    # 1. Obter metadados via API
    $ver = $FallbackVer; $assetUrl = $FallbackUrl
    try {
        $rel   = Invoke-RestMethod "https://api.github.com/repos/${Repo}/releases/latest" -TimeoutSec 15 -ErrorAction Stop
        $ver   = $rel.tag_name.TrimStart("v")
        $asset = $rel.assets | Where-Object { $_.name -like $AssetFilter } | Select-Object -First 1
        if ($asset) { $assetUrl = $asset.browser_download_url }
        Write-Info "  v${ver} — $(Split-Path $assetUrl -Leaf)"
    } catch {
        Write-Warn "  GitHub API inacessível — a usar fallback v${ver}"
    }
    if (-not $assetUrl) { Write-Warn "  Sem URL de download disponível"; return $null }

    # 2. Teste rápido de conectividade ao host de download (objects.githubusercontent.com)
    # Se falhar imediatamente, não perder tempo com múltiplos métodos
    $downloadHost = ([Uri]$assetUrl).Host
    $quickTest = $false
    try {
        $req = [System.Net.WebRequest]::Create("https://${downloadHost}")
        $req.Timeout = 5000; $req.Method = "HEAD"
        $resp = $req.GetResponse(); $resp.Close(); $quickTest = $true
    } catch {}

    if (-not $quickTest) {
        # Host bloqueado — mostrar instrução clara e sair rapidamente
        $toolName = Split-Path $Repo -Leaf
        $manualPath = if ($ManualDest) { $ManualDest } else { $Dest }
        Write-Warn "  $downloadHost inacessível (firewall/proxy)"
        Write-Host ""
        Write-Host "  ┌─ INSTALAÇÃO MANUAL ─────────────────────────────────────┐" -ForegroundColor Yellow
        Write-Host "  │ 1. Descarregar numa máquina com acesso à internet:       │" -ForegroundColor Yellow
        Write-Host "  │    $assetUrl" -ForegroundColor Cyan
        Write-Host "  │ 2. Extrair o .exe do ZIP                                 │" -ForegroundColor Yellow
        Write-Host "  │ 3. Copiar para: $manualPath" -ForegroundColor Cyan
        Write-Host "  │ 4. Re-executar o script (usará cache automaticamente)    │" -ForegroundColor Yellow
        Write-Host "  └──────────────────────────────────────────────────────────┘" -ForegroundColor Yellow
        Write-Host ""
        Write-LogJsonl -Level "WARN" -Message "${toolName}: host de download bloqueado ($downloadHost)" -Extra @{
            download_url = $assetUrl
            manual_dest  = $manualPath
        }
        return $null
    }

    # Host acessível — tentar descarregar
    # Método 1: Safe-Download (IWR + WebClient + BITS)
    if (Safe-Download -Url $assetUrl -Dest $Dest -MinBytes $MinBytes) { return $ver }

    # Método 2: Invoke-RestMethod com Accept: application/octet-stream
    Write-Info "  A tentar Invoke-RestMethod com Accept: application/octet-stream..."
    try {
        Invoke-RestMethod -Uri $assetUrl -OutFile $Dest -TimeoutSec 120 `
            -Headers @{ Accept = "application/octet-stream"; "User-Agent" = "PowerShell" } -ErrorAction Stop
        if ((Test-Path $Dest) -and (Get-Item $Dest).Length -ge $MinBytes) { return $ver }
        Remove-Item $Dest -Force -ErrorAction SilentlyContinue
    } catch {}

    # Método 3: curl.exe nativo (WinHTTP — stack diferente do PS)
    $curlExe = "$env:SystemRoot\System32\curl.exe"
    if (Test-Path $curlExe) {
        Write-Info "  A tentar curl.exe nativo (WinHTTP)..."
        try {
            & $curlExe -fsSL --max-time 120 --proxy-negotiate -o $Dest $assetUrl 2>&1 | Out-Null
            if ((Test-Path $Dest) -and (Get-Item $Dest).Length -ge $MinBytes) { return $ver }
            Remove-Item $Dest -Force -ErrorAction SilentlyContinue
        } catch {}
    }

    Write-Warn "  Todos os métodos falharam."
    Write-Warn "  Download manual: $assetUrl"
    return $null
}

function Run-Scan {
    param([string]$Label, [string]$OutFile, [scriptblock]$ScriptBlock)
    Write-Info "A correr: $Label..."
    try {
        & $ScriptBlock 2>&1 3>&1 5>&1 | Out-File -FilePath $OutFile -Encoding UTF8 -Force
    } catch {
        "ERRO: $($_.Exception.Message)" | Out-File -FilePath $OutFile -Encoding UTF8
    }
    if (Test-Path $OutFile) {
        $sz = [math]::Round((Get-Item $OutFile).Length / 1KB, 1)
        if ($sz -gt 0) { Write-Info "  ✔ $Label ($sz KB)" } else { Write-Warn "  ⚠ $Label output vazio" }
    }
}

function Get-ExeVersion {
    param([string[]]$Paths)
    foreach ($p in $Paths) {
        if (Test-Path $p) {
            $v = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($p).FileVersion
            if ($v -and $v.Trim() -ne "" -and $v -ne "0.0.0.0") { return ($v.Trim() -split " ")[0] }
            $fv = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($p)
            $v2 = "$($fv.FileMajorPart).$($fv.FileMinorPart).$($fv.FileBuildPart).$($fv.FilePrivatePart)"
            if ($v2 -ne "0.0.0.0") { return $v2 }
        }
    }
    return $null
}

function Get-RegVersion {
    param([string]$Pattern)
    $roots = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    foreach ($r in $roots) {
        $m = Get-ItemProperty $r -ErrorAction SilentlyContinue |
             Where-Object { $_.DisplayName -match $Pattern -and $_.DisplayVersion } |
             Select-Object -First 1
        if ($m) { return [PSCustomObject]@{ Name=$m.DisplayName; Version=$m.DisplayVersion.Trim(); Publisher=$m.Publisher } }
    }
    return $null
}

function Escape-Html {
    param([string]$s)
    if ([string]::IsNullOrEmpty($s)) { return "" }
    $s -replace "&","&amp;" -replace "<","&lt;" -replace ">","&gt;" -replace '"',"&quot;"
}

function Colorize-Html {
    param([string]$s)
    # IMPORTANTE: aplicar CVE/CWE PRIMEIRO (tags inline curtas).
    # Depois aplicar tags de linha inteira — usar regex non-greedy ($) para não engolir múltiplas linhas.
    $s = $s -replace "(CVE-\d{4}-\d+)",  '<span class="cve-inline">$1</span>'
    $s = $s -replace "(CWE-\d+)",        '<span class="cwe-inline">$1</span>'
    # Linhas inteiras — non-greedy, ancorado a fim de linha
    $s = $s -replace "(?m)^([^\r\n]*CRÍTICO[^\r\n]*)$",  '<span class="finding-line">$1</span>'
    $s = $s -replace "(?m)^([^\r\n]*CRITICAL[^\r\n]*)$", '<span class="finding-line">$1</span>'
    $s = $s -replace "(?m)^([^\r\n]*ALERTA[^\r\n]*)$",   '<span class="alert-line">$1</span>'
    $s = $s -replace "(?m)^([^\r\n]*\[HIGH\][^\r\n]*)$", '<span class="alert-line">$1</span>'
    $s = $s -replace "(?m)^([^\r\n]*\bOK:[^\r\n]*)$",    '<span class="ok-line">$1</span>'
    return $s
}

function Invoke-NvdApi {
    param([string]$Keyword, [int]$ResultsPerPage = 10, [int]$Retries = 1)
    $kw  = [Uri]::EscapeUriString($Keyword)
    $url = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${kw}&resultsPerPage=${ResultsPerPage}"
    # Headers: incluir API key se disponivel (#2 — 10x rate limit)
    $headers = @{}
    if ($script:NvdApiKey -and $script:NvdApiKey -ne "") {
        $headers["apiKey"] = $script:NvdApiKey
    }
    for ($attempt = 0; $attempt -le $Retries; $attempt++) {
        try {
            if ($headers.Count -gt 0) {
                return Invoke-RestMethod -Uri $url -TimeoutSec 25 -Headers $headers -ErrorAction Stop
            } else {
                return Invoke-RestMethod -Uri $url -TimeoutSec 25 -ErrorAction Stop
            }
        } catch {
            $statusCode = 0
            try { $statusCode = [int]$_.Exception.Response.StatusCode } catch {}
            if ($statusCode -eq 429 -and $attempt -lt $Retries) {
                Write-Warn "  NVD 429 rate limit — retry em 32s..."
                Start-Sleep -Seconds 32
                continue
            }
            throw
        }
    }
}

# Sleep entre requests NVD — ajustado pela presença de API key
function Get-NvdSleep {
    if ($script:NvdApiKey -and $script:NvdApiKey -ne "") { return 1 }
    else { return 7 }
}
function Get-NvdBatchSleep {
    if ($script:NvdApiKey -and $script:NvdApiKey -ne "") { return 6 }
    else { return 32 }
}

function Get-Category {
    param([string]$base)
    switch -Regex ($base) {
        '^01_sysinfo'      { return 'system' }
        '^02_users'        { return 'system' }
        '^03_network'      { return 'network' }
        '^04_winpeas'      { return 'privesc' }
        '^05_seatbelt'     { return 'hardening' }
        '^06_privesc'      { return 'privesc' }
        '^07_trivy'        { return 'cve' }
        '^08_nvd'          { return 'cve' }
        '^09_registry'     { return 'hardening' }
        '^10_services'     { return 'privesc' }
        '^11_patch'        { return 'cve' }
        '^12_app'          { return 'cve' }
        default            { return 'other' }
    }
}

# ─── AV Exclusion ─────────────────────────────────────────────────
$AvExclusionAdded = $false
if ($AvExclusion -and $IsAdmin) {
    Write-Sec "AV Exclusion"
    try {
        $def = Get-MpPreference -ErrorAction Stop
        if ($def.ExclusionPath -notcontains $Tools) {
            Add-MpPreference -ExclusionPath $Tools -ErrorAction Stop
            $AvExclusionAdded = $true
            Write-Info "AV exclusion adicionada: $Tools"
        } else { Write-Info "AV exclusion já existente" }
    } catch { Write-Warn "AV exclusion falhou: $($_.Exception.Message)" }
    $null = Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
        if ($script:AvExclusionAdded) {
            Remove-MpPreference -ExclusionPath $script:Tools -ErrorAction SilentlyContinue
        }
    }
}

# ═══════════════════════════════════════════════════════════════════
# FASE 1 — DOWNLOAD DE FERRAMENTAS
# ═══════════════════════════════════════════════════════════════════
Write-Step "FASE 1 — Ferramentas"

# ── winPEAS ───────────────────────────────────────────────────────
$WinPeas = "$Tools\winPEASany_ofs.exe"
if ($SkipDownload -and (Test-Path $WinPeas)) { Write-Info "winPEAS — cache OK (skip)" }
elseif (-not (Test-Path $WinPeas) -and -not $SkipDownload) {
    Ensure-Tool "winPEAS" $WinPeas @(
        "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASany_ofs.exe"
    ) 500000 | Out-Null
}
elseif (Test-Path $WinPeas) { Write-Info "winPEAS — cache OK" }

# ── Seatbelt ──────────────────────────────────────────────────────
$Seatbelt = "$Tools\Seatbelt.exe"
if (-not (Test-Path $Seatbelt) -and -not $SkipDownload) {
    $ok = Ensure-Tool "Seatbelt" $Seatbelt @(
        "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/dotnet%20v4.5%20compiled%20binaries/Seatbelt.exe",
        "https://github.com/kraloveckey/ghostpack-binaries/raw/main/Windows/Seatbelt.exe"
    ) 100000
    if (-not $ok) {
        $SharpUp = "$Tools\SharpUp.exe"
        if (Ensure-Tool "SharpUp" $SharpUp @(
            "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/dotnet%20v4.5%20compiled%20binaries/SharpUp.exe"
        ) 50000) { $Seatbelt = $SharpUp }
    }
} elseif (Test-Path $Seatbelt) { Write-Info "Seatbelt — cache OK" }

# ── PrivescCheck ──────────────────────────────────────────────────
$PrivescCheck = "$Tools\PrivescCheck.ps1"
if (-not (Test-Path $PrivescCheck) -and -not $SkipDownload) {
    Ensure-Tool "PrivescCheck" $PrivescCheck @(
        "https://github.com/itm4n/PrivescCheck/releases/latest/download/PrivescCheck.ps1",
        "https://raw.githubusercontent.com/itm4n/PrivescCheck/master/PrivescCheck.ps1"
    ) 10000 | Out-Null
} elseif (Test-Path $PrivescCheck) { Write-Info "PrivescCheck — cache OK" }

# ── Trivy ─────────────────────────────────────────────────────────
$TrivyBin = "$Tools\trivy.exe"
if (-not (Test-Path $TrivyBin) -or $Force) {
    Write-Info "A determinar versão do Trivy..."
    try {
        $rel = Invoke-RestMethod "https://api.github.com/repos/aquasecurity/trivy/releases/latest" -TimeoutSec 15
        $ver = $rel.tag_name.TrimStart("v")
        $url = "https://github.com/aquasecurity/trivy/releases/download/v${ver}/trivy_${ver}_windows-64bit.zip"
        $zip = "$Tools\trivy.zip"
        if (Safe-Download -Url $url -Dest $zip -MinBytes 5000000) {
            Expand-Archive -Path $zip -DestinationPath $Tools -Force
            Remove-Item $zip -Force -ErrorAction SilentlyContinue
            if (Test-Path $TrivyBin) { Write-Info "  Trivy v$ver OK" }
        }
    } catch { Write-Warn "  Trivy: $($_.Exception.Message)" }
} elseif (Test-Path $TrivyBin) {
    $sz = [math]::Round((Get-Item $TrivyBin).Length / 1MB)
    Write-Info "Trivy — cache OK ($sz MB)"
}

# ── Grype ─────────────────────────────────────────────────────────
$GrypeBin = "$Tools\grype.exe"
if (-not (Test-Path $GrypeBin) -or $Force) {
    Write-Info "A determinar versão do Grype..."
    try {
        $rel = Invoke-RestMethod "https://api.github.com/repos/anchore/grype/releases/latest" -TimeoutSec 15
        $ver = $rel.tag_name.TrimStart("v")
        $url = "https://github.com/anchore/grype/releases/download/v${ver}/grype_${ver}_windows_amd64.zip"
        $zip = "$Tools\grype.zip"
        if (Safe-Download -Url $url -Dest $zip -MinBytes 20000000) {
            Expand-Archive -Path $zip -DestinationPath $Tools -Force
            Remove-Item $zip -Force -ErrorAction SilentlyContinue
            if (Test-Path $GrypeBin) { Write-Info "  Grype v$ver OK" }
        }
    } catch { Write-Warn "  Grype: $($_.Exception.Message)" }
} elseif (Test-Path $GrypeBin) {
    $sz = [math]::Round((Get-Item $GrypeBin).Length / 1MB)
    Write-Info "Grype — cache OK ($sz MB)"
}

# ── OSV-Scanner ───────────────────────────────────────────────────
$OsvBin = "$Tools\osv-scanner.exe"
$OsvCmd = $null

if (Test-Path $OsvBin) {
    $OsvCmd = $OsvBin
    Write-Info "OSV-Scanner — cache OK"
} elseif (Get-Command osv-scanner -ErrorAction SilentlyContinue) {
    $OsvCmd = (Get-Command osv-scanner).Source
    Write-Info "OSV-Scanner — sistema OK ($OsvCmd)"
} elseif (-not $SkipDownload) {
    Write-Info "A determinar versão mais recente do OSV-Scanner (google)..."
    $osvZip = "$Tools\osv_tmp.zip"
    $osvTmp = "$Tools\osv_extracted"
    try {
        $osvVer = Get-GitHubRelease `
            -Repo        "google/osv-scanner" `
            -AssetFilter "*windows*amd64*.zip" `
            -Dest        $osvZip `
            -MinBytes    5000000 `
            -FallbackVer "2.3.8" `
            -FallbackUrl "https://github.com/google/osv-scanner/releases/download/v2.3.8/osv-scanner_2.3.8_windows_amd64.zip" `
            -ManualDest  $OsvBin

        if ($osvVer -and (Test-Path $osvZip)) {
            New-Item -ItemType Directory -Force -Path $osvTmp | Out-Null
            Expand-Archive -Path $osvZip -DestinationPath $osvTmp -Force -ErrorAction Stop
            $exeFound = Get-ChildItem -Path $osvTmp -Filter "osv-scanner.exe" -Recurse -ErrorAction SilentlyContinue |
                        Select-Object -First 1
            if ($exeFound) {
                Copy-Item $exeFound.FullName $OsvBin -Force
                $OsvCmd = $OsvBin
                $sz = [math]::Round((Get-Item $OsvBin).Length / 1MB, 1)
                Write-Info "  OSV-Scanner v${osvVer} extraído OK ($sz MB)"
            } else {
                Write-Warn "  OSV-Scanner: ZIP descarregado mas osv-scanner.exe não encontrado"
            }
        }
    } catch {
        Write-Warn "  OSV-Scanner: $($_.Exception.Message)"
    } finally {
        Remove-Item $osvZip -Force -ErrorAction SilentlyContinue
        Remove-Item $osvTmp -Recurse -Force -ErrorAction SilentlyContinue
    }

    if (-not $OsvCmd) { Write-Warn "  OSV-Scanner: não disponível — lock file scan será saltado" }
}

# ── Watson ────────────────────────────────────────────────────────
$WatsonBin = "$Tools\Watson.exe"
$WatsonCmd = $null

if (Test-Path $WatsonBin) {
    $WatsonCmd = $WatsonBin
    Write-Info "Watson — cache OK"
} elseif (Get-Command Watson -ErrorAction SilentlyContinue) {
    $WatsonCmd = (Get-Command Watson).Source
    Write-Info "Watson — sistema OK"
} elseif (-not $SkipDownload) {
    Write-Info "A determinar versão mais recente do Watson (jazzband)..."
    $watsonZip = "$Tools\watson_tmp.zip"
    $watsonTmp = "$Tools\watson_extracted"
    try {
        $watsonVer = Get-GitHubRelease `
            -Repo        "jazzband/Watson" `
            -AssetFilter "*.zip" `
            -Dest        $watsonZip `
            -MinBytes    20000 `
            -FallbackVer "2.1.0" `
            -FallbackUrl "https://github.com/jazzband/Watson/releases/download/v2.1.0/Watson.zip" `
            -ManualDest  $WatsonBin

        if ($watsonVer -and (Test-Path $watsonZip)) {
            New-Item -ItemType Directory -Force -Path $watsonTmp | Out-Null
            Expand-Archive -Path $watsonZip -DestinationPath $watsonTmp -Force -ErrorAction Stop
            $exeFound = Get-ChildItem -Path $watsonTmp -Filter "Watson.exe" -Recurse -ErrorAction SilentlyContinue |
                        Select-Object -First 1
            if ($exeFound) {
                Copy-Item $exeFound.FullName $WatsonBin -Force
                $WatsonCmd = $WatsonBin
                $sz = [math]::Round((Get-Item $WatsonBin).Length / 1KB)
                Write-Info "  Watson v${watsonVer} extraído OK ($sz KB)"
            } else {
                Write-Warn "  Watson: ZIP descarregado mas Watson.exe não encontrado"
            }
        }
    } catch {
        Write-Warn "  Watson: $($_.Exception.Message)"
    } finally {
        Remove-Item $watsonZip -Force -ErrorAction SilentlyContinue
        Remove-Item $watsonTmp -Recurse -Force -ErrorAction SilentlyContinue
    }

    if (-not $WatsonCmd) { Write-Warn "  Watson: não disponível — CVEs inline na fase 11 continuam activos" }
}

# Actualizar referência usada na fase 11
if ($WatsonCmd) { $WatsonBin = $WatsonCmd }

# ═══════════════════════════════════════════════════════════════════
# FASE 2 — SCANS DE SEGURANÇA
# ═══════════════════════════════════════════════════════════════════
Write-Step "FASE 2 — Scans de Segurança"

# ─── 01: Sysinfo ──────────────────────────────────────────────────
Run-Scan "01_sysinfo" "$Out\01_sysinfo.txt" {
    "=== SISTEMA ==="; "Hostname : $env:COMPUTERNAME"; "Domain   : $env:USERDOMAIN"
    "Username : $env:USERNAME"; "OS       : $([System.Environment]::OSVersion.VersionString)"
    ""; "=== SYSTEMINFO ==="; systeminfo 2>&1
    ""; "=== HOTFIXES INSTALADOS ==="; Get-HotFix -ErrorAction SilentlyContinue | Sort-Object @{Expression={ if ($_.InstalledOn) { $_.InstalledOn } else { [datetime]::MinValue } }} -Descending | Format-Table -AutoSize | Out-String
    ""; "=== PROCESSOS A CORRER ==="; Get-Process | Sort-Object CPU -Descending | Format-Table Id,Name,CPU,WorkingSet -AutoSize | Out-String
    ""; "=== DRIVES ==="; Get-PSDrive -PSProvider FileSystem | Format-Table | Out-String
}

# ─── 02: Users & Groups ───────────────────────────────────────────
Run-Scan "02_users_groups" "$Out\02_users_groups.txt" {
    "=== UTILIZADORES LOCAIS ==="; Get-LocalUser | Format-Table Name,Enabled,LastLogon,PasswordNeverExpires -AutoSize | Out-String
    ""; "=== GRUPOS LOCAIS ==="; Get-LocalGroup | Format-Table | Out-String
    ""; "=== MEMBROS ADMINISTRATORS ==="; Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | Format-Table | Out-String
    ""; "=== SENHA NUNCA EXPIRA ==="; Get-LocalUser | Where-Object { $_.PasswordNeverExpires } | ForEach-Object { "ALERTA: senha nunca expira: $($_.Name) — CWE-521" }
    ""; "=== SESSÕES ACTIVAS ==="; query session 2>&1
    ""; "=== ÚLTIMOS LOGINS ==="; Get-EventLog -LogName Security -InstanceId 4624 -Newest 20 -ErrorAction SilentlyContinue | Select-Object TimeGenerated,Message | Format-List | Out-String
}

# ─── 03: Network ──────────────────────────────────────────────────
Run-Scan "03_network" "$Out\03_network.txt" {
    "=== INTERFACES ==="; Get-NetIPAddress | Format-Table InterfaceAlias,AddressFamily,IPAddress,PrefixLength | Out-String
    ""; "=== PORTAS EM ESCUTA ==="; netstat -ano | Select-String "LISTENING"
    ""; "=== TODAS AS CONEXÕES ==="; netstat -ano 2>&1
    ""; "=== ROUTING ==="; route print 2>&1
    ""; "=== DNS ==="; Get-DnsClientServerAddress | Format-Table | Out-String
    ""; "=== FIREWALL STATUS ==="; Get-NetFirewallProfile | Format-Table Name,Enabled,DefaultInboundAction,DefaultOutboundAction | Out-String
    ""; "=== FIREWALL RULES ALLOW INBOUND ==="; Get-NetFirewallRule | Where-Object { $_.Direction -eq "Inbound" -and $_.Action -eq "Allow" -and $_.Enabled -eq "True" } | Format-Table Name,Profile,Protocol -AutoSize | Out-String
    ""; "=== SMB SHARES ==="; Get-SmbShare | Format-Table Name,Path,Description | Out-String
    Get-SmbShare | Where-Object { $_.Name -notmatch "^(ADMIN|IPC|C|D|E)\$" } | ForEach-Object { "ALERTA: Share não-standard: $($_.Name) → $($_.Path) — CWE-284" }
    ""; "=== WI-FI PROFILES ==="; netsh wlan show profiles 2>&1
}

# ─── 04: winPEAS ──────────────────────────────────────────────────
Write-Sec "04 — winPEAS"
if ($Quick) {
    "[saltado — modo rápido]" | Out-File "$Out\04_winpeas_skipped.txt" -Encoding UTF8
    Write-Warn "04_winpeas saltado (-Quick)"
} elseif (Test-Path $WinPeas) {
    Write-Info "A correr winPEAS (2-5 min)..."
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $WinPeas; $psi.Arguments = "quiet"; $psi.WorkingDirectory = $Tools
        $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
        $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
        $proc = [System.Diagnostics.Process]::Start($psi)
        $stdout = $proc.StandardOutput.ReadToEnd(); $stderr = $proc.StandardError.ReadToEnd()
        $proc.WaitForExit(300000)
        ($stdout + "`n" + $stderr) | Out-File "$Out\04_winpeas.txt" -Encoding UTF8
        $sz = [math]::Round((Get-Item "$Out\04_winpeas.txt").Length / 1KB, 1)
        Write-Info "04_winpeas OK ($sz KB)"
    } catch {
        "Erro: $($_.Exception.Message)" | Out-File "$Out\04_winpeas.txt" -Encoding UTF8
        Write-Warn "04_winpeas ERRO — pode ter sido bloqueado por AV. Tentar -AvExclusion"
    }
} else {
    Run-Scan "04_privesc_manual" "$Out\04_winpeas.txt" {
        "=== PRIVESC MANUAL ==="; ""
        "=== AlwaysInstallElevated ==="; $h=$env:HKCU; $l=$env:HKLM
        $hkcu = Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
        $hklm = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
        if ($hkcu.AlwaysInstallElevated -eq 1 -and $hklm.AlwaysInstallElevated -eq 1) { "CRÍTICO: AlwaysInstallElevated activo — CVE-2021-34527, CWE-269" }
        else { "OK: AlwaysInstallElevated não activo" }
        ""; "=== Unquoted Service Paths ==="; Get-WmiObject -Class Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.PathName -match " " -and $_.PathName -notmatch '^"' } | ForEach-Object { "CRÍTICO: Unquoted path: $($_.Name) — $($_.PathName) — CWE-428" }
        ""; "=== Scheduled Tasks ==="; Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -notlike "\Microsoft\*" } | Format-Table TaskName,TaskPath,State -AutoSize | Out-String
        ""; "=== AutoRun ==="; foreach ($p in @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run","HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")) { "--- $p ---"; Get-ItemProperty -Path $p -ErrorAction SilentlyContinue | Out-String }
    }
}

# ─── 05: Seatbelt ─────────────────────────────────────────────────
Write-Sec "05 — Seatbelt"
if ($Quick) {
    "[saltado — modo rápido]" | Out-File "$Out\05_seatbelt_skipped.txt" -Encoding UTF8
    Write-Warn "05_seatbelt saltado (-Quick)"
} elseif (Test-Path $Seatbelt) {
    $isSeatbelt = (Split-Path $Seatbelt -Leaf) -eq "Seatbelt.exe"
    $toolArgs   = if ($isSeatbelt) { "-group=all" } else { "audit" }
    $toolLabel  = if ($isSeatbelt) { "Seatbelt" } else { "SharpUp" }
    Write-Info "A correr $toolLabel..."
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $Seatbelt; $psi.Arguments = $toolArgs; $psi.WorkingDirectory = $Tools
        $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
        $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
        $proc = [System.Diagnostics.Process]::Start($psi)
        $stdout = $proc.StandardOutput.ReadToEnd(); $stderr = $proc.StandardError.ReadToEnd()
        $proc.WaitForExit(120000)
        ($stdout + "`n" + $stderr) | Out-File "$Out\05_seatbelt.txt" -Encoding UTF8
        $sz = [math]::Round((Get-Item "$Out\05_seatbelt.txt").Length / 1KB, 1)
        Write-Info "05_seatbelt OK ($sz KB)"
    } catch {
        "Erro: $($_.Exception.Message)" | Out-File "$Out\05_seatbelt.txt" -Encoding UTF8
        Write-Warn "05_seatbelt ERRO"
    }
} else {
    "Seatbelt não disponível — instalar em: https://github.com/GhostPack/Seatbelt" |
        Out-File "$Out\05_seatbelt.txt" -Encoding UTF8
}

# ─── 06: PrivescCheck ─────────────────────────────────────────────
Write-Sec "06 — PrivescCheck"
if (Test-Path $PrivescCheck) {
    Write-Info "A correr PrivescCheck..."
    $runAsAdmin = $IsAdmin
    try {
        $pcJob = Start-Job -ScriptBlock {
            param($pc,$outBase,$runAsAdmin)
            # Suprimir warnings do PS dentro do job
            $WarningPreference = "SilentlyContinue"
            Import-Module $pc -Force -ErrorAction Stop -WarningAction SilentlyContinue
            Invoke-PrivescCheck -Extended -Force -Risky -Report $outBase -Format TXT,HTML,CSV 2>&1
        } -ArgumentList $PrivescCheck,"$Out\06_privesc",$runAsAdmin
        Wait-Job $pcJob -Timeout 300 | Out-Null
        $jobOut = Receive-Job $pcJob -WarningAction SilentlyContinue
        Remove-Job $pcJob -Force

        # Separar warnings esperados (admin) do output real
        # Warnings do PrivescCheck quando admin são informativos — guardar no .txt mas não poluir o terminal
        $privescWarnings = @($jobOut | Where-Object { $_ -match "^WARNING:.*won't give proper results when run as an administrator" })
        $privescOutput   = @($jobOut | Where-Object { $_ -notmatch "^WARNING:.*won't give proper results when run as an administrator" })

        $adminWarningNote = if ($privescWarnings.Count -gt 0) {
            @("","=== NOTA: $($privescWarnings.Count) checks ignorados por correr como Admin ===",
              "(Para estes checks: correr sem privilégios elevados para resultados completos)",
              "Checks ignorados:", ($privescWarnings -join "`n"), "")
        } else { @() }

        @("=== PRIVESCCHECK OUTPUT ===","Correu como Admin: $runAsAdmin","",
          "NOTA: Quando Admin, checks de ACL/serviços são menos fiáveis.","","") `
          + $privescOutput + $adminWarningNote |
            Out-File "$Out\06_privesc.txt" -Encoding UTF8

        # Só mostrar no terminal se houve warnings (1 linha resumida)
        if ($privescWarnings.Count -gt 0) {
            Write-Info "06_privesc OK ($($privescWarnings.Count) checks ignorados — ver .txt para detalhe)"
        } else {
            Write-Info "06_privesc OK"
        }
    } catch {
        "Erro: $($_.Exception.Message)" | Out-File "$Out\06_privesc.txt" -Encoding UTF8
        Write-Warn "06_privesc ERRO: $($_.Exception.Message)"
    }
} else {
    Run-Scan "06_services_manual" "$Out\06_privesc.txt" {
        "=== SERVIÇOS ==="; Get-Service | Format-Table Name,DisplayName,Status,StartType | Out-String
        ""; "=== UNQUOTED PATHS ==="; Get-WmiObject -Class Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.PathName -match " " -and $_.PathName -notmatch '^"' } | ForEach-Object { "CRÍTICO: $($_.Name) | $($_.PathName) — CWE-428" }
        ""; "=== SCHEDULED TASKS NÃO-MICROSOFT ==="; Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -notlike "\Microsoft\*" -and $_.State -ne "Disabled" } | Format-Table TaskName,TaskPath,State -AutoSize | Out-String
    }
}

# ─── 07: Trivy (texto) ────────────────────────────────────────────
Write-Sec "07 — Trivy"
if (Test-Path $TrivyBin) {
    $scanners = if ($DeepScan) { "vuln,secret,misconfig" } else { "vuln" }
    Write-Info "A correr Trivy (texto, scanners: $scanners)..."
    try {
        & $TrivyBin fs "C:\" --scanners $scanners --severity CRITICAL,HIGH,MEDIUM `
            --format table --no-progress --timeout 10m `
            --skip-dirs "C:\Windows\WinSxS,C:\Windows\SoftwareDistribution" `
            --output "$Out\07_trivy.txt" 2>&1 | Out-Null
        Write-Info "07_trivy OK"
    } catch { Write-Warn "07_trivy ERRO: $($_.Exception.Message)" }
} else {
    "Trivy não disponível" | Out-File "$Out\07_trivy.txt" -Encoding UTF8
}

# ─── 08: NVD CVE Lookup básico ────────────────────────────────────
Write-Sec "08 — NVD Lookup"
if ($NoNvd) {
    "[saltado — -NoNvd activo]" | Out-File "$Out\08_nvd_cve_skipped.txt" -Encoding UTF8
    Write-Warn "08_nvd_cve saltado"
} else {
    $nvdOut = [System.Collections.Generic.List[string]]::new()
    $nvdOut.Add("=== NVD API CVE/CWE LOOKUP ==="); $nvdOut.Add("Data: $(Get-Date)"); $nvdOut.Add("")
    $components = [ordered]@{}
    $osInfo2 = Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue
    if ($osInfo2.Version) { $components["windows"] = $osInfo2.Version }
    $iisV = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\InetStp" -ErrorAction SilentlyContinue).VersionString
    if ($iisV) { $components["iis"] = $iisV }
    # SSH: o OpenSSH do Windows não tem ProductVersion no registry — usar FileVersionInfo do ssh.exe
    $sshCmd = Get-Command ssh.exe -ErrorAction SilentlyContinue
    if ($sshCmd) {
        $sshV = $sshCmd.Version.ToString()
        if (-not $sshV -or $sshV -eq "0.0.0.0") {
            # Fallback: parsear output de "ssh -V" (vai para stderr)
            $sshOut = & ssh.exe -V 2>&1 | Out-String
            if ($sshOut -match "OpenSSH_for_Windows_(\d+\.\d+[.\dp]*)") { $sshV = $Matches[1] }
            elseif ($sshOut -match "OpenSSH_(\d+\.\d+[.\dp]*)") { $sshV = $Matches[1] }
        }
        if ($sshV) { $components["openssh"] = $sshV }
    }
    $dnV = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -ErrorAction SilentlyContinue).Version
    if ($dnV) { $components["dotnet"] = $dnV }
    foreach ($pkg in $components.Keys) {
        $ver = $components[$pkg]; $nvdOut.Add("─── $pkg $ver ───")
        try {
            $resp = Invoke-NvdApi -Keyword $pkg -ResultsPerPage 5 -Retries 1
            foreach ($v in $resp.vulnerabilities | Select-Object -First 5) {
                $cveId = $v.cve.id; $sev = "N/A"
                foreach ($mk in @("cvssMetricV31","cvssMetricV30","cvssMetricV2")) { $ms = $v.cve.metrics.$mk; if ($ms) { $sev = $ms[0].cvssData.baseSeverity; break } }
                $cwes = (@($v.cve.weaknesses | ForEach-Object { $_.description | Where-Object { $_.value -like "CWE-*" } | Select-Object -ExpandProperty value }) -join ", ")
                $desc = ($v.cve.descriptions | Where-Object { $_.lang -eq "en" } | Select-Object -First 1).value
                if ($desc.Length -gt 120) { $desc = $desc.Substring(0,120) + "..." }
                $nvdOut.Add("  $cveId [$sev] CWE: $cwes"); $nvdOut.Add("  Desc: $desc"); $nvdOut.Add("")
            }
        } catch { $nvdOut.Add("  NVD API erro: $($_.Exception.Message)") }
        $nvdOut.Add(""); Start-Sleep -Seconds (Get-NvdSleep)
    }
    $nvdOut | Out-File "$Out\08_nvd_cve.txt" -Encoding UTF8; Write-Info "08_nvd_cve OK"
}

# ─── 09: Registry ─────────────────────────────────────────────────
Run-Scan "09_registry" "$Out\09_registry.txt" {
    "=== REGISTRY AUDIT ==="; ""
    "--- AutoRun ---"
    foreach ($k in @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run","HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run","HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce")) {
        $p = Get-ItemProperty $k -ErrorAction SilentlyContinue
        if ($p) { $p.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object { "  ALERTA AutoRun: $($_.Name) = $($_.Value) — CWE-284" } }
    }
    ""; "--- LSA ---"
    $lsa = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue
    if ($lsa.RunAsPPL -ne 1)          { "  ALERTA: LSA RunAsPPL não activo — CWE-522" } else { "  OK: LSA RunAsPPL activo" }
    if ($lsa.LmCompatibilityLevel -lt 5) { "  ALERTA: LmCompatibilityLevel=$($lsa.LmCompatibilityLevel) — CWE-287" } else { "  OK: LmCompatibilityLevel=$($lsa.LmCompatibilityLevel)" }
    ""; "--- WDigest ---"
    $wdig = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -ErrorAction SilentlyContinue
    if ($wdig.UseLogonCredential -eq 1) { "  CRÍTICO: WDigest UseLogonCredential=1 — passwords em memória — CWE-522" } else { "  OK: WDigest desactivado" }
    ""; "--- AutoLogon ---"
    $al = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue
    $dp = $al.PSObject.Properties["DefaultPassword"]
    if ($dp -and $dp.Value -ne "") { "  CRÍTICO: AutoLogon com password em texto claro — CWE-256" } else { "  OK: AutoLogon sem password" }
    ""; "--- UAC ---"
    $uac = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue
    if ($uac.EnableLUA -eq 0) { "  CRÍTICO: UAC desactivado — CWE-269" } elseif ($uac.ConsentPromptBehaviorAdmin -eq 0) { "  ALERTA: UAC sem prompt para admins — CWE-269" } else { "  OK: UAC activo" }
    ""; "--- SMBv1 ---"
    $smb1 = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -ErrorAction SilentlyContinue
    if ($smb1.SMB1 -eq 1) { "  CRÍTICO: SMBv1 activo — CVE-2017-0144 (EternalBlue) — CWE-327" } else { "  OK: SMBv1 desactivado" }
    ""; "--- RDP ---"
    $rdp = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -ErrorAction SilentlyContinue
    if ($rdp.UserAuthentication -ne 1) { "  ALERTA: RDP sem NLA — CWE-287" } else { "  OK: RDP com NLA" }
    if ($rdp.SecurityLayer -lt 2)      { "  ALERTA: RDP SecurityLayer=$($rdp.SecurityLayer) — CWE-319" } else { "  OK: RDP TLS activo" }
    ""; "--- PS Logging ---"
    $psLog = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue
    if ($psLog.EnableScriptBlockLogging -ne 1) { "  ALERTA: PS ScriptBlock Logging desactivado — CWE-778" } else { "  OK: PS Logging activo" }
}

# ─── 10: Services ─────────────────────────────────────────────────
Run-Scan "10_services" "$Out\10_services.txt" {
    "=== SERVIÇOS — ANÁLISE DE SEGURANÇA ==="; ""
    "--- Unquoted Paths ---"
    $unq = Get-WmiObject -Class Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.PathName -match " " -and $_.PathName -notmatch '^"' -and $_.PathName -notmatch "^C:\\Windows" }
    if ($unq) { foreach ($s in $unq) { "  CRÍTICO: $($s.Name) | $($s.StartMode) | $($s.PathName) — CWE-428" } } else { "  OK: Sem unquoted paths" }
    ""; "--- DLL Hijack Potencial ---"
    Get-WmiObject -Class Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.PathName -like "*.exe*" -and $_.State -eq "Running" } | ForEach-Object {
        $exePath = $_.PathName -replace '"','' -replace ' .*',''; $dir = Split-Path $exePath -Parent -ErrorAction SilentlyContinue
        if ($dir -and (Test-Path $dir)) {
            $acl = Get-Acl $dir -ErrorAction SilentlyContinue
            if ($acl) { $w = $acl.Access | Where-Object { $_.FileSystemRights -match "Write|FullControl" -and $_.IdentityReference -match "Users|Everyone|Authenticated" }; if ($w) { "  ALERTA: Dir gravável: $dir ($($_.Name)) — CWE-427" } }
        }
    }
    ""; "--- Tarefas Agendadas Não-Microsoft ---"
    Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -notlike "\Microsoft\*" -and $_.State -ne "Disabled" } | ForEach-Object {
        $exec = if ($_.Actions[0].Execute) { $_.Actions[0].Execute } else { "N/A" }
        "  $($_.TaskName) | $($_.TaskPath) | $exec | $($_.State)"
    }
    ""; "--- Software Instalado ---"
    $sw = @()
    $sw += Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue
    $sw += Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue
    $sw | Where-Object { $_.DisplayName } | Select-Object DisplayName,DisplayVersion,Publisher | Sort-Object DisplayName | Format-Table -AutoSize | Out-String
}

# ─── 11: Patch Gap Analysis ───────────────────────────────────────
Write-Sec "11 — Patch Gap Analysis"
$patchOut = [System.Collections.Generic.List[string]]::new()
$patchOut.Add("=== PATCH GAP ANALYSIS ==="); $patchOut.Add("Data: $(Get-Date)"); $patchOut.Add("")
$osInfo3   = Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue
$osBuild   = $osInfo3.BuildNumber; $osVer3 = $osInfo3.Version; $osName3 = $osInfo3.Caption

# Camada A — WES-NG
$patchOut.Add("══ CAMADA A — WES-NG ══"); $patchOut.Add("")
$pythonCmd = @("python","python3") | Where-Object { Get-Command $_ -ErrorAction SilentlyContinue } | Select-Object -First 1
if (-not $pythonCmd) {
    $patchOut.Add("[!] Python não encontrado — WES-NG indisponível")
    Write-Warn "Python não encontrado — WES-NG saltado"
} else {
    $wesInstalled = $false
    try { $wesVer = & $pythonCmd -m wesng --version 2>&1; if ($wesVer -notmatch "error|not found") { $wesInstalled = $true } } catch {}
    if (-not $wesInstalled) {
        try { & $pythonCmd -m pip install wesng --quiet 2>&1 | Out-Null; $wesInstalled = $true; Write-Info "WES-NG instalado" } catch { Write-Warn "WES-NG install falhou" }
    }
    if ($wesInstalled) {
        & $pythonCmd -m wesng --update 2>&1 | Out-Null
        $sysinfoTmp = "$Out\sysinfo_wes.txt"; systeminfo 2>&1 | Out-File $sysinfoTmp -Encoding UTF8
        try {
            $wesResult = & $pythonCmd -m wesng $sysinfoTmp --hide "Explicitly Patched" 2>&1 | Out-String
            $patchOut.Add($wesResult)
            Write-Info "WES-NG OK — $([regex]::Matches($wesResult,'CVE-\d{4}-\d+').Count) CVEs"
        } catch { $patchOut.Add("[!] WES-NG erro: $($_.Exception.Message)") }
    }
}

# Camada B — MSRC API
$patchOut.Add(""); $patchOut.Add("══ CAMADA B — MSRC API ══"); $patchOut.Add("")
$msrcProduct = switch -Regex ($osVer3) {
    "^10\.0\.26"  { "Windows 11 Version 24H2" }
    "^10\.0\.225" { "Windows 11 Version 23H2" }
    "^10\.0\.222" { "Windows 11 Version 22H2" }
    "^10\.0\.190" { "Windows 10 Version 22H2" }
    default       { "Windows 10" }
}
$patchOut.Add("Produto: $msrcProduct (build $osBuild)")
try {
    $msrcBase = "https://api.msrc.microsoft.com/cvrf/v3.0"
    $updatesResp = Invoke-RestMethod "$msrcBase/Updates" -TimeoutSec 20 -ErrorAction Stop
    $recentUpdates = $updatesResp.value | Where-Object { try { [datetime]$_.CurrentReleaseDate -gt (Get-Date).AddMonths(-6) } catch { $false } } | Sort-Object CurrentReleaseDate -Descending | Select-Object -First 4
    foreach ($update in $recentUpdates) {
        $patchOut.Add("─── Patch Tuesday: $($update.CurrentReleaseDate) ───")
        try {
            $cvrf = Invoke-RestMethod "$msrcBase/cvrf/$($update.ID)" -TimeoutSec 30 -ErrorAction Stop
            $notPatched = $cvrf.Vulnerability | Where-Object {
                $kbsNeeded = $_.Remediations | Where-Object { $_.Type -eq 10 } | ForEach-Object { if ($_.Description.Value -match "(KB\d+)") { $matches[1] } } | Where-Object { $_ }
                if ($kbsNeeded) { ($kbsNeeded | Where-Object { $hotfixes -contains $_ }).Count -eq 0 } else { $false }
            }
            foreach ($vuln in ($notPatched | Select-Object -First 15)) {
                $sevL = if ($vuln.Threats[0].Description.Value -match "Critical") { "CRÍTICO" } elseif ($vuln.Threats[0].Description.Value -match "Important") { "ALERTA" } else { "INFO" }
                $exploited = if (($vuln.Threats | Where-Object { $_.Type -eq 1 } | Select-Object -First 1).Description.Value -match "Exploited:Yes") { " *** EXPLOITED ***" } else { "" }
                $kbs = ($vuln.Remediations | Where-Object { $_.Type -eq 10 } | ForEach-Object { if ($_.Description.Value -match "(KB\d+)") { $matches[1] } } | Where-Object { $_ } | Sort-Object -Unique) -join ", "
                $patchOut.Add("  $sevL [$($vuln.CVE)] $($vuln.Title.Value)$exploited")
                if ($kbs) { $patchOut.Add("  KB necessário: $kbs") }
                $patchOut.Add("")
            }
            if ($notPatched.Count -eq 0) { $patchOut.Add("  OK: Sem CVEs não-patchados este mês") }
        } catch { $patchOut.Add("  Erro CVRF $($update.ID): $($_.Exception.Message)") }
        Start-Sleep -Milliseconds 500
    }
} catch { $patchOut.Add("[!] MSRC API erro: $($_.Exception.Message)") }

# Camada C — Watson / Inline CVEs
$patchOut.Add(""); $patchOut.Add("══ CAMADA C — Watson / CVEs inline ══"); $patchOut.Add("")
if (Test-Path $WatsonBin) {
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo; $psi.FileName = $WatsonBin
        $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
        $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
        $proc = [System.Diagnostics.Process]::Start($psi)
        $watsonResult = $proc.StandardOutput.ReadToEnd() + $proc.StandardError.ReadToEnd()
        $proc.WaitForExit(60000); $patchOut.Add($watsonResult); Write-Info "Watson OK"
    } catch { $patchOut.Add("[!] Watson erro: $($_.Exception.Message)") }
} else {
    $patchOut.Add("[Watson não disponível — checks inline]"); $patchOut.Add("")
    function Test-KB { param([string]$KB); return ($hotfixes -contains $KB) }
    $knownCves = @(
        [PSCustomObject]@{ CVE="CVE-2025-21333"; Sev="CRÍTICO"; Name="Hyper-V NT Kernel EoP (exploited)"; KB=@("KB5050009","KB5050011","KB5050013","KB5050014"); MinBuild=19041 }
        [PSCustomObject]@{ CVE="CVE-2025-24983"; Sev="HIGH";    Name="Win32k UAF EoP (exploited)";       KB=@("KB5053598","KB5053599"); MinBuild=0 }
        [PSCustomObject]@{ CVE="CVE-2025-26633"; Sev="HIGH";    Name="MSC EvilTwin (exploited)";         KB=@("KB5053598","KB5053599"); MinBuild=0 }
        [PSCustomObject]@{ CVE="CVE-2024-38080"; Sev="CRÍTICO"; Name="Hyper-V EoP (exploited)";         KB=@("KB5040427","KB5040430"); MinBuild=19041 }
        [PSCustomObject]@{ CVE="CVE-2024-21338"; Sev="CRÍTICO"; Name="AppLocker Driver EoP";             KB=@("KB5034763","KB5034765"); MinBuild=19041 }
        [PSCustomObject]@{ CVE="CVE-2023-28252"; Sev="CRÍTICO"; Name="CLFS EoP (exploited)";             KB=@("KB5025221","KB5025224"); MinBuild=0 }
        [PSCustomObject]@{ CVE="CVE-2022-0847";  Sev="CRÍTICO"; Name="PrintNightmare Spooler";           KB=@("KB5010386","KB5010392"); MinBuild=0 }
        [PSCustomObject]@{ CVE="CVE-2021-34527"; Sev="CRÍTICO"; Name="PrintNightmare";                   KB=@("KB5004945","KB5004946"); MinBuild=0 }
        [PSCustomObject]@{ CVE="CVE-2021-36934"; Sev="CRÍTICO"; Name="HiveNightmare/SeriousSAM";         KB=@("KB5005010","KB5005030"); MinBuild=0 }
        [PSCustomObject]@{ CVE="CVE-2020-0796";  Sev="CRÍTICO"; Name="SMBGhost";                         KB=@("KB4551762"); MinBuild=18362 }
        [PSCustomObject]@{ CVE="CVE-2020-1472";  Sev="CRÍTICO"; Name="ZeroLogon (Netlogon)";             KB=@("KB4571694","KB4571702"); MinBuild=0 }
        [PSCustomObject]@{ CVE="CVE-2019-0708";  Sev="CRÍTICO"; Name="BlueKeep (RDP RCE)";               KB=@("KB4499175","KB4499180"); MinBuild=0 }
        [PSCustomObject]@{ CVE="CVE-2017-0144";  Sev="CRÍTICO"; Name="EternalBlue (SMBv1)";              KB=@("KB4012212","KB4013429"); MinBuild=0 }
    )
    $found = 0
    foreach ($e in $knownCves) {
        if ($e.MinBuild -gt 0 -and [int]$osBuild -lt $e.MinBuild) { continue }
        $patched = $e.KB | Where-Object { $hotfixes -contains $_ }
        if (-not $patched) {
            $patchOut.Add("  $($e.Sev): $($e.CVE) — $($e.Name)")
            $patchOut.Add("  KBs: $($e.KB -join ', ')"); $patchOut.Add(""); $found++
        }
    }
    if ($found -eq 0) { $patchOut.Add("  OK: Nenhum CVE conhecido não-patchado detectado") }
    else { $patchOut.Add("TOTAL não-patchados: $found") }
}
$patchOut | Out-File "$Out\11_patch_gap.txt" -Encoding UTF8; Write-Info "11_patch_gap OK"

# ─── 12: App Vulns ────────────────────────────────────────────────
Write-Sec "12 — App Vulns"
$appOutput = [System.Collections.Generic.List[string]]::new()
$appOutput.Add("=== APPLICATION VULNERABILITY SCAN ==="); $appOutput.Add("Data: $(Get-Date)"); $appOutput.Add("")

# Inventário via registry
$appOutput.Add("══ INVENTÁRIO ══"); $appOutput.Add("")
$appOutput.Add("--- Registry (Uninstall) ---")
$regPaths = @("HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*","HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*","HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*")
$allApps = @(); foreach ($rp in $regPaths) { $allApps += Get-ItemProperty $rp -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -and $_.DisplayVersion } }
$allApps | Sort-Object DisplayName -Unique | ForEach-Object { $appOutput.Add("  $($_.DisplayName) == $($_.DisplayVersion)  [$($_.Publisher)]") }
$appOutput.Add("")

# winget, choco, scoop
$appOutput.Add("--- winget ---")
if (Get-Command winget -ErrorAction SilentlyContinue) { winget list 2>&1 | Select-Object -Skip 2 | ForEach-Object { $appOutput.Add("  $_") } } else { $appOutput.Add("  winget não encontrado") }
$appOutput.Add("")
$appOutput.Add("--- Chocolatey ---")
if (Get-Command choco -ErrorAction SilentlyContinue) { choco list --local-only 2>&1 | ForEach-Object { $appOutput.Add("  $_") } } else { $appOutput.Add("  Chocolatey não encontrado") }
$appOutput.Add("")
$appOutput.Add("--- Scoop ---")
if (Get-Command scoop -ErrorAction SilentlyContinue) { scoop list 2>&1 | ForEach-Object { $appOutput.Add("  $_") } } else { $appOutput.Add("  Scoop não encontrado") }
$appOutput.Add("")

# Runtimes
$appOutput.Add("--- Runtimes ---")
foreach ($rt in @{python="python --version";node="node --version";java="java -version";dotnet="dotnet --version";git="git --version";openssl="openssl version"}.GetEnumerator()) {
    try { $v = Invoke-Expression $rt.Value 2>&1 | Select-Object -First 1; if ($v) { $appOutput.Add("  $($rt.Key): $v") } } catch {}
}
if (Get-Command dotnet -ErrorAction SilentlyContinue) {
    $appOutput.Add("  .NET SDKs:"); dotnet --list-sdks 2>&1 | ForEach-Object { $appOutput.Add("    $_") }
}
if (Get-Command pip -ErrorAction SilentlyContinue) {
    $appOutput.Add("  pip packages:"); pip list 2>&1 | Select-Object -Skip 2 -First 30 | ForEach-Object { $appOutput.Add("    $_") }
}
$appOutput.Add("")

# Browsers
$appOutput.Add("--- Browsers ---")
$browserPaths = @(
    @{Name="Chrome"; Path="$env:ProgramFiles\Google\Chrome\Application\chrome.exe"},
    @{Name="Chrome(x86)"; Path="${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"},
    @{Name="Firefox"; Path="$env:ProgramFiles\Mozilla Firefox\firefox.exe"},
    @{Name="Edge"; Path="${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"},
    @{Name="Brave"; Path="$env:ProgramFiles\BraveSoftware\Brave-Browser\Application\brave.exe"},
    @{Name="Opera"; Path="$env:AppData\Opera Software\Opera Stable\opera.exe"}
)
foreach ($b in $browserPaths) { if (Test-Path $b.Path) { $ver = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($b.Path).FileVersion; $appOutput.Add("  $($b.Name): $ver") } }

# Office
$appOutput.Add(""); $appOutput.Add("--- Office ---")
foreach ($ok in @("HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration","HKLM:\SOFTWARE\Wow6432Node\Microsoft\Office\ClickToRun\Configuration")) {
    $o = Get-ItemProperty $ok -ErrorAction SilentlyContinue; if ($o.VersionToReport) { $appOutput.Add("  Office C2R: $($o.VersionToReport)"); break }
}
$appOutput.Add("")

# OSV-Scanner
$appOutput.Add("══ OSV-SCANNER ══"); $appOutput.Add("")
if ($OsvCmd -and (Test-Path $OsvCmd)) {
    $lockPatterns = @("package-lock.json","yarn.lock","requirements.txt","Pipfile.lock","go.sum","Cargo.lock","packages.lock.json")
    $lockFiles = @(); $searchRoots = @($env:USERPROFILE,"$env:USERPROFILE\Documents","$env:USERPROFILE\Desktop","C:\inetpub","C:\Projects")
    foreach ($root in $searchRoots) {
        if (-not (Test-Path $root)) { continue }
        foreach ($pat in $lockPatterns) {
            $lockFiles += Get-ChildItem -Path $root -Filter $pat -Recurse -ErrorAction SilentlyContinue -Depth 5 | Where-Object { $_.FullName -notmatch "node_modules|\.git" } | Select-Object -First 3
        }
    }
    if ($lockFiles.Count -gt 0) {
        $appOutput.Add("Lock files encontrados: $($lockFiles.Count)")
        foreach ($lf in $lockFiles | Select-Object -First 15) {
            $appOutput.Add("  Scanning: $($lf.FullName)")
            try { $appOutput.Add((& $OsvCmd --format table --lockfile $lf.FullName 2>&1 | Out-String)) } catch {}
        }
    } else { $appOutput.Add("Sem lock files encontrados") }
    $sbomOut = "$Out\12_sbom.cdx.json"
    try { & $OsvCmd scan --format cyclonedx-1-4 --output $sbomOut 2>&1 | Out-Null; if (Test-Path $sbomOut) { $appOutput.Add("SBOM: $sbomOut") } } catch {}
} else { $appOutput.Add("[!] OSV-Scanner não disponível (GitHub bloqueado — tentar: winget install Google.OSVScanner)") }

# Grype
$appOutput.Add(""); $appOutput.Add("══ GRYPE ══"); $appOutput.Add("")
if (Test-Path $GrypeBin) {
    & $GrypeBin db update 2>&1 | Out-Null
    try {
        $appOutput.Add((& $GrypeBin --output table --only-fixed "dir:C:\" --exclude "C:\Windows\WinSxS" --exclude "C:\Windows\SoftwareDistribution" 2>&1 | Out-String))
        & $GrypeBin --output json "dir:C:\" --file $GrypeJson --exclude "C:\Windows\WinSxS" 2>&1 | Out-Null
        if ((Test-Path $GrypeJson) -and (Get-Item $GrypeJson).Length -gt 0) {
            $gd = Get-Content $GrypeJson -Raw | ConvertFrom-Json; $bySev = @{}
            foreach ($m in $gd.matches) { $sev = $m.vulnerability.severity.ToUpper(); if (-not $bySev[$sev]) { $bySev[$sev] = @() }; $bySev[$sev] += "$($m.vulnerability.id) $($m.artifact.name)==$($m.artifact.version)" }
            foreach ($sev in @("CRITICAL","HIGH","MEDIUM","LOW")) { $items = $bySev[$sev]; if ($items) { $appOutput.Add("  $sev ($($items.Count)):"); $items | Select-Object -First 15 | ForEach-Object { $appOutput.Add("    $_") } } }
            $appOutput.Add("  TOTAL: $(($bySev.Values | Measure-Object -Sum Count).Sum)")
        }
    } catch { $appOutput.Add("  Grype erro: $($_.Exception.Message)") }
} else { $appOutput.Add("[!] Grype não disponível") }

# PURL/NVD lookup
$appOutput.Add(""); $appOutput.Add("══ PURL / NVD LOOKUP ══"); $appOutput.Add("")
if ($NoNvd) { $appOutput.Add("[saltado — -NoNvd activo]") } else {
    $purlMap = [ordered]@{}
    foreach ($b in $browserPaths) { if (Test-Path $b.Path) { $v = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($b.Path).FileVersion; if ($v) { $purlMap[$b.Name.ToLower() -replace "\(.*\)","" -replace "\s",""] = $v.Trim() } } }
    $rtNvd = @{python={"python --version 2>&1 | Select-String '\d+\.\d+\.\d+' | % { $_.Matches[0].Value }"};nodejs={"node --version 2>&1 | % { $_ -replace 'v','' }"};git={"git --version 2>&1 | Select-String '\d+\.\d+\.\d+' | % { $_.Matches[0].Value }"};openssl={"openssl version 2>&1 | Select-String '\d+\.\d+\.\d+[a-z]*' | % { $_.Matches[0].Value }"}}
    foreach ($rt in $rtNvd.Keys) { try { $v = Invoke-Expression $rtNvd[$rt]; if ($v) { $purlMap[$rt] = $v.ToString().Trim() } } catch {} }
    foreach ($ok in @("HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration")) { $o = Get-ItemProperty $ok -ErrorAction SilentlyContinue; if ($o.VersionToReport) { $purlMap["microsoft_office"] = $o.VersionToReport; break } }
    $appVers = @{
        "7-zip"=@("$env:ProgramFiles\7-Zip\7z.exe","${env:ProgramFiles(x86)}\7-Zip\7z.exe")
        "winrar"=@("$env:ProgramFiles\WinRAR\WinRAR.exe","${env:ProgramFiles(x86)}\WinRAR\WinRAR.exe")
        "vlc"=@("$env:ProgramFiles\VideoLAN\VLC\vlc.exe","${env:ProgramFiles(x86)}\VideoLAN\VLC\vlc.exe")
        "notepad++"=@("$env:ProgramFiles\Notepad++\notepad++.exe","${env:ProgramFiles(x86)}\Notepad++\notepad++.exe")
        "putty"=@("$env:ProgramFiles\PuTTY\putty.exe","${env:ProgramFiles(x86)}\PuTTY\putty.exe")
        "winscp"=@("$env:ProgramFiles\WinSCP\WinSCP.exe")
        "zoom"=@("$env:AppData\Zoom\bin\Zoom.exe","$env:ProgramFiles\Zoom\bin\Zoom.exe")
        "openvpn"=@("$env:ProgramFiles\OpenVPN\bin\openvpn.exe")
        "wireguard"=@("$env:ProgramFiles\WireGuard\wireguard.exe")
    }
    foreach ($app in $appVers.Keys) { $v = Get-ExeVersion -Paths $appVers[$app]; if ($v) { $purlMap[$app] = $v } }
    foreach ($app in $purlMap.Keys) {
        $ver = $purlMap[$app]; $appOutput.Add("─── $app $ver ───")
        try {
            $resp = Invoke-NvdApi -Keyword $app -ResultsPerPage 5 -Retries 1
            foreach ($v in $resp.vulnerabilities | Select-Object -First 5) {
                $cveId = $v.cve.id; $sev = "N/A"
                foreach ($mk in @("cvssMetricV31","cvssMetricV30","cvssMetricV2")) { $ms = $v.cve.metrics.$mk; if ($ms) { $sev = $ms[0].cvssData.baseSeverity; break } }
                $desc = ($v.cve.descriptions | Where-Object { $_.lang -eq "en" } | Select-Object -First 1).value
                if ($desc.Length -gt 120) { $desc = $desc.Substring(0,120) + "..." }
                $label = if ($sev -eq "CRITICAL") { "CRÍTICO" } elseif ($sev -eq "HIGH") { "ALERTA" } else { $sev }
                $appOutput.Add("  ${label}: ${cveId} [$sev] — ${desc}")
            }
        } catch { $appOutput.Add("  NVD erro: $($_.Exception.Message)") }
        $appOutput.Add(""); Start-Sleep -Seconds (Get-NvdSleep)
    }
}

# Trivy apps
$appOutput.Add(""); $appOutput.Add("══ TRIVY — Apps ══"); $appOutput.Add("")
if (Test-Path $TrivyBin) {
    & $TrivyBin db update 2>&1 | Out-Null
    try { $appOutput.Add((& $TrivyBin fs "C:\" --scanners vuln --severity "CRITICAL,HIGH" --format table --no-progress --skip-dirs "C:\Windows\WinSxS,C:\Windows\SoftwareDistribution" 2>&1 | Out-String)) } catch { $appOutput.Add("  Trivy app scan erro: $($_.Exception.Message)") }
} else { $appOutput.Add("[!] Trivy não disponível") }

$appOutput | Out-File "$Out\12_app_vulns.txt" -Encoding UTF8
$sz = [math]::Round((Get-Item "$Out\12_app_vulns.txt" -ErrorAction SilentlyContinue).Length / 1KB, 1)
Write-Info "12_app_vulns OK ($sz KB)"

# ═══════════════════════════════════════════════════════════════════
# FASE 3 — INVENTÁRIO JSON ESTRUTURADO
# ═══════════════════════════════════════════════════════════════════
Write-Step "FASE 3 — Inventário JSON"

$Inventory = [System.Collections.Generic.List[object]]::new()

# Apps conhecidas com detecção via .exe + registry
$AppDefs = [ordered]@{
    "7-zip"       = @{ Reg="^7-Zip";             Exe=@("$env:ProgramFiles\7-Zip\7z.exe","${env:ProgramFiles(x86)}\7-Zip\7z.exe");   Nvd="7-zip";              Cat="Compression" }
    "winrar"      = @{ Reg="^WinRAR";            Exe=@("$env:ProgramFiles\WinRAR\WinRAR.exe","${env:ProgramFiles(x86)}\WinRAR\WinRAR.exe"); Nvd="winrar";    Cat="Compression" }
    "chrome"      = @{ Reg="^Google Chrome$";    Exe=@("$env:ProgramFiles\Google\Chrome\Application\chrome.exe","${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"); Nvd="google chrome"; Cat="Browser" }
    "firefox"     = @{ Reg="^Mozilla Firefox";   Exe=@("$env:ProgramFiles\Mozilla Firefox\firefox.exe"); Nvd="firefox";              Cat="Browser" }
    "edge"        = @{ Reg="^Microsoft Edge$";   Exe=@("${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"); Nvd="microsoft edge chromium"; Cat="Browser" }
    "brave"       = @{ Reg="^Brave";             Exe=@("$env:ProgramFiles\BraveSoftware\Brave-Browser\Application\brave.exe"); Nvd="brave browser"; Cat="Browser" }
    "vscode"      = @{ Reg="^Microsoft Visual Studio Code"; Exe=@("$env:ProgramFiles\Microsoft VS Code\Code.exe","$env:LocalAppData\Programs\Microsoft VS Code\Code.exe"); Nvd="visual studio code"; Cat="Editor" }
    "notepadpp"   = @{ Reg="^Notepad\+\+";       Exe=@("$env:ProgramFiles\Notepad++\notepad++.exe","${env:ProgramFiles(x86)}\Notepad++\notepad++.exe"); Nvd="notepad++"; Cat="Editor" }
    "python"      = @{ Reg="^Python \d";         Exe=@();  Nvd="python";             Cat="Runtime" }
    "nodejs"      = @{ Reg="^Node\.js";          Exe=@("$env:ProgramFiles\nodejs\node.exe"); Nvd="node.js"; Cat="Runtime" }
    "java"        = @{ Reg="^Java\(TM\)|^OpenJDK"; Exe=@(); Nvd="java jdk";         Cat="Runtime" }
    "dotnet"      = @{ Reg="^Microsoft .NET (SDK|Runtime)"; Exe=@(); Nvd="microsoft .net"; Cat="Runtime" }
    "zoom"        = @{ Reg="^Zoom$";             Exe=@("$env:AppData\Zoom\bin\Zoom.exe"); Nvd="zoom";      Cat="Communication" }
    "teams"       = @{ Reg="^Microsoft Teams";   Exe=@("$env:LocalAppData\Microsoft\Teams\current\Teams.exe"); Nvd="microsoft teams"; Cat="Communication" }
    "slack"       = @{ Reg="^Slack$";            Exe=@("$env:LocalAppData\slack\slack.exe"); Nvd="slack";  Cat="Communication" }
    "discord"     = @{ Reg="^Discord$";          Exe=@("$env:LocalAppData\Discord\app-*\Discord.exe"); Nvd="discord"; Cat="Communication" }
    "putty"       = @{ Reg="^PuTTY";             Exe=@("$env:ProgramFiles\PuTTY\putty.exe","${env:ProgramFiles(x86)}\PuTTY\putty.exe"); Nvd="putty"; Cat="Remote" }
    "winscp"      = @{ Reg="^WinSCP";            Exe=@("$env:ProgramFiles\WinSCP\WinSCP.exe"); Nvd="winscp"; Cat="Remote" }
    "filezilla"   = @{ Reg="^FileZilla Client";  Exe=@("$env:ProgramFiles\FileZilla FTP Client\filezilla.exe"); Nvd="filezilla"; Cat="Remote" }
    "teamviewer"  = @{ Reg="^TeamViewer";        Exe=@("$env:ProgramFiles\TeamViewer\TeamViewer.exe"); Nvd="teamviewer"; Cat="Remote" }
    "openvpn"     = @{ Reg="^OpenVPN";           Exe=@("$env:ProgramFiles\OpenVPN\bin\openvpn.exe"); Nvd="openvpn"; Cat="Network" }
    "wireguard"   = @{ Reg="^WireGuard$";        Exe=@("$env:ProgramFiles\WireGuard\wireguard.exe"); Nvd="wireguard"; Cat="Network" }
    "wireshark"   = @{ Reg="^Wireshark";         Exe=@("$env:ProgramFiles\Wireshark\Wireshark.exe"); Nvd="wireshark"; Cat="Network" }
    "nmap"        = @{ Reg="^Nmap";              Exe=@("${env:ProgramFiles(x86)}\Nmap\nmap.exe"); Nvd="nmap"; Cat="Network" }
    "vmware_ws"   = @{ Reg="^VMware Workstation"; Exe=@("${env:ProgramFiles(x86)}\VMware\VMware Workstation\vmware.exe"); Nvd="vmware workstation"; Cat="Virtualization" }
    "virtualbox"  = @{ Reg="^Oracle VM VirtualBox"; Exe=@("$env:ProgramFiles\Oracle\VirtualBox\VirtualBox.exe"); Nvd="virtualbox"; Cat="Virtualization" }
    "docker"      = @{ Reg="^Docker Desktop";    Exe=@();  Nvd="docker";             Cat="Virtualization" }
    "vlc"         = @{ Reg="^VLC media player";  Exe=@("$env:ProgramFiles\VideoLAN\VLC\vlc.exe","${env:ProgramFiles(x86)}\VideoLAN\VLC\vlc.exe"); Nvd="vlc media player"; Cat="Media" }
    "git"         = @{ Reg="^Git$|^Git version"; Exe=@("$env:ProgramFiles\Git\cmd\git.exe"); Nvd="git";    Cat="DevTool" }
    "acrobat"     = @{ Reg="^Adobe Acrobat|^Adobe Reader"; Exe=@("$env:ProgramFiles\Adobe\Acrobat DC\Acrobat\Acrobat.exe","${env:ProgramFiles(x86)}\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe"); Nvd="adobe acrobat reader"; Cat="Document" }
    "libreoffice" = @{ Reg="^LibreOffice";       Exe=@("$env:ProgramFiles\LibreOffice\program\soffice.exe"); Nvd="libreoffice"; Cat="Document" }
    "keepass"     = @{ Reg="^KeePass";           Exe=@("$env:ProgramFiles\KeePass Password Safe 2\KeePass.exe"); Nvd="keepass"; Cat="Security" }
    "veracrypt"   = @{ Reg="^VeraCrypt";         Exe=@("$env:ProgramFiles\VeraCrypt\VeraCrypt.exe"); Nvd="veracrypt"; Cat="Security" }
    "openssh"     = @{ Reg="";                   Exe=@("$env:SystemRoot\System32\OpenSSH\ssh.exe","$env:ProgramFiles\OpenSSH\ssh.exe"); Nvd="openssh"; Cat="Remote" }
}

# Office via ClickToRun
foreach ($ok in @("HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration","HKLM:\SOFTWARE\Wow6432Node\Microsoft\Office\ClickToRun\Configuration")) {
    $c2r = Get-ItemProperty $ok -ErrorAction SilentlyContinue
    if ($c2r.VersionToReport) {
        $Inventory.Add([PSCustomObject]@{ Key="office365"; Name="Microsoft Office 365"; Version=$c2r.VersionToReport; Publisher="Microsoft"; Category="Document"; NvdKeyword="microsoft office"; Source="c2r" })
        break
    }
}

foreach ($key in $AppDefs.Keys) {
    $def = $AppDefs[$key]; $ver = $null; $name = $key; $pub = ""; $installDate = ""
    if ($def.Exe.Count -gt 0) { $ver = Get-ExeVersion -Paths ($def.Exe | Where-Object { $_ -notmatch "\*" }) }
    if (-not $ver -and $def.Reg -ne "") {
        $reg = Get-RegVersion -Pattern $def.Reg
        if ($reg) { $ver = $reg.Version; $name = $reg.Name; $pub = $reg.Publisher }
    }
    if ($ver) {
        $Inventory.Add([PSCustomObject]@{ Key=$key; Name=$name; Version=$ver; Publisher=$pub; Category=$def.Cat; NvdKeyword=$def.Nvd; Source="known" })
    }
}

# Inventário geral do registry
$AllInstalled = [System.Collections.Generic.List[object]]::new()
$seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($r in $regPaths) {
    Get-ItemProperty $r -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -and $_.DisplayVersion -and $_.DisplayName -notmatch "^(KB\d|Security Update|Hotfix)" } |
    ForEach-Object {
        $n = $_.DisplayName.Trim()
        if ($seen.Add($n)) {
            $AllInstalled.Add([PSCustomObject]@{ Name=$n; Version=$_.DisplayVersion.Trim(); Publisher=$_.Publisher; InstallDate=$_.InstallDate })
        }
    }
}

$Inventory | ConvertTo-Json -Depth 5 | Out-File $InvFile -Encoding UTF8
Write-Info "Inventário: $($Inventory.Count) apps conhecidas + $($AllInstalled.Count) registry total → $InvFile"

# ═══════════════════════════════════════════════════════════════════
# FASE 4 — CVE/CWE JSON (Trivy JSON + Grype JSON + NVD API)
# ═══════════════════════════════════════════════════════════════════
Write-Step "FASE 4 — CVE JSON"

$CveResults = [System.Collections.Generic.List[object]]::new()
$SeenPairs  = [System.Collections.Generic.HashSet[string]]::new()

# Trivy em modo JSON
if (Test-Path $TrivyBin) {
    Write-Info "Trivy (JSON)..."
    $env:TRIVY_NO_PROGRESS = "true"
    try {
        & $TrivyBin fs --format json --output $TrivyJson `
            --skip-dirs "C:\Windows,C:\Program Files\WindowsApps,C:\ProgramData\Microsoft" `
            C:\ 2>&1 | Out-Null
        if (Test-Path $TrivyJson) {
            $tj = Get-Content $TrivyJson -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
            if ($tj.Results) {
                foreach ($res in $tj.Results) {
                    foreach ($v in $res.Vulnerabilities) {
                        $pair = "$($v.VulnerabilityID)|$($v.PkgName)"; if (-not $SeenPairs.Add($pair)) { continue }
                        $cvss = $null; if ($v.CVSS) { $cvss = ($v.CVSS.PSObject.Properties.Value | Where-Object {$_.V3Score} | Select-Object -First 1).V3Score }
                        $CveResults.Add([PSCustomObject]@{
                            Source="Trivy"; App=$v.PkgName; Version=$v.InstalledVersion; FixedIn=$v.FixedVersion
                            CveId=$v.VulnerabilityID; Severity=$v.Severity; Cvss=$cvss
                            Title=($v.Title -as [string]); Description=if($v.Description.Length -gt 200){$v.Description.Substring(0,200)+"…"}else{$v.Description}
                            Cwe=if($v.CweIDs){$v.CweIDs -join ", "}else{""}; References=if($v.References){$v.References[0]}else{""}
                        })
                    }
                }
            }
            Write-Info "  Trivy JSON: $($CveResults.Count) CVEs"
        }
    } catch { Write-Warn "  Trivy JSON: $($_.Exception.Message)" }
}

# Grype JSON (já gerado na fase 12)
if ((Test-Path $GrypeJson) -and (Get-Item $GrypeJson).Length -gt 0) {
    Write-Info "Grype JSON..."
    try {
        $gd = Get-Content $GrypeJson -Raw | ConvertFrom-Json
        $grypeAdded = 0
        foreach ($m in $gd.matches) {
            $pair = "$($m.vulnerability.id)|$($m.artifact.name)"; if (-not $SeenPairs.Add($pair)) { continue }
            $cvss = $null; $m.vulnerability.cvss | Where-Object { $_.version -like "3*" } | Select-Object -First 1 | ForEach-Object { $cvss = $_.metrics.baseScore }
            $CveResults.Add([PSCustomObject]@{
                Source="Grype"; App=$m.artifact.name; Version=$m.artifact.version; FixedIn=($m.vulnerability.fix.versions -join ", ")
                CveId=$m.vulnerability.id; Severity=$m.vulnerability.severity; Cvss=$cvss
                Title=""; Description=if($m.vulnerability.description.Length -gt 200){$m.vulnerability.description.Substring(0,200)+"…"}else{$m.vulnerability.description}
                Cwe=""; References=if($m.vulnerability.urls){$m.vulnerability.urls[0]}else{""}
            }); $grypeAdded++
        }
        Write-Info "  Grype JSON: $grypeAdded CVEs novos"
    } catch { Write-Warn "  Grype JSON: $($_.Exception.Message)" }
}

# NVD API para apps conhecidas
if (-not $NoNvd) {
    $hasApiKey = ($NvdApiKey -ne "")
    $batchSize = if ($hasApiKey) { 50 } else { 5 }
    $maxApps   = if ($hasApiKey) { 100 } else { 30 }
    Write-Info "NVD API para $($Inventory.Count) apps (API key: $hasApiKey)..."
    Write-Info "  Rate limit: $batchSize req per 30s — esperar $(Get-NvdBatchSleep)s entre batches"
    $reqCount = 0
    foreach ($app in ($Inventory | Select-Object -First $maxApps)) {
        $reqCount++
        if ($reqCount -gt 1 -and ($reqCount % $batchSize -eq 1)) {
            Write-Info "  Rate limit pause ($(Get-NvdBatchSleep)s)..."
            Start-Sleep -Seconds (Get-NvdBatchSleep)
        }
        try {
            $resp = Invoke-NvdApi -Keyword $app.NvdKeyword -ResultsPerPage 10 -Retries 1
            foreach ($v in $resp.vulnerabilities) {
                $pair = "$($v.cve.id)|$($app.Key)"; if (-not $SeenPairs.Add($pair)) { continue }
                $sev = "UNKNOWN"; $score = $null; $cwe = ""
                foreach ($mk in @("cvssMetricV31","cvssMetricV30","cvssMetricV2")) { $ms = $v.cve.metrics.$mk; if ($ms) { $sev = $ms[0].cvssData.baseSeverity; $score = $ms[0].cvssData.baseScore; break } }
                if ($v.cve.weaknesses) { $cwe = (@($v.cve.weaknesses | ForEach-Object { $_.description | Where-Object { $_.lang -eq "en" } | Select-Object -First 1 -ExpandProperty value } | Where-Object { $_ -match "^CWE-" })) -join ", " }
                $desc = ($v.cve.descriptions | Where-Object { $_.lang -eq "en" } | Select-Object -First 1).value
                $CveResults.Add([PSCustomObject]@{
                    Source="NVD"; App=$app.Key; Version=$app.Version; FixedIn=""
                    CveId=$v.cve.id; Severity=$sev; Cvss=$score; Title=""
                    Description=if($desc.Length -gt 200){$desc.Substring(0,200)+"…"}else{$desc}
                    Cwe=$cwe; References=if($v.cve.references){$v.cve.references[0].url}else{""}
                })
            }
            Write-Info "  $($app.Key) $($app.Version) — $($resp.totalResults) NVD"
        } catch { Write-Warn "  NVD [$($app.Key)]: $($_.Exception.Message)" }
    }
}

$CveResults | ConvertTo-Json -Depth 5 | Out-File $CveFile -Encoding UTF8
Write-Info "CVEs: $($CveResults.Count) total → $CveFile"

# ═══════════════════════════════════════════════════════════════════
# FASE 4.5 — EXPORTS (CSV + SARIF) e COMPARAÇÃO (#1 + #3)
# ═══════════════════════════════════════════════════════════════════
Write-Step "FASE 4.5 — Exports CSV/SARIF + Compare"

# ── CSV Export ────────────────────────────────────────────────────
try {
    $CveResults |
        Select-Object Source,App,Version,FixedIn,CveId,Severity,Cvss,Cwe,Title,Description,References |
        Export-Csv -Path $CveCsv -NoTypeInformation -Encoding UTF8 -Force
    Write-Info "CSV: $($CveResults.Count) CVEs → $CveCsv"
} catch { Write-Warn "CSV export: $($_.Exception.Message)" }

# ── SARIF Export ──────────────────────────────────────────────────
# SARIF 2.1.0 — formato standard consumido por GitHub, Azure DevOps, GitLab
try {
    $sevMap = @{ "CRITICAL"="error"; "HIGH"="error"; "IMPORTANT"="error"; "MEDIUM"="warning"; "MODERATE"="warning"; "LOW"="note"; "NEGLIGIBLE"="note"; "UNKNOWN"="none" }
    $rulesDict = @{}
    $sarifResults = [System.Collections.Generic.List[object]]::new()
    foreach ($cve in $CveResults) {
        if (-not $cve.CveId) { continue }
        if (-not $rulesDict.ContainsKey($cve.CveId)) {
            $rulesDict[$cve.CveId] = @{
                id    = $cve.CveId
                name  = $cve.CveId
                shortDescription = @{ text = if ($cve.Title) { $cve.Title.Substring(0,[Math]::Min(120,$cve.Title.Length)) } else { $cve.CveId } }
                fullDescription  = @{ text = if ($cve.Description) { $cve.Description.Substring(0,[Math]::Min(500,$cve.Description.Length)) } else { $cve.CveId } }
                helpUri = "https://nvd.nist.gov/vuln/detail/$($cve.CveId)"
                properties = @{
                    tags = @("security","cve")
                    "security-severity" = if ($cve.Cvss) { [string]$cve.Cvss } else { "0" }
                }
            }
        }
        $sev = if ($cve.Severity) { $cve.Severity.ToUpper() } else { "UNKNOWN" }
        $level = if ($sevMap.ContainsKey($sev)) { $sevMap[$sev] } else { "none" }
        $msg = "$($cve.App) $($cve.Version) → $($cve.CveId) ($sev)"
        if ($cve.FixedIn) { $msg += " — fixed in $($cve.FixedIn)" }
        $sarifResults.Add(@{
            ruleId  = $cve.CveId
            level   = $level
            message = @{ text = $msg }
            locations = @(@{ physicalLocation = @{ artifactLocation = @{ uri = if ($cve.App) { $cve.App } else { "unknown" } } } })
            properties = @{
                package      = if ($cve.App) { $cve.App } else { "" }
                version      = if ($cve.Version) { $cve.Version } else { "" }
                fixedVersion = if ($cve.FixedIn) { $cve.FixedIn } else { "" }
                cwe          = if ($cve.Cwe) { $cve.Cwe } else { "" }
                source       = if ($cve.Source) { $cve.Source } else { "" }
            }
        })
    }
    $sarif = @{
        '$schema' = "https://json.schemastore.org/sarif-2.1.0.json"
        version   = "2.1.0"
        runs      = @(@{
            tool = @{
                driver = @{
                    name    = "windows-full-audit"
                    version = "1.0"
                    informationUri = "https://github.com/user/security-audit-scripts"
                    rules = @($rulesDict.Values)
                }
            }
            invocations = @(@{
                executionSuccessful = $true
                startTimeUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                machine = $Target
            })
            results = $sarifResults
        })
    }
    $sarif | ConvertTo-Json -Depth 20 | Out-File $CveSarif -Encoding UTF8 -Force
    Write-Info "SARIF: $($sarifResults.Count) results, $($rulesDict.Count) rules → $CveSarif"
} catch { Write-Warn "SARIF export: $($_.Exception.Message)" }

# ── Compare com run anterior (#3) ─────────────────────────────────
if ($Compare -ne "") {
    Write-Info "A comparar com: $Compare"
    try {
        $previous = Get-Content $Compare -Raw | ConvertFrom-Json
        # Indexar por (CveId, App) — chaves como hashtables (HashSet em PS é mais chato)
        $curIdx = @{}; foreach ($c in $CveResults) { if ($c.CveId) { $curIdx["$($c.CveId)|$($c.App)"] = $c } }
        $prevIdx = @{}; foreach ($c in $previous) { if ($c.CveId) { $prevIdx["$($c.CveId)|$($c.App)"] = $c } }

        $newCves    = @($curIdx.Keys  | Where-Object { -not $prevIdx.ContainsKey($_) } | ForEach-Object { $curIdx[$_] })
        $resolved   = @($prevIdx.Keys | Where-Object { -not $curIdx.ContainsKey($_) } | ForEach-Object { $prevIdx[$_] })
        $sevChanges = [System.Collections.Generic.List[object]]::new()
        foreach ($k in ($curIdx.Keys | Where-Object { $prevIdx.ContainsKey($_) })) {
            $curSev  = if ($curIdx[$k].Severity)  { $curIdx[$k].Severity.ToUpper() }  else { "" }
            $prevSev = if ($prevIdx[$k].Severity) { $prevIdx[$k].Severity.ToUpper() } else { "" }
            if ($curSev -ne $prevSev) {
                $sevChanges.Add([PSCustomObject]@{
                    CveId    = $curIdx[$k].CveId
                    App      = $curIdx[$k].App
                    Previous = $prevSev
                    Current  = $curSev
                    Cvss     = $curIdx[$k].Cvss
                })
            }
        }
        $diff = [PSCustomObject]@{
            previous_file = $Compare
            current_file  = $CveFile
            summary = @{
                total_previous   = $previous.Count
                total_current    = $CveResults.Count
                new              = $newCves.Count
                resolved         = $resolved.Count
                severity_changed = $sevChanges.Count
            }
            new_cves         = $newCves
            resolved_cves    = $resolved
            severity_changes = $sevChanges
        }
        $diff | ConvertTo-Json -Depth 10 | Out-File $DiffFile -Encoding UTF8 -Force
        Write-Info "Compare: $($newCves.Count) novos, $($resolved.Count) resolvidos, $($sevChanges.Count) mudaram severidade → $DiffFile"
    } catch { Write-Warn "Compare: $($_.Exception.Message)" }
}

# ═══════════════════════════════════════════════════════════════════
# FASE 5 — APP UPDATES JSON (winget + choco + scoop)
# ═══════════════════════════════════════════════════════════════════
Write-Step "FASE 5 — App Updates JSON"

$AppUpdates = [System.Collections.Generic.List[object]]::new()

# winget
$WingetCmd = Get-Command winget -ErrorAction SilentlyContinue
$WingetPath = if ($WingetCmd) { $WingetCmd.Source } else { $null }
if (-not $WingetPath) { $WingetPath = "$env:LocalAppData\Microsoft\WindowsApps\winget.exe"; if (-not (Test-Path $WingetPath)) { $WingetPath = $null } }
if ($WingetPath) {
    Write-Info "winget upgrade list..."
    try {
        $env:WINGET_DISABLE_UPDATE_CHECK = "1"
        $wingetOut = & $WingetPath upgrade --accept-source-agreements 2>&1 | Where-Object { $_ -notmatch "^\s*$|^-+$|^Name\s+Id|The following|upgrades available|winget\.exe" }
        foreach ($line in $wingetOut) {
            if ($line -match "^\s*(.+?)\s{2,}(\S+)\s{2,}(\S+)\s{2,}(\S+)\s*$") {
                $appName = $Matches[1].Trim(); $appId = $Matches[2].Trim(); $cur = $Matches[3].Trim(); $new = $Matches[4].Trim()
                if ($appName -and $appId -ne "Id" -and $cur -ne "Version") {
                    $AppUpdates.Add([PSCustomObject]@{ Source="winget"; Name=$appName; WingetId=$appId; Current=$cur; Available=$new; UpdateCmd="winget upgrade --id `"$appId`" --accept-package-agreements" })
                }
            }
        }
        Write-Info "winget: $($AppUpdates.Count) updates"
    } catch { Write-Warn "winget: $($_.Exception.Message)" }
}

# Chocolatey
if (Get-Command choco -ErrorAction SilentlyContinue) {
    Write-Info "choco outdated..."
    try {
        $chocoOut = & choco outdated --limit-output 2>&1
        foreach ($line in $chocoOut) {
            if ($line -match "^(.+)\|(.+)\|(.+)\|") {
                $AppUpdates.Add([PSCustomObject]@{ Source="Chocolatey"; Name=$Matches[1]; WingetId=$Matches[1]; Current=$Matches[2]; Available=$Matches[3]; UpdateCmd="choco upgrade $($Matches[1]) -y" })
            }
        }
    } catch { Write-Warn "choco: $($_.Exception.Message)" }
}

# Scoop
if (Get-Command scoop -ErrorAction SilentlyContinue) {
    Write-Info "scoop status..."
    try {
        $scoopOut = & scoop status 2>&1
        foreach ($line in $scoopOut) {
            if ($line -match "^\s+(\S+)\s+(\S+)\s+(\S+)") {
                $AppUpdates.Add([PSCustomObject]@{ Source="Scoop"; Name=$Matches[1]; WingetId=$Matches[1]; Current=$Matches[2]; Available=$Matches[3]; UpdateCmd="scoop update $($Matches[1])" })
            }
        }
    } catch { Write-Warn "scoop: $($_.Exception.Message)" }
}

$AppUpdates | ConvertTo-Json -Depth 3 | Out-File $AppUpdFile -Encoding UTF8
Write-Info "App updates: $($AppUpdates.Count) → $AppUpdFile"

# ═══════════════════════════════════════════════════════════════════
# FASE 6 — RELATÓRIO HTML UNIFICADO
# ═══════════════════════════════════════════════════════════════════
Write-Step "FASE 6 — Relatório HTML"
Start-Sleep -Seconds 1

# ── Estatísticas para o tab Audit ─────────────────────────────────
$txtFiles = Get-ChildItem "$Out\*.txt" -ErrorAction SilentlyContinue | Sort-Object Name

# Cache: ler cada ficheiro UMA vez. Ficheiros grandes (>500KB) lê só primeiras 3000 linhas
$FileCache = @{}
foreach ($f in $txtFiles) {
    try {
        if ($f.Length -gt 500000) {
            $FileCache[$f.FullName] = (Get-Content $f.FullName -TotalCount 3000 -Encoding UTF8 -ErrorAction SilentlyContinue) -join "`n"
        } else {
            $FileCache[$f.FullName] = [System.IO.File]::ReadAllText($f.FullName, [System.Text.Encoding]::UTF8)
        }
    } catch {
        $FileCache[$f.FullName] = ""
        Write-Warn "Falha ao ler $($f.Name): $($_.Exception.Message)"
    }
}

foreach ($f in $txtFiles) {
    $content = $FileCache[$f.FullName]
    if ([string]::IsNullOrWhiteSpace($content)) { continue }
    $TotalCrit += ([regex]::Matches($content, "CRÍTICO|CRITICAL")).Count
    $TotalHigh += ([regex]::Matches($content, "\bHIGH\b|\[HIGH\]|ALERTA")).Count
    [regex]::Matches($content, "CVE-\d{4}-\d+") | ForEach-Object { [void]$AllCves.Add($_.Value) }
    [regex]::Matches($content, "CWE-\d+")        | ForEach-Object { [void]$AllCwes.Add($_.Value) }
}
$UniqCves = $AllCves.Count; $UniqCwes = $AllCwes.Count
Write-Info "Audit stats: Critical=$TotalCrit High=$TotalHigh CVEs=$UniqCves CWEs=$UniqCwes"

# Cache de contagens por ficheiro — usado pelo TOC e pelas secções
$CountCache = @{}
foreach ($f in $txtFiles) {
    $c = $FileCache[$f.FullName]
    if ([string]::IsNullOrWhiteSpace($c)) {
        $CountCache[$f.FullName] = @{ Crit=0; High=0 }
    } else {
        $CountCache[$f.FullName] = @{
            Crit = ([regex]::Matches($c, "CRÍTICO|CRITICAL")).Count
            High = ([regex]::Matches($c, "\bHIGH\b|\[HIGH\]|ALERTA")).Count
        }
    }
}

# ── Estatísticas para o tab CVE Dashboard ─────────────────────────
$CveCrit = ($CveResults | Where-Object { $_.Severity -eq "CRITICAL" }).Count
$CveHigh = ($CveResults | Where-Object { $_.Severity -in @("HIGH","IMPORTANT") }).Count
$CveMed  = ($CveResults | Where-Object { $_.Severity -in @("MEDIUM","MODERATE") }).Count
$CweUniq = ($CveResults | Where-Object { $_.Cwe } | ForEach-Object { $_.Cwe -split ",\s*" } | Where-Object { $_ -match "^CWE-" } | Sort-Object -Unique).Count
Write-Info "CVE dashboard: Critical=$CveCrit High=$CveHigh Total=$($CveResults.Count) CWEs=$CweUniq"

# ── Top findings para Executive Summary ───────────────────────────
$topFindings = [System.Collections.Generic.List[object]]::new()
foreach ($f in $txtFiles) {
    $content = $FileCache[$f.FullName]
    if ([string]::IsNullOrWhiteSpace($content)) { continue }
    $ms = [regex]::Matches($content, "^.{0,200}(CRÍTICO|CRITICAL|ALERTA).*$", "Multiline")
    $cnt = 0
    foreach ($m in $ms) {
        if ($cnt -ge 4) { break }
        $line = $m.Value.Trim()
        $sev = if ($line -match "CRÍTICO|CRITICAL") { "critical" } else { "high" }
        $short = if ($line.Length -gt 180) { $line.Substring(0,180) } else { $line }
        $topFindings.Add([PSCustomObject]@{ Sev=$sev; Src=$f.BaseName; Msg=(Escape-Html $short) }); $cnt++
    }
    if ($topFindings.Count -ge 20) { break }
}

# ── Tabela de CVEs ─────────────────────────────────────────────────
$cveTable = [System.Collections.Generic.List[object]]::new()
$sevOrder = @{ "CRITICAL"=1; "HIGH"=2; "MEDIUM"=3; "LOW"=4; "UNKNOWN"=5 }
foreach ($cve in ($AllCves | Sort-Object)) {
    $sev = "UNKNOWN"; $foundIn = ""; $desc = ""
    foreach ($f in $txtFiles) {
        $content = $FileCache[$f.FullName]
        if ([string]::IsNullOrWhiteSpace($content)) { continue }
        if ($content -match [regex]::Escape($cve)) {
            $foundIn = $f.BaseName
            # Heurística melhorada: procurar severity dentro de 80 chars do CVE
            $proximityPattern = "$([regex]::Escape($cve)).{0,80}\b(CRITICAL|HIGH|MEDIUM|LOW)\b"
            $sevMatch = [regex]::Match($content, $proximityPattern, "IgnoreCase")
            if (-not $sevMatch.Success) {
                # Tentar inverso — severity antes do CVE
                $sevMatch = [regex]::Match($content, "\b(CRITICAL|HIGH|MEDIUM|LOW)\b.{0,80}$([regex]::Escape($cve))", "IgnoreCase")
            }
            if ($sevMatch.Success) { $sev = $sevMatch.Groups[1].Value.ToUpper() }
            # Descrição: linha que contém "Desc:" próxima do CVE
            $dm = [regex]::Match($content,"$([regex]::Escape($cve))[^\n]*\n[^\n]*?Desc:\s*([^\n]{0,150})")
            if ($dm.Success) { $desc = Escape-Html $dm.Groups[1].Value.Trim() }
            break
        }
    }
    if ([string]::IsNullOrEmpty($desc)) { $desc = "(ver $foundIn)" }
    $cveTable.Add([PSCustomObject]@{ Sev=$sev; Cve=$cve; Src=$foundIn; Desc=$desc })
}
$cveTable = $cveTable | Sort-Object { $sevOrder[$_.Sev] }, Cve

# ── Agrupar ficheiros por categoria ───────────────────────────────
$tocOrder = @('system','network','privesc','hardening','cve','other')
$catFiles = @{}; foreach ($cat in $tocOrder) { $catFiles[$cat] = @() }
foreach ($f in $txtFiles) { $cat = Get-Category -base $f.BaseName; $catFiles[$cat] += $f }

# ── JSON para o CVE Dashboard ──────────────────────────────────────
$CveJson  = $CveResults | Select-Object Source,App,Version,FixedIn,CveId,Severity,Cvss,Title,Description,Cwe,References | ConvertTo-Json -Depth 5 -Compress
$InvJson  = $Inventory  | Select-Object Key,Name,Version,Publisher,Category | ConvertTo-Json -Depth 3 -Compress
$UpdJson  = $AppUpdates | Select-Object Source,Name,WingetId,Current,Available,UpdateCmd | ConvertTo-Json -Depth 3 -Compress

# ── OS Info ───────────────────────────────────────────────────────
$winBuild = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue
$buildStr = if ($winBuild) { "Build $($winBuild.CurrentBuildNumber) ($($winBuild.DisplayVersion))" } else { [System.Environment]::OSVersion.VersionString }

# ═══════════════════════════════════════════════════════════════════
# GERAR HTML
# ═══════════════════════════════════════════════════════════════════
$sb = [System.Text.StringBuilder]::new(2000000)

[void]$sb.AppendLine(@"
<!DOCTYPE html>
<html lang="pt">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Full Audit — $Target — $Date</title>
<style>
:root{
  --bg:#0d1117; --bg2:#161b22; --bg3:#21262d; --bg4:#2d333b;
  --text:#c9d1d9; --dim:#8b949e; --border:#30363d;
  --cyan:#58a6ff; --green:#3fb950; --yellow:#d29922;
  --red:#f85149; --magenta:#bc8cff; --orange:#ff7b00;
  --red-bg:rgba(248,81,73,.12); --orange-bg:rgba(255,123,0,.10);
  --yellow-bg:rgba(210,153,34,.08); --green-bg:rgba(63,185,80,.08);
  --sidebar-w:260px;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:'Consolas','Monaco','Courier New',monospace;font-size:13px;line-height:1.5;display:flex;min-height:100vh}
.sidebar{width:var(--sidebar-w);background:var(--bg2);border-right:1px solid var(--border);position:fixed;top:0;left:0;bottom:0;overflow-y:auto;padding:20px 0;z-index:50}
.sb-head{padding:0 20px 15px;border-bottom:1px solid var(--border);margin-bottom:10px}
.sb-head h2{color:var(--cyan);font-size:1em;margin-bottom:4px}
.sb-head .host{font-size:.78em;color:var(--dim)}
.tabs{display:flex;padding:0 16px;margin-top:8px;border-bottom:1px solid var(--border);margin-bottom:6px}
.tab-btn{padding:5px 12px;font-size:.82em;cursor:pointer;color:var(--dim);background:none;border:none;border-bottom:2px solid transparent;transition:.12s;font-family:inherit}
.tab-btn:hover{color:var(--text)}
.tab-btn.active{color:var(--cyan);border-bottom-color:var(--cyan)}
.toc-cat{padding:8px 20px 4px;font-size:.7em;color:var(--dim);text-transform:uppercase;letter-spacing:1px;margin-top:5px}
.toc-item{display:flex;justify-content:space-between;align-items:center;padding:5px 20px;cursor:pointer;color:var(--text);text-decoration:none;font-size:.83em;border-left:3px solid transparent;transition:.12s}
.toc-item:hover{background:var(--bg3);border-left-color:var(--cyan)}
.toc-item.active{background:var(--bg3);border-left-color:var(--cyan);color:var(--cyan)}
.toc-badges{display:flex;gap:3px}
.toc-mini{padding:1px 5px;border-radius:2px;font-size:.7em;font-weight:bold}
.tm-c{background:#3d0000;color:var(--red)}.tm-h{background:#2d1800;color:var(--yellow)}.tm-o{background:#001a10;color:var(--green)}
.main{margin-left:var(--sidebar-w);flex:1;display:flex;flex-direction:column;min-width:0}
.header{background:linear-gradient(135deg,#0d1117,#161b22);border-bottom:2px solid var(--cyan);padding:15px 28px;position:sticky;top:0;z-index:40}
.header h1{color:var(--cyan);font-size:1.15em;margin-bottom:6px}
.meta{display:flex;flex-wrap:wrap;gap:12px;font-size:.79em;opacity:.85}
.stats{display:flex;gap:6px;margin-top:8px;flex-wrap:wrap;align-items:center}
.stat-badge{padding:2px 10px;border-radius:3px;font-weight:bold;font-size:.82em;border:1px solid}
.stat-crit{background:var(--red-bg);color:var(--red);border-color:var(--red)}
.stat-high{background:var(--orange-bg);color:var(--orange);border-color:var(--orange)}
.stat-cve{background:rgba(188,140,255,.1);color:var(--magenta);border-color:var(--magenta)}
.stat-cwe{background:var(--green-bg);color:var(--green);border-color:var(--green)}
.stat-info{background:rgba(88,166,255,.1);color:var(--cyan);border-color:var(--cyan)}
.filters{margin-left:auto;display:flex;gap:5px}
.filter-btn{padding:2px 9px;border-radius:3px;font-size:.78em;cursor:pointer;background:var(--bg3);color:var(--dim);border:1px solid var(--border);transition:.12s}
.filter-btn:hover{color:var(--text);border-color:var(--cyan)}
.filter-btn.active{color:var(--cyan);border-color:var(--cyan)}
.container{padding:18px 28px;flex:1}
.tab-panel{display:none}
.tab-panel.active{display:block}
.exec-summary{background:linear-gradient(135deg,rgba(248,81,73,.07),rgba(210,153,34,.04));border:1px solid var(--red);border-left:4px solid var(--red);border-radius:6px;padding:16px 20px;margin-bottom:14px}
.exec-summary h2{color:var(--red);margin-bottom:10px;font-size:1em}
.finding-row{display:flex;gap:10px;padding:5px 0;border-bottom:1px dashed rgba(255,255,255,.05);font-size:.83em}
.finding-row:last-child{border-bottom:none}
.fr-sev{padding:2px 7px;border-radius:3px;font-weight:bold;font-size:.73em;min-width:65px;text-align:center;flex-shrink:0}
.fr-sev.critical{background:#3d0000;color:var(--red)}.fr-sev.high{background:#2d1800;color:var(--yellow)}
.fr-src{color:var(--cyan);flex-shrink:0;min-width:130px;font-size:.79em}
.fr-msg{color:var(--text);flex:1;word-break:break-word}
.category{margin-bottom:14px}
.category-h{padding:6px 0;margin-bottom:6px;border-bottom:1px solid var(--border);color:var(--dim);font-size:.9em;letter-spacing:1px;text-transform:uppercase}
.sec{background:var(--bg2);border:1px solid var(--border);border-radius:6px;margin-bottom:8px;scroll-margin-top:120px}
.sec-h{display:flex;justify-content:space-between;align-items:center;padding:8px 14px;cursor:pointer;border-radius:6px 6px 0 0;background:var(--bg3);user-select:none}
.sec-h:hover{background:#2a2f3a}
.sec-t{font-weight:bold;color:var(--cyan);font-size:.88em}
.sec-c{max-height:0;overflow:hidden;transition:max-height .3s}
.sec-c.open{max-height:9999px}
pre{padding:14px;overflow-x:auto;font-size:12px;white-space:pre-wrap;word-break:break-all}
.badge{padding:2px 6px;border-radius:3px;font-size:.73em;font-weight:bold;margin-left:3px}
.b-crit{background:#3d0000;color:var(--red)}.b-high{background:#2d1800;color:var(--yellow)}.b-ok{background:#001a10;color:var(--green)}.b-info{background:#001030;color:var(--cyan)}
.finding-line{color:var(--red);font-weight:bold}.alert-line{color:var(--yellow);font-weight:bold}.ok-line{color:var(--green)}
.cve-inline{color:var(--magenta);font-weight:bold}.cwe-inline{color:var(--green);font-weight:bold}
.cve-table{width:100%;border-collapse:collapse;font-size:.83em}
.cve-table th,.cve-table td{padding:7px 11px;text-align:left;border-bottom:1px solid var(--border)}
.cve-table th{background:var(--bg3);color:var(--cyan);font-size:.78em;text-transform:uppercase}
.cve-table tr:hover{background:rgba(88,166,255,.04)}
.cve-id{color:var(--magenta);font-weight:bold}
.sev-tag{display:inline-block;padding:1px 7px;border-radius:3px;font-size:.74em;font-weight:bold;min-width:62px;text-align:center}
.sev-CRITICAL{background:var(--red-bg);color:var(--red)}.sev-HIGH,.sev-IMPORTANT{background:var(--orange-bg);color:var(--orange)}
.sev-MEDIUM,.sev-MODERATE{background:var(--yellow-bg);color:var(--yellow)}.sev-LOW,.sev-NEGLIGIBLE{background:var(--green-bg);color:var(--green)}.sev-UNKNOWN{background:var(--bg3);color:var(--dim)}
.dash-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:10px;margin-bottom:16px}
.dash-card{background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:14px 16px;text-align:center}
.dash-card .num{font-size:2em;font-weight:700;line-height:1}
.dash-card .lbl{font-size:.72em;color:var(--dim);margin-top:3px;text-transform:uppercase;letter-spacing:.5px}
.section2{background:var(--bg2);border:1px solid var(--border);border-radius:6px;margin-bottom:10px}
.sec2-hdr{display:flex;justify-content:space-between;align-items:center;padding:9px 14px;cursor:pointer;background:var(--bg3);border-radius:6px 6px 0 0;user-select:none}
.sec2-hdr:hover{background:var(--bg4)}
.sec2-title{font-weight:700;color:var(--cyan);font-size:.88em}
.sec2-body{padding:14px;display:none}
.sec2-body.open{display:block}
.vtable{width:100%;border-collapse:collapse;font-size:.81em}
.vtable th{background:var(--bg3);color:var(--cyan);padding:6px 10px;text-align:left;font-size:.77em;text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid var(--border)}
.vtable td{padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top;word-break:break-word;max-width:300px}
.vtable tr:hover{background:rgba(88,166,255,.04)}
.vtable tr:last-child td{border-bottom:none}
.sev{display:inline-block;padding:1px 7px;border-radius:2px;font-size:.74em;font-weight:700;min-width:62px;text-align:center}
.fixed{color:var(--green);font-size:.77em}
.cwe-id{color:var(--green);font-size:.79em}
.upd-cmd{font-family:monospace;background:var(--bg4);padding:2px 7px;border-radius:3px;font-size:.79em;color:var(--cyan);cursor:pointer}
.upd-cmd:hover{background:var(--bg3)}
.upd-row{border-left:3px solid var(--orange)}
.inv-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:8px}
.inv-card{background:var(--bg3);border:1px solid var(--border);border-radius:5px;padding:10px 12px}
.inv-card h4{color:var(--text);font-size:.83em;margin-bottom:3px}
.inv-ver{color:var(--cyan);font-size:.8em}
.inv-cat{display:inline-block;font-size:.69em;padding:1px 6px;border-radius:10px;background:var(--bg4);color:var(--dim);margin-top:3px}
.search-box{width:100%;padding:6px 11px;background:var(--bg4);border:1px solid var(--border);border-radius:4px;color:var(--text);font-family:monospace;font-size:.83em;margin-bottom:10px;outline:none}
.search-box:focus{border-color:var(--cyan)}
::-webkit-scrollbar{width:6px;height:6px}::-webkit-scrollbar-track{background:var(--bg)}::-webkit-scrollbar-thumb{background:var(--bg4);border-radius:3px}
.footer{text-align:center;padding:14px;opacity:.35;font-size:.74em;border-top:1px solid var(--border);margin-top:14px}
body.filter-critical .sec:not(.has-crit){display:none}
body.filter-critical .category:not(.has-crit){display:none}
body.filter-high .sec:not(.has-high):not(.has-crit){display:none}
body.filter-high .category:not(.has-high):not(.has-crit){display:none}
</style>
</head>
<body>
"@)

# ── Sidebar ────────────────────────────────────────────────────────
[void]$sb.AppendLine(@"
<aside class="sidebar">
  <div class="sb-head">
    <h2>&#128269; windows-full-audit</h2>
    <div class="host">$Target &middot; $Date</div>
  </div>
  <div class="tabs">
    <button class="tab-btn active" onclick="switchTab('audit',this)">Audit</button>
    <button class="tab-btn"        onclick="switchTab('dashboard',this)">CVE Dashboard</button>
  </div>
  <nav id="toc-audit">
"@)

foreach ($cat in $tocOrder) {
    $files = $catFiles[$cat]; if (-not $files) { continue }
    $label = switch ($cat) { 'system' {'&#x1F5A5; System'} 'network' {'&#x1F310; Network'} 'privesc' {'&#x1F510; Privilege Escalation'} 'hardening' {'&#x1F6E1; Hardening'} 'cve' {'&#x1F41B; CVE / Vulnerabilities'} default {'&#x1F4C4; Other'} }
    [void]$sb.AppendLine("<div class=`"toc-cat`">$label</div>")
    foreach ($f in $files) {
        $fc = $CountCache[$f.FullName].Crit
        $fh = $CountCache[$f.FullName].High
        $badges = ""
        if ($fc -gt 0) { $badges += "<span class=`"toc-mini tm-c`">$fc</span>" }
        if ($fh -gt 0) { $badges += "<span class=`"toc-mini tm-h`">$fh</span>" }
        if (-not $badges) { $badges = "<span class=`"toc-mini tm-o`">OK</span>" }
        [void]$sb.AppendLine("<a class=`"toc-item`" href=`"#$($f.BaseName)`" onclick=`"switchTab('audit',document.querySelectorAll('.tab-btn')[0])`"><span>$($f.BaseName)</span><span class=`"toc-badges`">$badges</span></a>")
    }
}

[void]$sb.AppendLine(@"
  </nav>
  <nav id="toc-dash" style="display:none">
    <div class="toc-cat">Visão Geral</div>
    <div class="toc-item active" onclick="showDash('summary',this)">&#128202; Dashboard</div>
    <div class="toc-cat">Vulnerabilidades</div>
    <div class="toc-item" onclick="showDash('cve',this)">&#128308; CVEs / CWEs <span class="toc-mini tm-c">$($CveResults.Count)</span></div>
    <div class="toc-cat">Updates</div>
    <div class="toc-item" onclick="showDash('upd',this)">&#128230; App Updates <span class="toc-mini $(if($AppUpdates.Count -gt 0){"tm-h"}else{"tm-o"})">$($AppUpdates.Count)</span></div>
    <div class="toc-cat">Inventário</div>
    <div class="toc-item" onclick="showDash('inv',this)">&#128203; Apps <span class="toc-mini tm-o">$($Inventory.Count)</span></div>
  </nav>
</aside>
"@)

# ── Header ─────────────────────────────────────────────────────────
[void]$sb.AppendLine(@"
<main class="main">
<div class="header">
  <h1>&#128269; windows-full-audit &mdash; $Target</h1>
  <div class="meta">
    <span>&#128187; <b>$Target</b></span>
    <span>&#129695; <b>$buildStr</b></span>
    <span>&#128197; <b>$Date</b></span>
    <span>&#128272; Admin: <b>$IsAdmin</b></span>
  </div>
  <div class="stats">
    <span class="stat-badge stat-crit">&#128308; Critical: $TotalCrit</span>
    <span class="stat-badge stat-high">&#128992; High: $TotalHigh</span>
    <span class="stat-badge stat-cve">&#128995; CVEs JSON: $($CveResults.Count)</span>
    <span class="stat-badge stat-cwe">&#128994; CWEs: $CweUniq</span>
    <span class="stat-badge stat-info">&#128230; Updates: $($AppUpdates.Count)</span>
    <div class="filters">
      <span class="filter-btn active" onclick="setFilter('all',this)">All</span>
      <span class="filter-btn" onclick="setFilter('critical',this)">Critical</span>
      <span class="filter-btn" onclick="setFilter('high',this)">+High</span>
    </div>
  </div>
</div>
<div class="container">
"@)

# ══════════════════════════════════════════════════════════════════
# TAB 1 — AUDIT
# ══════════════════════════════════════════════════════════════════
[void]$sb.AppendLine('<div id="tab-audit" class="tab-panel active">')

# Executive Summary
if ($topFindings.Count -gt 0) {
    [void]$sb.AppendLine('<div class="exec-summary"><h2>&#9888; Executive Summary — Top Findings</h2>')
    foreach ($f in $topFindings) {
        [void]$sb.AppendLine("<div class=`"finding-row`"><span class=`"fr-sev $($f.Sev)`">$($f.Sev.ToUpper())</span><span class=`"fr-src`"><a href=`"#$($f.Src)`" style=`"color:inherit`">$($f.Src)</a></span><span class=`"fr-msg`">$($f.Msg)</span></div>")
    }
    [void]$sb.AppendLine('</div>')
}

# Execution errors / warnings block — só aparece se houver
if ($Global:ErrorCount -gt 0 -or $Global:WarnCount -gt 0) {
    $errColor = if ($Global:ErrorCount -gt 0) { "var(--red)" } else { "var(--yellow)" }
    $errBg    = if ($Global:ErrorCount -gt 0) { "rgba(248,81,73,.05)" } else { "rgba(210,153,34,.05)" }
    [void]$sb.AppendLine("<div style=`"background:$errBg;border:1px solid $errColor;border-left:4px solid $errColor;border-radius:6px;padding:14px 18px;margin-bottom:14px`">")
    [void]$sb.AppendLine("<h2 style=`"color:$errColor;font-size:.95em;margin-bottom:10px`">&#9888; Execution Issues &mdash; $($Global:ErrorCount) errors, $($Global:WarnCount) warnings</h2>")
    [void]$sb.AppendLine("<div style=`"font-size:.82em;color:var(--dim);margin-bottom:8px`">Log estruturado: <code style=`"color:var(--cyan)`">$($Global:ErrorLog)</code></div>")

    # Ler últimos 15 eventos do error log e mostrar tabela
    if (Test-Path $Global:ErrorLog) {
        try {
            $logLines = Get-Content $Global:ErrorLog -Tail 15 -ErrorAction SilentlyContinue |
                        Where-Object { $_ -and -not $_.StartsWith("#") }
            if ($logLines) {
                [void]$sb.AppendLine('<details><summary style="cursor:pointer;color:var(--cyan);font-size:.85em">Ver últimos 15 eventos</summary>')
                [void]$sb.AppendLine('<table class="vtable" style="margin-top:8px"><thead><tr><th>Hora</th><th>Nível</th><th>Fase</th><th>Mensagem</th></tr></thead><tbody>')
                foreach ($line in $logLines) {
                    try {
                        $e = $line | ConvertFrom-Json
                        $ts = $e.timestamp -replace 'T',' ' -replace 'Z',''
                        $lvl = $e.level
                        $msg = (Escape-Html $e.message)
                        if ($msg.Length -gt 100) { $msg = $msg.Substring(0, 100) }
                        $ph = Escape-Html $e.phase
                        if ($ph.Length -gt 30) { $ph = $ph.Substring(0, 30) }
                        $lvlColor = if ($lvl -eq "ERROR") { "var(--red)" } else { "var(--yellow)" }
                        [void]$sb.AppendLine("<tr><td style=`"font-size:.75em;color:var(--dim)`">$ts</td><td><span style=`"color:$lvlColor;font-weight:bold`">$lvl</span></td><td style=`"color:var(--cyan);font-size:.78em`">$ph</td><td style=`"font-size:.8em`">$msg</td></tr>")
                    } catch {}
                }
                [void]$sb.AppendLine('</tbody></table></details>')
            }
        } catch {}
    }
    [void]$sb.AppendLine('</div>')
}

# CVE Table (extraída dos .txt)
if ($cveTable.Count -gt 0) {
    [void]$sb.AppendLine("<div class=`"category`"><div class=`"category-h`">&#128027; CVE Summary ($UniqCves únicos nos scans)</div>")
    [void]$sb.AppendLine("<div class=`"sec`"><div class=`"sec-h`" onclick=`"toggle('cve-audit-table')`"><span class=`"sec-t`">&#128202; CVE Table</span></div><div class=`"sec-c open`" id=`"cve-audit-table-content`">")
    [void]$sb.AppendLine('<table class="cve-table"><thead><tr><th>Severity</th><th>CVE ID</th><th>Source</th><th>Description</th></tr></thead><tbody>')
    foreach ($cve in $cveTable) {
        $sevClass = switch ($cve.Sev) { "CRITICAL"{"CRITICAL"} "HIGH"{"HIGH"} "MEDIUM"{"MEDIUM"} "LOW"{"LOW"} default{"UNKNOWN"} }
        [void]$sb.AppendLine("<tr><td><span class=`"sev-tag sev-$sevClass`">$($cve.Sev)</span></td><td><span class=`"cve-id`">$($cve.Cve)</span></td><td><a href=`"#$($cve.Src)`" style=`"color:var(--cyan)`">$($cve.Src)</a></td><td>$($cve.Desc)</td></tr>")
    }
    [void]$sb.AppendLine('</tbody></table></div></div></div>')
}

# Secções por categoria
foreach ($cat in $tocOrder) {
    $files = $catFiles[$cat]; if (-not $files) { continue }
    $label = switch ($cat) { 'system' {'&#x1F5A5; System'} 'network' {'&#x1F310; Network'} 'privesc' {'&#x1F510; Privilege Escalation'} 'hardening' {'&#x1F6E1; Hardening'} 'cve' {'&#x1F41B; CVE / Vulnerabilities'} default {'&#x1F4C4; Other'} }
    $catCrit = 0; $catHigh = 0
    foreach ($f in $files) {
        $catCrit += $CountCache[$f.FullName].Crit
        $catHigh += $CountCache[$f.FullName].High
    }
    $catCls = "category"
    if ($catCrit -gt 0) { $catCls += " has-crit" }
    if ($catHigh -gt 0) { $catCls += " has-high" }
    [void]$sb.AppendLine("<div class=`"$catCls`"><div class=`"category-h`">$label</div>")
    foreach ($f in $files) {
        $content = $FileCache[$f.FullName]
        if ([string]::IsNullOrWhiteSpace($content)) { $content = "(vazio)" }
        $fc = $CountCache[$f.FullName].Crit
        $fh = $CountCache[$f.FullName].High
        $badges = ""
        if ($fc -gt 0) { $badges += "<span class=`"badge b-crit`">$fc CRITICAL</span>" }
        if ($fh -gt 0) { $badges += "<span class=`"badge b-high`">$fh HIGH</span>" }
        if (-not $badges) { $badges = "<span class=`"badge b-ok`">OK</span>" }
        $secCls = "sec"
        if ($fc -gt 0) { $secCls += " has-crit" }
        if ($fh -gt 0) { $secCls += " has-high" }
        $autoOpen = ""
        if ($fc -gt 0 -or $fh -gt 0) { $autoOpen = " open" }
        $contentEsc = Colorize-Html (Escape-Html $content)
        if ($f.Length -gt 500000) { $contentEsc += "`n<span style='color:var(--yellow)'>[... truncado a 3000 linhas — ver .txt completo ...]</span>" }
        [void]$sb.AppendLine("<div class=`"$secCls`" id=`"$($f.BaseName)`"><div class=`"sec-h`" onclick=`"toggle('$($f.BaseName)')`"><span class=`"sec-t`">&#128196; $($f.BaseName)</span><span>$badges</span></div><div class=`"sec-c$autoOpen`" id=`"$($f.BaseName)-content`"><pre>$contentEsc</pre></div></div>")
    }
    [void]$sb.AppendLine("</div>")
}

[void]$sb.AppendLine('</div>') # end tab-audit

# ══════════════════════════════════════════════════════════════════
# TAB 2 — CVE DASHBOARD
# ══════════════════════════════════════════════════════════════════
[void]$sb.AppendLine('<div id="tab-dashboard" class="tab-panel">')
[void]$sb.AppendLine(@"
<div id="dash-summary">
<div class="dash-grid">
  <div class="dash-card"><div class="num" style="color:var(--red)">$CveCrit</div><div class="lbl">Critical CVEs</div></div>
  <div class="dash-card"><div class="num" style="color:var(--orange)">$CveHigh</div><div class="lbl">High CVEs</div></div>
  <div class="dash-card"><div class="num" style="color:var(--yellow)">$CveMed</div><div class="lbl">Medium CVEs</div></div>
  <div class="dash-card"><div class="num" style="color:var(--green)">$CweUniq</div><div class="lbl">CWEs Únicos</div></div>
  <div class="dash-card"><div class="num" style="color:var(--cyan)">$($AppUpdates.Count)</div><div class="lbl">App Updates</div></div>
  <div class="dash-card"><div class="num" style="color:var(--text)">$($CveResults.Count)</div><div class="lbl">CVEs Total</div></div>
  <div class="dash-card"><div class="num" style="color:var(--text)">$($Inventory.Count)</div><div class="lbl">Apps Detectadas</div></div>
</div>
<div class="section2"><div class="sec2-hdr" onclick="toggleS2('top-apps')"><span class="sec2-title">&#127942; Apps com mais CVEs</span><span style="color:var(--dim)">&#9660;</span></div><div class="sec2-body open" id="top-apps-body"><div id="top-apps-content"></div></div></div>
<div class="section2"><div class="sec2-hdr" onclick="toggleS2('top-cwes')"><span class="sec2-title">&#128278; CWEs mais frequentes</span><span style="color:var(--dim)">&#9660;</span></div><div class="sec2-body" id="top-cwes-body"><div id="top-cwes-content"></div></div></div>
</div>
<div id="dash-cve" style="display:none">
  <input class="search-box" id="cve-search" placeholder="&#128269; Filtrar CVE, app, CWE, descrição..." oninput="renderCves()">
  <div id="cve-table-wrap"></div>
</div>
<div id="dash-upd" style="display:none">
  <div class="section2"><div class="sec2-hdr" onclick="toggleS2('upd-sec')"><span class="sec2-title">&#128230; App Updates Disponíveis</span><span style="color:var(--dim)">&#9660;</span></div><div class="sec2-body open" id="upd-sec-body"><div id="upd-content"></div></div></div>
</div>
<div id="dash-inv" style="display:none">
  <input class="search-box" id="inv-search" placeholder="&#128269; Filtrar apps..." oninput="renderInv()">
  <div id="inv-grid-wrap"></div>
</div>
"@)
[void]$sb.AppendLine('</div>') # end tab-dashboard

# ── Footer + JS ────────────────────────────────────────────────────
[void]$sb.AppendLine(@"
</div><!-- /container -->
<div class="footer">windows-full-audit &mdash; $Target &mdash; $Date &mdash; $buildStr</div>
</main>
<script>
const DATA_CVE=$CveJson;
const DATA_INV=$InvJson;
const DATA_UPD=$UpdJson;
let cveFilter='all';

function switchTab(id,el){
  document.querySelectorAll('.tab-panel').forEach(p=>p.classList.remove('active'));
  document.getElementById('tab-'+id).classList.add('active');
  document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));
  if(el) el.classList.add('active');
  document.getElementById('toc-audit').style.display=id==='audit'?'':'none';
  document.getElementById('toc-dash').style.display=id==='audit'?'none':'';
  if(id==='dashboard'){renderSummary();renderCves();}
}
function toggle(id){var c=document.getElementById(id+'-content');if(c)c.classList.toggle('open');}
function toggleS2(id){var b=document.getElementById(id+'-body');if(b)b.classList.toggle('open');}
function setFilter(mode,el){
  document.body.classList.remove('filter-critical','filter-high');
  if(mode!=='all')document.body.classList.add('filter-'+mode);
  document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));
  if(el)el.classList.add('active');
}
function showDash(id,el){
  document.querySelectorAll('#tab-dashboard > div').forEach(d=>d.style.display='none');
  var s=document.getElementById('dash-'+id);if(s)s.style.display='block';
  document.querySelectorAll('#toc-dash .toc-item').forEach(i=>i.classList.remove('active'));
  if(el)el.classList.add('active');
  if(id==='cve')renderCves();if(id==='inv')renderInv();if(id==='upd')renderUpd();if(id==='summary')renderSummary();
}
function sevBadge(s){
  var sn=(s||'UNKNOWN').toUpperCase();
  var cls={'CRITICAL':'sev-CRITICAL','HIGH':'sev-HIGH','IMPORTANT':'sev-HIGH','MEDIUM':'sev-MEDIUM','MODERATE':'sev-MEDIUM','LOW':'sev-LOW','NEGLIGIBLE':'sev-LOW'}[sn]||'sev-UNKNOWN';
  return '<span class="sev '+cls+'">'+sn+'</span>';
}
function renderCves(){
  var q=(document.getElementById('cve-search')?.value||'').toLowerCase();
  var rows=DATA_CVE;
  if(cveFilter!=='all')rows=rows.filter(r=>(r.Severity||'').toUpperCase()===cveFilter);
  if(q)rows=rows.filter(r=>(r.CveId||'').toLowerCase().includes(q)||(r.App||'').toLowerCase().includes(q)||(r.Cwe||'').toLowerCase().includes(q)||(r.Description||'').toLowerCase().includes(q));
  var ord={CRITICAL:0,HIGH:1,IMPORTANT:1,MEDIUM:2,MODERATE:2,LOW:3,NEGLIGIBLE:3};
  rows.sort((a,b)=>{var sa=ord[(a.Severity||'').toUpperCase()]??9,sb=ord[(b.Severity||'').toUpperCase()]??9;return sa!==sb?sa-sb:(parseFloat(b.Cvss)||0)-(parseFloat(a.Cvss)||0);});
  var h='<div style="display:flex;gap:5px;margin-bottom:8px">';
  ['all','CRITICAL','HIGH','MEDIUM'].forEach(f=>{h+='<span style="padding:2px 9px;border-radius:3px;font-size:.77em;cursor:pointer;border:1px solid var(--border);'+(cveFilter===f?'color:var(--cyan);border-color:var(--cyan);':'color:var(--dim)')+'" onclick="cveFilter=\''+f+'\';renderCves()">'+f+'</span>';});
  h+='</div><p style="color:var(--dim);font-size:.79em;margin-bottom:8px">'+rows.length+' CVEs</p>';
  h+='<table class="vtable"><thead><tr><th>Sev</th><th>CVSS</th><th>CVE</th><th>App/Ver</th><th>Fix</th><th>CWE</th><th>Fonte</th><th>Desc</th></tr></thead><tbody>';
  rows.forEach(r=>{
    var fix=r.FixedIn?'<span class="fixed">&#10003; '+r.FixedIn+'</span>':'<span style="color:var(--dim);font-size:.77em">&#8211;</span>';
    var cweS=r.Cwe?'<span class="cwe-id">'+r.Cwe+'</span>':'&#8211;';
    var cveL=r.CveId?'<a class="cve-id" href="https://nvd.nist.gov/vuln/detail/'+r.CveId+'" target="_blank" style="text-decoration:none">'+r.CveId+'</a>':'&#8211;';
    var desc=(r.Title||r.Description||'').substring(0,130);
    h+='<tr>'+
       '<td>'+sevBadge(r.Severity)+'</td>'+
       '<td style="color:var(--yellow)">'+(r.Cvss!=null?r.Cvss:'&#8211;')+'</td>'+
       '<td>'+cveL+'</td>'+
       '<td><b>'+(r.App||'')+'</b><br><span style="color:var(--dim);font-size:.77em">'+(r.Version||'')+'</span></td>'+
       '<td>'+fix+'</td><td>'+cweS+'</td>'+
       '<td style="color:var(--dim);font-size:.77em">'+(r.Source||'')+'</td>'+
       '<td style="font-size:.79em;color:var(--dim)">'+desc+'</td></tr>';
  });
  h+='</tbody></table>';
  document.getElementById('cve-table-wrap').innerHTML=h;
}
function renderInv(){
  var q=(document.getElementById('inv-search')?.value||'').toLowerCase();
  var rows=q?DATA_INV.filter(r=>(r.Name||'').toLowerCase().includes(q)||(r.Category||'').toLowerCase().includes(q)):DATA_INV;
  var h='<p style="color:var(--dim);font-size:.79em;margin-bottom:10px">'+rows.length+' apps</p><div class="inv-grid">';
  rows.forEach(r=>{
    var key=r.Key||r.Name;
    var cc=DATA_CVE.filter(c=>c.App===key).length;
    var crit=DATA_CVE.filter(c=>c.App===key&&(c.Severity||'').toUpperCase()==='CRITICAL').length;
    var hi=DATA_CVE.filter(c=>c.App===key&&['HIGH','IMPORTANT'].includes((c.Severity||'').toUpperCase())).length;
    var badge=crit>0?'<span style="color:var(--red);font-size:.73em">&#128308; '+crit+' Critical</span>':
              hi>0  ?'<span style="color:var(--orange);font-size:.73em">&#128992; '+hi+' High</span>':
              cc>0  ?'<span style="color:var(--yellow);font-size:.73em">&#9888; '+cc+' CVEs</span>':
                     '<span style="color:var(--green);font-size:.73em">&#10003; OK</span>';
    h+='<div class="inv-card"><h4>'+(r.Name||key)+'</h4><div class="inv-ver">'+(r.Version||'&#8211;')+'</div><div style="margin-top:3px">'+badge+'</div><span class="inv-cat">'+(r.Category||'')+'</span></div>';
  });
  h+='</div>';
  document.getElementById('inv-grid-wrap').innerHTML=h;
}
function renderUpd(){
  if(!DATA_UPD||!DATA_UPD.length){document.getElementById('upd-content').innerHTML='<p style="color:var(--green)">&#10003; Sem updates encontrados</p>';return;}
  var h='<p style="color:var(--dim);font-size:.79em;margin-bottom:8px">'+DATA_UPD.length+' updates</p>';
  h+='<table class="vtable"><thead><tr><th>Fonte</th><th>App</th><th>Atual</th><th>Disponível</th><th>Comando</th></tr></thead><tbody>';
  DATA_UPD.forEach(u=>{
    h+='<tr class="upd-row"><td style="color:var(--dim)">'+(u.Source||'')+'</td><td><b>'+(u.Name||'')+'</b></td><td style="color:var(--dim)">'+(u.Current||'')+'</td><td style="color:var(--green)">'+(u.Available||'')+'</td><td><span class="upd-cmd" onclick="navigator.clipboard.writeText(this.dataset.cmd)" data-cmd="'+(u.UpdateCmd||'').replace(/"/g,"&quot;")+'" title="Copiar">'+(u.UpdateCmd||'')+'</span></td></tr>';
  });
  h+='</tbody></table>';
  document.getElementById('upd-content').innerHTML=h;
}
function renderSummary(){
  var appC={};
  DATA_CVE.forEach(c=>{var a=c.App||'?';if(!appC[a])appC[a]={t:0,c:0,h:0};appC[a].t++;var s=(c.Severity||'').toUpperCase();if(s==='CRITICAL')appC[a].c++;else if(['HIGH','IMPORTANT'].includes(s))appC[a].h++;});
  var top=Object.entries(appC).sort((a,b)=>(b[1].c*100+b[1].h*10+b[1].t)-(a[1].c*100+a[1].h*10+a[1].t)).slice(0,15);
  var h='<table class="vtable"><thead><tr><th>App</th><th>Total</th><th>Critical</th><th>High</th></tr></thead><tbody>';
  top.forEach(([app,c])=>{h+='<tr><td><b>'+app+'</b></td><td>'+c.t+'</td><td>'+(c.c>0?'<span style="color:var(--red)">'+c.c+'</span>':'&#8211;')+'</td><td>'+(c.h>0?'<span style="color:var(--orange)">'+c.h+'</span>':'&#8211;')+'</td></tr>';});
  h+='</tbody></table>';
  document.getElementById('top-apps-content').innerHTML=h;
  var cweC={};
  DATA_CVE.forEach(c=>{(c.Cwe||'').split(/,\s*/).forEach(cw=>{cw=cw.trim();if(cw.match(/^CWE-\d+/))cweC[cw]=(cweC[cw]||0)+1;});});
  var topCwe=Object.entries(cweC).sort((a,b)=>b[1]-a[1]).slice(0,10);
  var ch=topCwe.length===0?'<p style="color:var(--dim)">Sem CWEs (via Trivy/NVD)</p>':'<table class="vtable"><thead><tr><th>CWE</th><th>Ocorrências</th><th>Ref</th></tr></thead><tbody>';
  topCwe.forEach(([cwe,n])=>{var num=cwe.replace('CWE-','');ch+='<tr><td><span class="cwe-id">'+cwe+'</span></td><td>'+n+'</td><td><a href="https://cwe.mitre.org/data/definitions/'+num+'.html" target="_blank" style="color:var(--cyan);font-size:.79em">cwe.mitre.org &#8599;</a></td></tr>';});
  if(topCwe.length>0)ch+='</tbody></table>';
  document.getElementById('top-cwes-content').innerHTML=ch;
}
function initScrollSpy(){
  var items=document.querySelectorAll('#toc-audit .toc-item');
  var sections=document.querySelectorAll('#tab-audit .sec[id]');
  var obs=new IntersectionObserver(function(entries){entries.forEach(function(e){if(e.isIntersecting){var id=e.target.id;items.forEach(function(i){i.classList.toggle('active',i.getAttribute('href')==='#'+id);});}});},{rootMargin:'-120px 0px -60% 0px'});
  sections.forEach(function(s){obs.observe(s);});
}
document.addEventListener('DOMContentLoaded',function(){
  document.querySelectorAll('.sec-c.open').forEach(function(el){el.style.maxHeight='none';});
  initScrollSpy(); renderSummary(); renderCves();
});
</script>
</body>
</html>
"@)

$sb.ToString() | Out-File $Report -Encoding UTF8

if ((Test-Path $Report) -and (Get-Item $Report).Length -gt 0) {
    $sz = [math]::Round((Get-Item $Report).Length / 1KB)
    Write-Info "Relatório: $Report ($sz KB)"
} else { Write-Err "Falha ao gerar relatório HTML" }

# ── AV Cleanup ────────────────────────────────────────────────────
if ($AvExclusionAdded) {
    Remove-MpPreference -ExclusionPath $Tools -ErrorAction SilentlyContinue
    Write-Info "AV exclusion removida"
}

# ── Sumário Final ─────────────────────────────────────────────────
$summaryLines = @(
    "╔══════════════════════════════════════════════════╗"
    "║   AUDIT COMPLETO                                 ║"
    "╠══════════════════════════════════════════════════╣"
    "║  [Audit]  Critical  : $TotalCrit"
    "║  [Audit]  High      : $TotalHigh"
    "║  [Audit]  CVEs txt  : $UniqCves"
    "║  [Dash]   CVEs JSON : $($CveResults.Count)"
    "║  [Dash]   CWEs      : $CweUniq"
    "║  [Dash]   App upd   : $($AppUpdates.Count)"
    "║  Inventário         : $($Inventory.Count) apps conhecidas"
    "╠══════════════════════════════════════════════════╣"
    "║  Execução  errors   : $($Global:ErrorCount)"
    "║  Execução  warnings : $($Global:WarnCount)"
    "╠══════════════════════════════════════════════════╣"
    "║  Relatório HTML : $Report"
    "║  Inventory JSON : $InvFile"
    "║  CVEs JSON      : $CveFile"
    "║  CVEs CSV       : $CveCsv"
    "║  CVEs SARIF     : $CveSarif"
    "║  Event log      : $($Global:EventLog)"
    "║  Error log      : $($Global:ErrorLog)"
)
if (Test-Path $DiffFile) {
    try {
        $diffData = Get-Content $DiffFile -Raw | ConvertFrom-Json
        $summaryLines += "║  Diff vs prev   : +$($diffData.summary.new) novos, -$($diffData.summary.resolved) resolvidos"
        $summaryLines += "║                   $DiffFile"
    } catch {}
}
$summaryLines += "╚══════════════════════════════════════════════════╝"

Write-Host "`n$($summaryLines -join "`n")" -ForegroundColor Cyan

# Log final
Write-LogJsonl -Level "INFO" -Message "Script terminado" -Extra @{
    errors     = $Global:ErrorCount
    warnings   = $Global:WarnCount
    cves_total = $CveResults.Count
}

# Mensagem destacada se houve erros
if ($Global:ErrorCount -gt 0) {
    Write-Host "[!] " -ForegroundColor Red -NoNewline
    Write-Host "Ocorreram $($Global:ErrorCount) erros e $($Global:WarnCount) avisos durante a execução."
    Write-Host "    Ver: $($Global:ErrorLog)"
    Write-Host "    Filtrar: Get-Content '$($Global:EventLog)' | ConvertFrom-Json | Where-Object level -eq 'ERROR'"
} elseif ($Global:WarnCount -gt 0) {
    Write-Host "[!] " -ForegroundColor Yellow -NoNewline
    Write-Host "Execução com $($Global:WarnCount) avisos. Ver: $($Global:ErrorLog)"
}

if (-not $NoBrowser -and (Test-Path $Report)) {
    Write-Info "A abrir relatório no browser..."
    Start-Process $Report
}

# ── Exit code semântico (#5) ──────────────────────────────────────
$exitCode = 0
if ($FailOn -ne "") {
    switch ($FailOn) {
        "critical" {
            if ($CveCrit -gt 0 -or $TotalCrit -gt 0) {
                Write-Err "FAIL-ON CRITICAL: $CveCrit CVEs Critical (JSON), $TotalCrit findings Critical (audit)"
                $exitCode = 2
            }
        }
        "high" {
            if ($CveCrit -gt 0 -or $TotalCrit -gt 0) {
                Write-Err "FAIL-ON HIGH: $CveCrit Critical detectados"
                $exitCode = 2
            } elseif ($CveHigh -gt 0 -or $TotalHigh -gt 0) {
                Write-Err "FAIL-ON HIGH: $CveHigh CVEs High (JSON), $TotalHigh findings High (audit)"
                $exitCode = 3
            }
        }
        "medium" {
            if ($CveCrit -gt 0) { Write-Err "FAIL-ON MEDIUM: $CveCrit Critical detectados"; $exitCode = 2 }
            elseif ($CveHigh -gt 0) { Write-Err "FAIL-ON MEDIUM: $CveHigh High detectados"; $exitCode = 3 }
            elseif ($CveMed -gt 0) { Write-Err "FAIL-ON MEDIUM: $CveMed CVEs Medium"; $exitCode = 4 }
        }
    }
}

exit $exitCode
