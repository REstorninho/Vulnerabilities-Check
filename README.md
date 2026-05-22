# Security Audit Scripts

Dois scripts de auditoria de segurança — um para Windows, outro para Linux — que combinam análise de segurança abrangente com scan de CVE/CWE estruturado e relatório HTML interactivo.

---

## Scripts

| Script | Plataforma | Descrição |
|--------|-----------|-----------|
| `windows-full-audit.ps1` | Windows (PS 5.1+) | Auditoria completa + CVE Dashboard |
| `linux-full-audit.sh` | Linux (bash) | Auditoria completa + CVE Dashboard |

---

## Features avançadas

Os scripts suportam várias funcionalidades para uso em CI/CD e gestão de vulnerabilidades ao longo do tempo:

### NVD API key — 10× mais rápido

A NVD API tem rate limit muito mais elevado quando se usa uma API key. Sem key: 5 req/30s. Com key: 50 req/30s.

Obter key gratuita em [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key).

```bash
# Linux
sudo bash linux-full-audit.sh --nvd-api-key "abc123..."
NVD_API_KEY=abc123 sudo bash linux-full-audit.sh

# Windows
powershell -File windows-full-audit.ps1 -NvdApiKey "abc123..."
$env:NVD_API_KEY = "abc123"; powershell -File windows-full-audit.ps1
```

Quando há key, o sleep entre batches passa de 32s para 6s e o número de apps analisadas no NVD lookup passa de 30 para 100.

### Exports CSV e SARIF

Além do `cve_results.json`, os scripts produzem automaticamente:

| Ficheiro | Formato | Uso |
|----------|---------|-----|
| `cve_results.csv` | CSV padrão | Abrir em Excel/Sheets, partilhar com equipas |
| `cve_results.sarif` | SARIF 2.1.0 | Ingerir em GitHub Code Scanning, Azure DevOps, GitLab |

SARIF é o formato padrão da indústria — pode ser carregado directamente no GitHub Security tab via `actions/upload-sarif`, ou consumido por qualquer ferramenta de SAST/DAST que suporte o standard.

### Comparação entre runs (diff)

Comparar com um audit anterior produz um `diff_vs_previous.json` que destaca:

- **Novos CVEs** — não existiam antes (preocupante — aparição de nova vulnerabilidade)
- **CVEs resolvidos** — desapareceram (bom — confirma que o patch funcionou)
- **Mudanças de severidade** — CVSS score mudou (re-avaliação NVD)

```bash
# Linux
sudo bash linux-full-audit.sh --compare reports/host_20260515_1030/cve_results.json

# Windows
powershell -File windows-full-audit.ps1 -Compare "reports\host_20260515_1030\cve_results.json"
```

Transforma os scripts de "snapshot único" em "tracking de postura de segurança ao longo do tempo".

### Deep Scan — secrets e misconfigurations

Por defeito o Trivy corre apenas no modo `vuln` (CVEs). Com `--deep-scan`/`-DeepScan`, activa também os scanners `secret` e `misconfig`:

- **secret** — detecta tokens, API keys, passwords hardcoded em ficheiros
- **misconfig** — detecta configurações inseguras (Dockerfile, Kubernetes, Terraform, etc.)

```bash
# Linux
sudo bash linux-full-audit.sh --deep-scan

# Windows
powershell -ExecutionPolicy Bypass -File windows-full-audit.ps1 -DeepScan
```

> ⚠️ O deep scan é significativamente mais lento e pode gerar falsos positivos em ambientes com muitos ficheiros de configuração.

### Exit codes semânticos (CI/CD)

Por defeito os scripts saem com `0`. Com `--fail-on`/`-FailOn`, podem falhar o pipeline quando há findings ao nível especificado:

```bash
# Linux
sudo bash linux-full-audit.sh --fail-on critical   # falha se houver Critical
sudo bash linux-full-audit.sh --fail-on high       # falha se houver High ou Critical

# Windows
powershell -File windows-full-audit.ps1 -FailOn critical
```

Códigos de saída:

| Code | Significado |
|------|-------------|
| `0` | Sucesso, sem findings ao nível especificado |
| `1` | Erro de execução (ficheiros, paths inválidos, etc) |
| `2` | `--fail-on critical` com Critical CVEs detectados |
| `3` | `--fail-on high` com High CVEs detectados |
| `4` | `--fail-on medium` com Medium CVEs detectados |

### Cache global de Trivy e Grype

A DB de vulnerabilidades do Trivy tem ~500MB e o Grype tem ~150MB. Por defeito são descarregadas para o home do utilizador. Os scripts redireccionam para `tools/trivy-cache/` e `tools/grype-cache/` — persistem entre execuções, poupam centenas de MB de tráfego e minutos por run.

### Exemplo: pipeline GitHub Actions

```yaml
- name: Security audit
  run: sudo bash linux-full-audit.sh --nvd-api-key ${{ secrets.NVD_API_KEY }} --fail-on critical
  
- name: Upload SARIF
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: reports/*/cve_results.sarif
    
- name: Upload artifacts
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: audit-report
    path: reports/
```

### Logging estruturado de execução

Cada run produz dois ficheiros de log em formato **JSON Lines** (uma linha por evento), úteis para debugging e auditoria:

| Ficheiro | Conteúdo |
|----------|----------|
| `audit_events.log` | Todos os eventos (INFO, WARN, ERROR) |
| `audit_errors.log` | Apenas ERROR e WARN — para debug rápido |

Cada linha é um objecto JSON com `timestamp`, `level`, `phase`, `message` e campos extra contextuais (ex: comando que falhou, URL inacessível, stderr capturado, número de linha do script).

**Filtrar com `jq` (Linux):**
```bash
# Só erros
jq 'select(.level=="ERROR")' reports/*/audit_events.log

# Erros agrupados por fase
jq -s 'group_by(.phase) | map({phase: .[0].phase, count: length})' reports/*/audit_errors.log

# Linha do tempo de execução
jq -c '{ts: .timestamp, lvl: .level, msg: .message}' reports/*/audit_events.log
```

**Filtrar com PowerShell (Windows):**
```powershell
# Só erros
Get-Content reports\*\audit_events.log | ConvertFrom-Json | Where-Object level -eq 'ERROR'

# Erros agrupados por fase
Get-Content reports\*\audit_errors.log | ConvertFrom-Json |
  Group-Object phase | Select-Object Name,Count
```

**No relatório HTML** — se houver erros ou avisos durante a execução, um bloco destacado aparece logo após o Executive Summary com contagens e os últimos 15 eventos do log. Caso contrário, não é mostrado.

O sumário final no terminal mostra sempre o número de errors/warnings e o caminho do log, mesmo que a execução tenha terminado com sucesso.

---

## Relatório HTML

O relatório gerado tem **duas tabs**:

**Tab "Audit"** — output dos scans de segurança:
- Executive Summary com top findings (CRÍTICO/ALERTA)
- Tabela de CVEs extraída dos scans de texto
- Secções colapsáveis por categoria com badges de severidade
- TOC lateral com scrollspy e filtros Critical / +High
- Colorização automática de findings, CVEs e CWEs

**Tab "CVE Dashboard"** — análise estruturada em JSON:
- Dashboard com cards de métricas (Critical, High, Medium, CWEs, Updates)
- Top apps por CVE count + Top CWEs com link para cwe.mitre.org
- Tabela CVE/CWE interactiva com filtros e ordenação por CVSS score
- Links directos para nvd.nist.gov por CVE ID
- App updates com comandos prontos a copiar (copy-to-clipboard)
- Inventário de apps/packages em grid com badge de severidade por app

---

## windows-full-audit.ps1

### Requisitos

- Windows 10/11 ou Windows Server 2016+
- **PowerShell 5.1** (incluído no Windows — não requer PS 7)
- Ligação à internet para download de ferramentas e consulta NVD/MSRC
- Executar como **Administrador** para cobertura total

### Uso

```powershell
# Auditoria completa
powershell -ExecutionPolicy Bypass -File windows-full-audit.ps1

# Com exclusão do Defender (recomendado — evita bloqueio do winPEAS)
powershell -ExecutionPolicy Bypass -File windows-full-audit.ps1 -AvExclusion

# Modo rápido (salta winPEAS e Seatbelt)
powershell -ExecutionPolicy Bypass -File windows-full-audit.ps1 -Quick

# Deep scan (Trivy com secrets + misconfig)
powershell -ExecutionPolicy Bypass -File windows-full-audit.ps1 -DeepScan

# Sem consulta NVD (offline)
powershell -ExecutionPolicy Bypass -File windows-full-audit.ps1 -NoNvd

# Forçar re-download de todas as ferramentas
powershell -ExecutionPolicy Bypass -File windows-full-audit.ps1 -Force

# Output personalizado
powershell -ExecutionPolicy Bypass -File windows-full-audit.ps1 -Output C:\audit
```

### Parâmetros

| Parâmetro | Alias | Descrição |
|-----------|-------|-----------|
| `-Help` | `-h` | Mostra ajuda |
| `-Output DIR` | `-o` | Directório de output personalizado |
| `-SkipDownload` | `-s` | Usa ferramentas em cache, não descarrega |
| `-Quick` | `-q` | Salta winPEAS e Seatbelt (mais rápido) |
| `-DeepScan` | | Activa Trivy secret+misconfig (mais lento, encontra secrets) |
| `-NoNvd` | `-n` | Salta consulta NVD API (modo offline) |
| `-NoBrowser` | | Não abre o relatório no browser |
| `-AvExclusion` | | Adiciona `tools\` às exclusões do Defender durante o scan |
| `-Force` | | Re-download de ferramentas mesmo que já existam em cache |
| `-NvdApiKey KEY` | | NVD API key (também via env var `NVD_API_KEY`) |
| `-Compare FILE` | | Comparar com `cve_results.json` de run anterior |
| `-FailOn LEVEL` | | Exit code != 0 quando há findings (`critical`/`high`/`medium`) |

### Fases de execução

| Fase | Descrição |
|------|-----------|
| 1 | Download de ferramentas (winPEAS, Seatbelt, PrivescCheck, Trivy, Grype, OSV-Scanner, Watson, WES-NG) |
| 2 | 12 scans de segurança → ficheiros `.txt` |
| 3 | Inventário JSON estruturado (registry + FileVersionInfo) |
| 4 | CVE/CWE JSON via Trivy + Grype + NVD API |
| 5 | App updates JSON via winget + Chocolatey + Scoop |
| 6 | Relatório HTML unificado |

### Scans (Fase 2)

| Ficheiro | Conteúdo |
|----------|----------|
| `01_sysinfo.txt` | Informação do sistema, hotfixes, processos, drives |
| `02_users_groups.txt` | Utilizadores locais, grupos, sessões, últimos logins |
| `03_network.txt` | Interfaces, portas, routing, firewall, SMB shares, Wi-Fi |
| `04_winpeas.txt` | Privesc automático — winPEAS |
| `05_seatbelt.txt` | Hardening checks — Seatbelt / SharpUp |
| `06_privesc.txt` | PrivescCheck: unquoted paths, DLL hijack, scheduled tasks |
| `07_trivy.txt` | CVE scan do filesystem (Trivy, formato tabela) |
| `08_nvd_cve.txt` | NVD API lookup para componentes do SO (Windows, IIS, .NET, OpenSSH) |
| `09_registry.txt` | Registry sensível: LSA, WDigest, AutoLogon, UAC, SMBv1, RDP, PS Logging |
| `10_services.txt` | Serviços: unquoted paths, DLL hijack, tarefas agendadas não-Microsoft |
| `11_patch_gap.txt` | WES-NG + MSRC API (6 Patch Tuesdays) + Watson + CVEs inline |
| `12_app_vulns.txt` | OSV-Scanner, Grype, PURL/NVD lookup, inventário completo de apps |

### Ferramentas descarregadas (tools\)

| Ferramenta | Fonte | Propósito |
|-----------|-------|-----------|
| winPEAS | github.com/peass-ng/PEASS-ng | Enumeração automática de privesc |
| Seatbelt | GhostPack / kraloveckey mirror | Hardening checks |
| PrivescCheck | github.com/itm4n/PrivescCheck | Análise de vectores de privesc |
| Trivy | github.com/aquasecurity/trivy | CVE scan de filesystem |
| Grype | github.com/anchore/grype | CVE scan alternativo |
| OSV-Scanner | github.com/google/osv-scanner | Scan de lock files e SBOM |
| Watson | GhostPack / kraloveckey mirror | Checks de CVEs Windows clássicos |

### Cobertura de CVEs inline (Fase 11)

Verificação offline de CVEs Windows de alto impacto, comparando hotfixes instalados:

`CVE-2026-21533` (RDS EoP) · `CVE-2026-21519` (DWM EoP) · `CVE-2025-21333/34/35` · `CVE-2025-24983` · `CVE-2025-26633` · `CVE-2024-38080` · `CVE-2024-21338` · `CVE-2023-28252` · `CVE-2022-21999` · `CVE-2021-34527` (PrintNightmare) · `CVE-2021-36934` (HiveNightmare) · `CVE-2020-0796` (SMBGhost) · `CVE-2020-1472` (ZeroLogon) · `CVE-2019-0708` (BlueKeep) · `CVE-2017-0144` (EternalBlue)

### Estrutura de output

```
C:\recon\
├── windows-full-audit.ps1
├── tools\
│   ├── winPEASany_ofs.exe
│   ├── Seatbelt.exe
│   ├── PrivescCheck.ps1
│   ├── trivy.exe
│   ├── grype.exe
│   ├── osv-scanner.exe
│   └── Watson.exe
└── reports\
    └── HOSTNAME_20260518_1030\
        ├── 01_sysinfo.txt
        ├── ...
        ├── 12_app_vulns.txt
        ├── inventory.json
        ├── cve_results.json
        ├── app_updates.json
        └── REPORT_HOSTNAME_20260518_1030.html
```

---

## linux-full-audit.sh

### Requisitos

- Linux (Debian/Ubuntu/Kali, RHEL/CentOS/Fedora, Arch/Manjaro, openSUSE, Alpine)
- `bash`, `python3`, `curl`, `tar`
- `perl` — necessário para linux-exploit-suggester-2
- Ligação à internet para download de ferramentas e consulta NVD
- Executar como **root** (`sudo`) para cobertura total

### Uso

```bash
# Auditoria completa
sudo bash linux-full-audit.sh

# Modo rápido (salta linPEAS e Lynis)
sudo bash linux-full-audit.sh --quick

# Sem consulta NVD (offline)
sudo bash linux-full-audit.sh --no-nvd

# Offline completo (sem downloads, sem NVD)
sudo bash linux-full-audit.sh --skip-download --no-nvd

# Deep scan (Trivy com secrets + misconfig)
sudo bash linux-full-audit.sh --deep-scan

# Forçar re-download de todas as ferramentas
sudo bash linux-full-audit.sh --force

# Output personalizado
sudo bash linux-full-audit.sh --output /tmp/audit
```

### Parâmetros

| Parâmetro | Alias | Descrição |
|-----------|-------|-----------|
| `--help` | `-h` | Mostra ajuda |
| `--output DIR` | `-o` | Directório de output personalizado |
| `--skip-download` | `-s` | Usa ferramentas em cache, não descarrega |
| `--quick` | `-q` | Salta linPEAS e Lynis (mais rápido) |
| `--deep-scan` | | Activa Trivy secret+misconfig (mais lento, encontra secrets) |
| `--no-nvd` | `-n` | Salta consulta NVD API (modo offline) |
| `--no-browser` | | Não tenta abrir o relatório no browser |
| `--force` | | Re-download de ferramentas mesmo que já existam em cache |
| `--nvd-api-key KEY` | | NVD API key (também via env var `NVD_API_KEY`) |
| `--compare FILE` | | Comparar com `cve_results.json` de run anterior |
| `--fail-on LEVEL` | | Exit code != 0 quando há findings (`critical`/`high`/`medium`) |

### Fases de execução

| Fase | Descrição |
|------|-----------|
| 1 | Download de ferramentas (linPEAS, Lynis, Trivy, Grype, OSV-Scanner, LES2, linux-exploit-suggester) |
| 2 | 11 scans de segurança → ficheiros `.txt` |
| 3 | Inventário JSON estruturado (packages do sistema + binários conhecidos) |
| 4 | CVE/CWE JSON via Trivy + Grype + NVD API |
| 5 | App updates JSON via apt/dnf/pacman/zypper/apk |
| 6 | Relatório HTML unificado |

### Scans (Fase 2)

| Ficheiro | Conteúdo |
|----------|----------|
| `01_sysinfo.txt` | Hostname, OS, CPU, memória, discos, interfaces, routing, portas, utilizadores |
| `02_packages.txt` | Packages instalados, actualizações pendentes, versões críticas |
| `03_linpeas.txt` | Privesc automático — linPEAS |
| `04_lynis.txt` | Hardening audit — Lynis (ou manual se indisponível) |
| `05_trivy.txt` | CVE scan do filesystem (Trivy, formato tabela, CRITICAL/HIGH/MEDIUM) |
| `06_nvd_cve.txt` | NVD API lookup para componentes chave (OpenSSL, OpenSSH, Python, nginx) |
| `07_ssh_audit.txt` | Config SSH: PermitRootLogin, PasswordAuth, MaxAuthTries, X11, TcpForwarding + CWE mapping |
| `08_users_perms.txt` | UID 0 duplicados, passwords vazias, sudoers, SUID não-standard, capabilities |
| `09_services_net.txt` | Serviços activos, portas, conexões estabelecidas, firewall, Docker API TCP |
| `10_patch_gap.txt` | LES2 + security updates por distro + kernel vs upstream + CVEs inline |
| `11_app_vulns.txt` | Inventário completo, OSV-Scanner, Grype, PURL/NVD lookup, Trivy apps |

### Ferramentas descarregadas (tools/)

| Ferramenta | Fonte | Propósito |
|-----------|-------|-----------|
| linPEAS | github.com/peass-ng/PEASS-ng | Enumeração automática de privesc |
| Lynis | cisofy.com | Hardening audit (CIS Benchmarks) |
| Trivy | github.com/aquasecurity/trivy | CVE scan de filesystem |
| Grype | github.com/anchore/grype | CVE scan alternativo |
| OSV-Scanner | github.com/google/osv-scanner | Scan de lock files e SBOM |
| linux-exploit-suggester-2 | github.com/jondonas/linux-exploit-suggester-2 | Kernel CVEs |
| linux-exploit-suggester | github.com/The-Z-Labs/linux-exploit-suggester | Kernel exploits |

### Distribuições suportadas

| Distro | Package Manager | Comando de updates |
|--------|-----------------|--------------------|
| Debian / Ubuntu / Kali | `apt` | `apt-get install --only-upgrade <pkg>` |
| RHEL / CentOS / Fedora | `dnf` / `yum` | `dnf update -y <pkg>` |
| Arch / Manjaro | `pacman` | `pacman -S --noconfirm <pkg>` |
| openSUSE | `zypper` | `zypper update <pkg>` |
| Alpine | `apk` | `apk add --upgrade <pkg>` |

### Cobertura de CVEs inline (Fase 10)

Verificação offline de kernel CVEs de alto impacto, comparando versão do kernel actual com versão de fix:

`CVE-2026-43500` (Dirty Frag RxRPC, exploit público) · `CVE-2026-43284` (Dirty Frag ESP, exploited) · `CVE-2026-31431` (Copy Fail algif_aead, exploited) · `CVE-2024-1086` (nf_tables UAF, exploited) · `CVE-2024-0646` (mremap OOB) · `CVE-2023-4623` (sch_hfsc UAF, exploited) · `CVE-2023-32629` + `CVE-2023-2640` (overlayfs Ubuntu, exploited) · `CVE-2023-3389` (io_uring UAF) · `CVE-2022-0847` (Dirty Pipe, exploited) · `CVE-2022-0185` (fsconfig heap overflow) · `CVE-2021-4034` (PwnKit) · `CVE-2021-22555` (netfilter, exploited) · `CVE-2021-3156` (Baron Samedit sudo) · `CVE-2020-14386` (raw socket LPE) · `CVE-2016-5195` (Dirty COW)

Checks adicionais específicos de distro: PwnKit (pkexec), overlayfs Ubuntu, runc CVE-2024-21626 (Leaky Vessels).

### Estrutura de output

```
/opt/audit/
├── linux-full-audit.sh
├── tools/
│   ├── linpeas.sh
│   ├── lynis/
│   ├── trivy
│   ├── grype
│   ├── osv-scanner
│   ├── les2.pl
│   └── linux-exploit-suggester.sh
└── reports/
    └── hostname_20260518_1030/
        ├── 01_sysinfo.txt
        ├── ...
        ├── 11_app_vulns.txt
        ├── inventory.json
        ├── cve_results.json
        ├── app_updates.json
        ├── trivy_raw.json
        ├── grype_raw.json
        └── REPORT_hostname_20260518_1030.html
```

---

## Comparação de funcionalidades

| Funcionalidade | Windows | Linux |
|----------------|---------|-------|
| Privesc automático | winPEAS | linPEAS |
| Hardening audit | Seatbelt + PrivescCheck | Lynis |
| SSH audit + CWE | ✓ (registry + config) | ✓ (sshd_config) |
| Registry / configuração sensível | LSA, WDigest, UAC, SMBv1, RDP | — |
| SUID / capabilities | — | ✓ |
| CVE scan filesystem | Trivy + Grype | Trivy + Grype |
| Deep scan (secrets + misconfig) | ✓ (`-DeepScan`) | ✓ (`--deep-scan`) |
| Lock files (OSV) | ✓ | ✓ |
| SBOM (CycloneDX) | ✓ | ✓ |
| Patch gap — SO | WES-NG + MSRC API | LES2 + distro security updates |
| Patch gap — offline | Watson + CVEs inline | CVEs inline (kernel version check) |
| NVD API lookup | ✓ | ✓ |
| App updates | winget + choco + scoop | apt / dnf / pacman / zypper / apk |
| Inventário JSON | Registry + FileVersionInfo | dpkg/rpm/pacman/apk + binários |
| Relatório HTML | ✓ (Audit + CVE Dashboard) | ✓ (Audit + CVE Dashboard) |

---

## Notas de segurança

**winPEAS e ferramentas de privesc são detectadas como malware por antivírus.** O Windows Defender vai bloquear o download e execução do winPEAS por defeito. Opções:

1. Usar `-AvExclusion` — o script adiciona `tools\` às exclusões do Defender automaticamente e remove no final
2. Adicionar exclusão manualmente antes de correr:
   ```powershell
   Add-MpPreference -ExclusionPath "C:\recon"
   ```
3. Usar `-Quick` para saltar winPEAS e Seatbelt completamente

**linPEAS** pode ser detectado por EDRs — em ambientes com monitorização activa, considerar correr em modo `-quick` ou usar apenas as fases de CVE scan.

**NVD API** tem rate limit de 5 requests/30 segundos sem API key. A fase de NVD lookup pode demorar vários minutos dependendo do número de apps detectadas. Para uso intensivo, obter uma API key gratuita em [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key).

---

## Ficheiros produzidos

Todos os dados estruturados ficam disponíveis em múltiplos formatos para integração com outras ferramentas:

| Ficheiro | Formato | Conteúdo | Uso |
|----------|---------|----------|-----|
| `inventory.json` | JSON | Apps e packages detectados | Inventário estruturado |
| `cve_results.json` | JSON | CVEs com CVSS, CWE, FixedIn | Análise programática |
| `cve_results.csv` | CSV | CVEs em formato tabular | Excel, Sheets, partilha |
| `cve_results.sarif` | SARIF 2.1.0 | CVEs em formato padrão | GitHub Code Scanning, Azure DevOps, GitLab |
| `app_updates.json` | JSON | Updates disponíveis + comandos | Patch management |
| `diff_vs_previous.json` | JSON | Comparação com run anterior | Tracking de postura ao longo do tempo |
| `audit_events.log` | JSON Lines | Todos os eventos de execução | Debug e auditoria |
| `audit_errors.log` | JSON Lines | Só ERROR e WARN | Debug rápido |
| `REPORT_<host>_<date>.html` | HTML | Relatório interactivo | Visualização humana |

Campos do `cve_results.json`: `Source` (Trivy/Grype/NVD), `App`, `Version`, `FixedIn`, `CveId`, `Severity`, `Cvss`, `Cwe`, `Title`, `Description`, `References`.

Campos do `diff_vs_previous.json`: `summary` (counts), `new_cves`, `resolved_cves`, `severity_changes`.

---

## Dependências externas consultadas

| Serviço | URL | Propósito |
|---------|-----|-----------|
| NVD API | services.nvd.nist.gov | CVE/CWE lookup por keyword |
| MSRC API *(Windows only)* | api.msrc.microsoft.com | Patch Tuesdays e CVEs por build |
| kernel.org *(Linux only)* | kernel.org/releases.json | Versão mais recente do kernel |
| GitHub API | api.github.com | Determinar versões mais recentes de Trivy e Grype |
