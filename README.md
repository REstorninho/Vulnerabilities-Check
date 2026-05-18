# Security Audit Scripts

Dois scripts de auditoria de segurança — um para Windows, outro para Linux — que combinam análise de segurança abrangente com scan de CVE/CWE estruturado e relatório HTML interactivo.

---

## Scripts

| Script | Plataforma | Descrição |
|--------|-----------|-----------|
| `windows-full-audit.ps1` | Windows (PS 5.1+) | Auditoria completa + CVE Dashboard |
| `linux-full-audit.sh` | Linux (bash) | Auditoria completa + CVE Dashboard |

Cada script é a combinação de dois scripts anteriores num único ficheiro:

- **`windows-audit.ps1` + `vuln-check.ps1`** → `windows-full-audit.ps1`
- **`linux-audit.sh` + `vuln-check.sh`** → `linux-full-audit.sh`

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
| `-NoNvd` | `-n` | Salta consulta NVD API (modo offline) |
| `-NoBrowser` | | Não abre o relatório no browser |
| `-AvExclusion` | | Adiciona `tools\` às exclusões do Defender durante o scan |
| `-Force` | | Re-download de ferramentas mesmo que já existam em cache |

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

`CVE-2025-21333/34/35` · `CVE-2025-24983` · `CVE-2025-26633` · `CVE-2024-38080` · `CVE-2024-21338` · `CVE-2023-28252` · `CVE-2022-21999` · `CVE-2021-34527` (PrintNightmare) · `CVE-2021-36934` (HiveNightmare) · `CVE-2020-0796` (SMBGhost) · `CVE-2020-1472` (ZeroLogon) · `CVE-2019-0708` (BlueKeep) · `CVE-2017-0144` (EternalBlue)

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
| `--no-nvd` | `-n` | Salta consulta NVD API (modo offline) |
| `--no-browser` | | Não tenta abrir o relatório no browser |
| `--force` | | Re-download de ferramentas mesmo que já existam em cache |

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

`CVE-2024-1086` (nf_tables UAF, exploited) · `CVE-2024-0646` (mremap OOB) · `CVE-2023-4623` (sch_hfsc UAF, exploited) · `CVE-2023-32629` + `CVE-2023-2640` (overlayfs Ubuntu, exploited) · `CVE-2023-3389` (io_uring UAF) · `CVE-2022-0847` (Dirty Pipe, exploited) · `CVE-2022-0185` (fsconfig heap overflow) · `CVE-2021-4034` (PwnKit) · `CVE-2021-22555` (netfilter, exploited) · `CVE-2021-3156` (Baron Samedit sudo) · `CVE-2020-14386` (raw socket LPE) · `CVE-2016-5195` (Dirty COW)

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

## Ficheiros JSON produzidos

Todos os dados estruturados ficam disponíveis em JSON para integração com outras ferramentas:

| Ficheiro | Conteúdo | Campos |
|----------|----------|--------|
| `inventory.json` | Apps e packages detectados | `key`, `name`, `version`, `category`, `nvd_keyword`, `source` |
| `cve_results.json` | CVEs encontrados | `Source`, `App`, `Version`, `FixedIn`, `CveId`, `Severity`, `Cvss`, `Cwe`, `Description`, `References` |
| `app_updates.json` | Updates disponíveis | `Source`, `Name`, `Current`, `Available`, `UpdateCmd` |

---

## Dependências externas consultadas

| Serviço | URL | Propósito |
|---------|-----|-----------|
| NVD API | services.nvd.nist.gov | CVE/CWE lookup por keyword |
| MSRC API *(Windows only)* | api.msrc.microsoft.com | Patch Tuesdays e CVEs por build |
| kernel.org *(Linux only)* | kernel.org/releases.json | Versão mais recente do kernel |
| GitHub API | api.github.com | Determinar versões mais recentes de Trivy e Grype |
