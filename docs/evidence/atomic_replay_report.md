# Relatório de Validação Detection-as-Code — vtx-detection-lab

- **Gerado em:** 2026-11-25 16:44 UTC
- **Regras avaliadas:** 4
- **Eventos de telemetria:** 10
- **Status do Quality Gate:** `PASS (0 FP / 0 FN)`

## 1. Resumo Executivo e Métricas de Precisão

| Métrica | Valor |
| :--- | :---: |
| **Total de Eventos Reproduzidos** | 10 |
| **Alertas Disparados** | 6 |
| **True Positives (TP)** | 6 |
| **True Negatives (TN)** | 4 |
| **False Positives (FP)** | 0 |
| **False Negatives (FN)** | 0 |
| **Precision** | **100.0%** |
| **Recall** | **100.0%** |

## 2. Matriz de Cobertura MITRE ATT&CK

| Rule ID | Título | Severidade | Tática | Técnica MITRE | Fonte | Wazuh SID | Compliance |
| :--- | :--- | :---: | :--- | :---: | :---: | :---: | :--- |
| `VTX-1002` | Suspicious LSASS Memory Access | **CRITICAL** | Credential Access | `T1003.001` | `sysmon` | `100102` | Req. 8.3, Req. 10.2.1, DE.CM-09, DE.AE-03 |
| `VTX-1001` | Encoded PowerShell Execution | **HIGH** | Execution | `T1059.001` | `sysmon` | `100101` | Req. 10.2.1, Req. 11.5, DE.CM-09, DE.AE-02 |
| `VTX-1003` | Suspicious Scheduled Task Creation | **HIGH** | Persistence | `T1053.005` | `sysmon` | `100103` | Req. 10.2.1, Req. 10.2.2, DE.CM-09 |
| `VTX-1004` | SSH Authentication Failure Pattern | **MEDIUM** | Credential Access | `T1110.001` | `linux_auth` | `100104` | Req. 8.3.4, Req. 10.2.1.4, DE.CM-01, DE.CM-03 |

## 3. Alertas Disparados no Replay

| Timestamp | Event ID | Host | Rule ID | Severidade | Técnica MITRE | Evidência (Matched Fields) |
| :--- | :--- | :--- | :---: | :---: | :---: | :--- |
| `2026-11-25T10:08:20Z` | `EVT-003` | `CDE-APP-WIN-01` | `VTX-1002` | **CRITICAL** | `T1003.001` | EventID=10; TargetImage=C:\Windows\System32\lsass.exe; GrantedAccess=0x1010 |
| `2026-11-25T10:01:12Z` | `EVT-001` | `FIN-WKSTN-01` | `VTX-1001` | **HIGH** | `T1059.001` | EventID=1; Image=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe; CommandLine=powershell.exe -NoP... |
| `2026-11-25T10:03:45Z` | `EVT-002` | `FIN-WKSTN-02` | `VTX-1001` | **HIGH** | `T1059.001` | EventID=1; Image=C:\Program Files\PowerShell\7\pwsh.exe; CommandLine=pwsh.exe -c "[Text.Encoding]::UTF8.Get... |
| `2026-11-25T10:12:04Z` | `EVT-004` | `CDE-APP-WIN-01` | `VTX-1003` | **HIGH** | `T1053.005` | EventID=1; Image=C:\Windows\System32\schtasks.exe; CommandLine=schtasks.exe /create /tn "SyncAgentUpdate" /... |
| `2026-11-25T10:15:31Z` | `EVT-005` | `PAY-LNX-GW-01` | `VTX-1004` | **MEDIUM** | `T1110.001` | service=sshd; message=Failed password for invalid user admin from 203.0.113.45 port 51234 ssh2 |
| `2026-11-25T10:15:39Z` | `EVT-006` | `PAY-LNX-GW-01` | `VTX-1004` | **MEDIUM** | `T1110.001` | service=sshd; message=Failed password for deploy from 198.51.100.22 port 44120 ssh2 |

## 4. Auditoria de Desvios (False Positives & False Negatives)

Nenhum falso positivo ou falso negativo registrado. Todas as regras passaram nos cenários de ataque simulado e controle benigno.

## 5. Rastreabilidade de Governança

- **PCI-DSS v4.0:** Req. 8.3 (Autenticação e controle de credenciais), Req. 10.2 (Registro e monitoramento de logs), Req. 11.5 (Detecção de intrusão e alterações).
- **NIST CSF 2.0:** `DE.CM-01`, `DE.CM-03`, `DE.CM-09` (Monitoramento Contínuo) e `DE.AE-02`, `DE.AE-03` (Análise de Eventos Adversos).
- **CIS Controls v8:** Control 8 (Audit Log Management) e Control 13 (Network Monitoring and Defense).
