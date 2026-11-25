# Mapeamento de Compliance — vtx-detection-lab

Este documento rastreia as regras de detecção, o motor de validação e os playbooks de resposta a incidentes aos requisitos de **PCI-DSS v4.0**, **NIST CSF 2.0** e **CIS Controls v8**.

## 1. Matriz por Regra de Detecção

| Rule ID | Wazuh SID | Técnica MITRE | PCI-DSS v4.0 | NIST CSF 2.0 | CIS Controls v8 | Playbook IR |
| :--- | :---: | :---: | :--- | :--- | :--- | :--- |
| `VTX-1001` | `100101` | `T1059.001` (PowerShell) | **Req. 10.2.1** (Logs de auditoria)<br>**Req. 11.5** (Detecção de intrusão) | `DE.CM-09`, `DE.AE-02` | Control 8.2 / 8.5 (Audit Log Management) | [`ir_vtx_1001_powershell_encoded.md`](../playbooks/ir_vtx_1001_powershell_encoded.md) |
| `VTX-1002` | `100102` | `T1003.001` (LSASS Memory) | **Req. 8.3** (Proteção de credenciais)<br>**Req. 10.2.1** (Monitoramento de acessos) | `DE.CM-09`, `DE.AE-03` | Control 8.5 / 13.6 (Endpoint & Security Monitoring) | [`ir_vtx_1002_lsass_credential_dumping.md`](../playbooks/ir_vtx_1002_lsass_credential_dumping.md) |
| `VTX-1003` | `100103` | `T1053.005` (Scheduled Task) | **Req. 10.2.1** (Ações administrativas)<br>**Req. 10.2.2** (Logs de privilégio) | `DE.CM-09`, `RS.MI-02` | Control 8.5 / 17.4 (Incident Response Process) | [`ir_vtx_1003_schtasks_persistence.md`](../playbooks/ir_vtx_1003_schtasks_persistence.md) |
| `VTX-1004` | `100104` | `T1110.001` (SSH Brute Force) | **Req. 8.3.4** (Tentativas inválidas de acesso)<br>**Req. 10.2.1.4** (Falhas de autenticação) | `DE.CM-01`, `DE.CM-03` | Control 8.5 / 13.1 (Centralized Event Alerting) | [`ir_vtx_1004_ssh_bruteforce.md`](../playbooks/ir_vtx_1004_ssh_bruteforce.md) |

## 2. Matriz por Capacidade do Pipeline

| Capacidade | PCI-DSS v4.0 | NIST CSF 2.0 | CIS Controls v8 | Evidência Versionada |
| :--- | :--- | :--- | :--- | :--- |
| Regras versionadas em Git (`rules/`) | **Req. 6.5 / 10.4** (Controle de mudanças em regras de monitoramento) | `GV.OV-01`, `PR.PS-01` | Control 4.1 / 8.11 | `rules/sigma_lite/*.yaml`, `rules/wazuh/local_rules.xml` |
| Testes automatizados de detecção (`replay --strict`) | **Req. 11.5.1 / 10.4.1** (Revisão e eficácia dos mecanismos de detecção) | `DE.AE-07`, `ID.IM-02` | Control 17.8 (Testes de detecção/resposta) | `docs/evidence/atomic_replay_report.md` |
| Playbooks estruturados de IR (`playbooks/`) | **Req. 12.10.1 / 12.10.5** (Plano de resposta a incidentes e contenção) | `RS.MA-01`, `RS.AN-03`, `RS.MI-01` | Control 17.1 / 17.4 / 17.9 | `playbooks/ir_vtx_*.md` |

## 3. Política de Severidade e SLAs de Resposta (SOC)

| Severidade | Tempo Máximo de Triagem (MTTA) | Critério Operacional |
| :---: | :---: | :--- |
| **CRITICAL** | **15 minutos** | Comprometimento provável de credenciais ou ativo em escopo `CDE` (ex.: `VTX-1002`). |
| **HIGH** | **30 minutos** | Execução suspeita ou persistência em endpoint/servidor (ex.: `VTX-1001`, `VTX-1003`). |
| **MEDIUM** | **60 minutos** | Reconhecimento ou tentativas de força bruta sem acesso confirmado (ex.: `VTX-1004`). |
| **LOW** | **24 horas** | Anomalias informativas para correlação e *threat hunting*. |

## 4. Limite de Escopo (Disclaimer)

Este mapeamento apoia a engenharia de detecção e a resposta a incidentes (Blue Team / SOC) e **não** substitui auditorias formais (QSA/ASV) nem garante conformidade regulatória isoladamente.
