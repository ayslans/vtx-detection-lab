# Playbook IR — VTX-1001: Encoded PowerShell Execution

- **Regra YAML / Wazuh SID:** `VTX-1001` / `100101`
- **Severidade:** `HIGH`
- **MITRE ATT&CK:** `Execution` — `T1059.001` (PowerShell)
- **Compliance:** PCI-DSS v4.0 (`Req. 10.2.1`, `Req. 11.5`) | NIST CSF 2.0 (`DE.CM-09`, `DE.AE-02`, `RS.AN-03`)
- **SLA de Triagem Inicial:** 30 minutos

## 1. Triagem e Validação (Triage)
1. Coletar do alerta: `host`, `User`, `ParentImage`, `Image`, `CommandLine` e `timestamp`.
2. Decodificar o payload Base64 em ambiente isolado (nunca executar o comando no host de análise):
   - No PowerShell (UTF-16LE padrão do `-EncodedCommand`): `[System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String("<BASE64>"))`
3. Verificar a cadeia de processos (*process tree*): invocações originadas de `winword.exe`, `excel.exe`, `cmd.exe`, `wscript.exe` ou `mshta.exe` elevam criticidade para incidente confirmado.
4. Checar falsos positivos conhecidos: agentes de automação assinados (SCCM, Ansible, inventário corporativo) executados sob conta de serviço autorizada.

## 2. Contenção (Containment)
- Se confirmado malicioso ou em ativo `CDE`:
  1. Isolar o endpoint da rede via EDR/firewall mantendo canal de gerenciamento forense.
  2. Encerrar o processo PowerShell suspeito e processos filhos derivados.
  3. Revogar sessões/tokens ativos da conta `User` envolvida e forçar troca de credenciais.
  4. Bloquear domínios/IPs de C2 extraídos do script decodificado no proxy/firewall (*defang* antes de documentar, ex.: `hxxp://203[.]0[.]113[.]45`).

## 3. Erradicação e Recuperação (Eradication & Recovery)
1. Inspecionar persistência criada pelo script (Scheduled Tasks, Run Keys, WMI Subscriptions, serviços).
2. Remover artefatos baixados em `C:\Users\Public`, `%TEMP%` e `C:\ProgramData`.
3. Validar integridade do host (varredura completa + revisão de logs de Script Block Logging `EventID 4104`).
4. Reintegrar o host à rede somente após aprovação do líder de IR.

## 4. Preservação de Evidências e Lições Aprendidas
- Exportar logs Sysmon (`EventID 1`, `3`, `11`) e PowerShell Operational (`EventID 4103`, `4104`) com hash SHA-256.
- Atualizar lista de exceções documentadas se for automação legítima, evitando silenciar a regra globalmente.
