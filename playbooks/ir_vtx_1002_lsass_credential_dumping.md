# Playbook IR — VTX-1002: Suspicious LSASS Memory Access

- **Regra YAML / Wazuh SID:** `VTX-1002` / `100102`
- **Severidade:** `CRITICAL`
- **MITRE ATT&CK:** `Credential Access` — `T1003.001` (LSASS Memory)
- **Compliance:** PCI-DSS v4.0 (`Req. 8.3`, `Req. 10.2.1`, `Req. 12.10`) | NIST CSF 2.0 (`DE.CM-09`, `DE.AE-03`, `RS.MI-01`)
- **SLA de Triagem Inicial:** 15 minutos (P0 / Emergencial em ativos CDE)

## 1. Triagem e Validação (Triage)
1. Identificar `SourceImage`, `TargetImage`, `GrantedAccess`, `CallTrace` e o hash do executável originador.
2. Validar assinatura digital e caminho de `SourceImage`:
   - Caminhos em `C:\Users\Public\`, `%TEMP%`, `%APPDATA%` ou binários como `procdump*.exe`, `rundll32.exe` (`comsvcs.dll`) e `Taskmgr.exe` fora de sessão administrativa são fortes indicadores de *credential dumping*.
3. Verificar se `SourceImage` corresponde a agente EDR/antivírus legítimo com assinatura válida (falso positivo esperado caso não esteja na allowlist).

## 2. Contenção Imediata (Containment)
1. **Isolar imediatamente** o endpoint comprometido na camada de rede.
2. Assumir comprometimento de todas as credenciais com sessão ativa ou em cache no host:
   - Revogar tickets Kerberos e sessões ativas das contas logadas (especialmente contas privilegiadas/administrativas).
   - Se conta de domínio com privilégio elevado esteve presente, acionar procedimento de rotação dupla da conta `krbtgt` após erradicação.
3. Bloquear o hash do binário `SourceImage` globalmente no EDR/AppLocker.

## 3. Erradicação e Recuperação (Eradication & Recovery)
1. Buscar arquivos de dump gerados recentemente (`*.dmp`, `lsass*`, arquivos grandes recém-criados em diretórios graváveis) e verificar possível exfiltração via logs de rede (Sysmon `EventID 3`).
2. Caçar movimentação lateral (`T1021`, `T1550`) usando as contas presentes no host afetado nas últimas 24h–72h.
3. Habilitar ou validar endurecimento preventivo: **Credential Guard**, **RunAsPPL (Protected Process Light)** para o LSASS e restrição de contas de Domain Admin em estações comuns.
4. Reconstruir (*reimage*) o host se estiver em escopo `CDE` ou se houver sinais de persistência avançada.

## 4. Preservação de Evidências e Lições Aprendidas
- Preservar logs Sysmon (`EventID 1`, `7`, `10`), Security (`EventID 4624`, `4672`) e captura de memória se exigido pelo processo forense.
- Registrar impacto regulatório no comitê de incidentes caso o ativo pertença ao ambiente PCI-DSS.
