# Playbook IR — VTX-1003: Suspicious Scheduled Task Creation

- **Regra YAML / Wazuh SID:** `VTX-1003` / `100103`
- **Severidade:** `HIGH`
- **MITRE ATT&CK:** `Persistence` — `T1053.005` (Scheduled Task)
- **Compliance:** PCI-DSS v4.0 (`Req. 10.2.1`, `Req. 10.2.2`) | NIST CSF 2.0 (`DE.CM-09`, `RS.MI-02`)
- **SLA de Triagem Inicial:** 30 minutos

## 1. Triagem e Validação (Triage)
1. Analisar `CommandLine` completo da criação da tarefa: nome (`/tn`), ação/executável (`/tr`), gatilho (`/sc`) e contexto de privilégio (`/ru SYSTEM`).
2. Correlacionar com eventos do Windows Security (`EventID 4698` — tarefa criada) e TaskScheduler Operational (`EventID 106`) para inspecionar o XML completo da tarefa.
3. Sinais de alta suspeita:
   - Alvo `/tr` apontando para `powershell.exe`, `cmd.exe`, `wscript.exe`, `mshta.exe` ou binários em `C:\ProgramData`, `C:\Users\Public`, `%TEMP%`.
   - Execução como `NT AUTHORITY\SYSTEM` criada fora de janela de mudança (GMUD/change ticket).

## 2. Contenção (Containment)
1. Desabilitar a tarefa agendada maliciosa antes de excluí-la (preservando o XML para perícia):
   - `schtasks /change /tn "<NOME_TAREFA>" /disable`
2. Encerrar qualquer instância em execução do binário referenciado em `/tr`.
3. Se houver indício de movimentação lateral remota (`/s <host>`), isolar também o host de origem e revogar a credencial usada.

## 3. Erradicação e Recuperação (Eradication & Recovery)
1. Exportar a definição XML da tarefa (`C:\Windows\System32\Tasks\...`) com hash SHA-256 e, em seguida, removê-la (`schtasks /delete /tn "<NOME_TAREFA>" /f`).
2. Remover o payload associado e verificar mecanismos paralelos de persistência (Run Keys, Services, Startup folder).
3. Revisar demais hosts do mesmo segmento em busca de tarefas com mesmo nome (`/tn`) ou caminho (`/tr`).

## 4. Preservação de Evidências e Lições Aprendidas
- Documentar o ticket de mudança quando for tarefa legítima de backup/deploy para reduzir ruído recorrente.
- Refinar correlação no SIEM cruzando `EventID 1` (`schtasks.exe`) com eventos de gravação de arquivo (`EventID 11`).
