# Playbook IR — VTX-1004: SSH Authentication Failure Pattern

- **Regra YAML / Wazuh SID:** `VTX-1004` / `100104`
- **Severidade:** `MEDIUM` (eleva para `CRITICAL` se houver login bem-sucedido na sequência)
- **MITRE ATT&CK:** `Credential Access` — `T1110.001` (Password Guessing / Brute Force)
- **Compliance:** PCI-DSS v4.0 (`Req. 8.3.4`, `Req. 10.2.1.4`) | NIST CSF 2.0 (`DE.CM-01`, `DE.CM-03`, `RS.MI-01`)
- **SLA de Triagem Inicial:** 60 minutos (15 minutos se seguido de `Accepted password`)

## 1. Triagem e Validação (Triage)
1. Extrair IP de origem (`src_ip`), usuários testados, frequência e janela de tempo em `/var/log/auth.log` ou `journalctl -u sshd`.
2. **Verificação prioritária:** checar imediatamente se houve evento `Accepted password` ou `Accepted publickey` a partir do mesmo IP de origem (ou sub-rede) após a sequência de falhas.
3. Enriquecer o IP de origem em fontes internas/externas (reputação, ASN, histórico de scanners, VPN corporativa) para descartar erro operacional de administrador legítimo.

## 2. Contenção (Containment)
- **Atenção (Active Response Guardrail):** evitar bloqueio automático irrestrito em gateways críticos sem allowlist de IPs administrativos/bastion (risco de auto-DoS).
1. Se origem externa não autorizada e sem login bem-sucedido:
   - Bloquear `src_ip` no firewall de borda/security group ou via regra controlada de `nftables`/`ufw`.
2. Se houve login bem-sucedido após força bruta:
   - Encerrar sessões SSH da conta comprometida, bloquear a conta temporariamente e isolar o servidor.
   - Auditar `~/.ssh/authorized_keys`, `/etc/passwd`, cronjobs e histórico de comandos (`auditd`).

## 3. Erradicação e Recuperação (Eradication & Recovery)
1. Validar hardening do `sshd_config`:
   - `PermitRootLogin no`
   - `PasswordAuthentication no` (priorizar autenticação por chave + MFA via bastion)
   - Restrição de acesso à porta SSH por IP de origem (VPN/Jump Host) e política de bloqueio de conta alinhada ao PCI-DSS Req. 8.3.4.
2. Em caso de acesso confirmado, rotacionar chaves SSH, segredos de aplicação e credenciais acessíveis a partir do servidor.

## 4. Preservação de Evidências e Lições Aprendidas
- Preservar recorte íntegro de `/var/log/auth.log` / `auditd` com timestamps UTC e hash SHA-256.
- Revisar exposição de porta 22 na superfície externa de ataque.
