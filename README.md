# win2025-cis-hardening

Ansible role + playbook that applies the **CIS Microsoft Windows Server 2025
Benchmark v2.1.0** (Level 1 + Level 2, **Member Server** profile) to Windows
Server 2025 hosts over WinRM.

## Purpose

Automates the CIS-recommended Account/Password/Lockout Policy, Local
Policies & Security Options, Windows Defender Firewall profile settings,
Advanced Audit Policy, and Administrative Templates (Computer + User)
controls for a standalone/member server (not a Domain Controller).

## Scope / what is NOT covered

This role was built from a prior extraction of the CIS PDF
(`outputs/win2025_controls_extracted.json`) that covers **sections 1, 2, 5, 9,
17, 18 and 19 only** (428 controls). The full CIS benchmark also has sections
3 (Event Log), 4 (Restricted Groups), 6 (Registry ACLs), 7 (File System
ACLs), 8 (Wired Network), 10-16 (Network List Manager, Wireless, Public Key,
Software Restriction/AppLocker, NAP, Application Control, IP Security) that
were **never extracted and are out of scope for this iteration** - they are
not present in `docs/coverage_matrix.csv` either. Treat this role as covering
the highest-priority sections (account policy, local security options,
firewall, audit policy, administrative templates), not the entire benchmark.
Extending it to the remaining sections is future work.

Within the 428 controls that were extracted:

| | Count |
|---|---|
| Total controls extracted (sections 1,2,5,9,17,18,19) | 428 |
| Applicable to Member Server (Level 1 + 2) | 390 |
| **Implemented** (automated by this role) | **380** |
| Manual / not automated (see below) | 10 |
| Not applicable (Domain Controller only) | 38 |

Implemented, by level: 302 Level 1 + 78 Level 2 = 380.
Implemented, by section: 1→10, 2→98, 5→1, 9→23, 17→27, 18→210, 19→11.

The 10 "manual" controls are:
- 2 controls CIS itself rates **"Manual"** (audit requires human verification):
  `1.2.3` (Allow Administrator account lockout) and `2.3.11.5` (Network
  security: Force logoff when logon hours expire).
- 8 **"Automated"** controls whose CIS-recommended value is genuinely
  one-of-several / environment-specific (e.g. `0 or 2`, `3, 5 or 11`,
  RPC authentication protocol, LAPS backup directory/complexity/post-auth
  action) - automating these with a guessed value could silently apply the
  wrong policy, so they are intentionally left for manual configuration.

Every one of these 10, plus all 38 DC-only controls, is listed by exact CIS
ID with a note in `docs/coverage_matrix.csv` explaining what the client
should verify/configure manually.

## Requirements

- Control node: `ansible-core >= 2.15`, Python `pywinrm` (`pip install
  pywinrm`).
- Collections: `ansible.windows`, `community.windows` (see
  `requirements.yml`):
  ```
  ansible-galaxy collection install -r requirements.yml
  ```
- Target hosts: Windows Server 2025, WinRM listener over **HTTPS (5986)**,
  reachable with an account in the local `Administrators` group (or a domain
  account with local admin rights).

## Inventory / WinRM configuration

Copy `inventory/hosts.example.ini` to `inventory/hosts.ini` and adjust:

```ini
[windows]
winsrv01.example.local  ansible_host=10.0.0.11

[windows:vars]
ansible_connection=winrm
ansible_port=5986
ansible_winrm_transport=credssp   ; or ntlm
ansible_winrm_server_cert_validation=ignore  ; lab only - use "validate" with a real cert in production
ansible_user=Administrator
ansible_password="{{ vault_windows_admin_password }}"
```

Do not commit real hostnames/credentials - use `ansible-vault` (or an
external secrets manager) for `ansible_password`.

## How to run

```bash
# 1. Install collections
ansible-galaxy collection install -r requirements.yml

# 2. Dry-run first (see "Check mode" caveats below)
ansible-playbook -i inventory/hosts.ini site.yml --check --diff

# 3. Apply
ansible-playbook -i inventory/hosts.ini site.yml
```

### Apply only Level 1, or only a subsection

```bash
# Level 1 only for this run (overrides group_vars/windows.yml default of 2)
ansible-playbook -i inventory/hosts.ini site.yml -e win2025cis_level=1

# Only the firewall and audit policy sections
ansible-playbook -i inventory/hosts.ini site.yml --tags section9,section17

# Everything except Administrative Templates (large blast radius)
ansible-playbook -i inventory/hosts.ini site.yml --skip-tags section18,section19

# A single control (note: controls implemented via a loop share one Ansible
# task, so tagging control 18.1.1.1 runs the WHOLE loop that task belongs to,
# not just that one item - use the per-control exception variable below if
# you need to skip/keep exactly one control)
ansible-playbook -i inventory/hosts.ini site.yml --tags 18.1.1.1
```

### Exclude individual controls

Every implemented control has a matching
`win2025cis_rule_<id_with_underscores>: true` boolean in
`roles/win2025_cis_hardening/defaults/main.yml`. Override any of them to
`false` in `group_vars/windows.yml`, `host_vars/<host>.yml`, or with `-e` to
skip exactly that control while still applying everything else at the
chosen level:

```bash
ansible-playbook -i inventory/hosts.ini site.yml -e win2025cis_rule_2_3_1_3=false
```

See the commented examples in `group_vars/windows.yml`.

### Check mode

`--check` works for the `ansible.windows.win_regedit`,
`ansible.windows.win_user_right`, `ansible.windows.win_service` and
`ansible.windows.win_audit_policy_system` tasks. `community.windows.win_security_policy`
(secedit-based Account/Local Policies) has **limited check-mode support
upstream** - always validate secedit-driven changes (sections 1 and part of
2) with `--diff` and a real dry run in a non-production environment first,
not just `--check`.

## Reboot / gpupdate

Administrative Templates (sections 18/19) and several Security Options
(section 2) are Group Policy Client Side Extension settings. This role
writes the underlying registry values directly (bypassing gpedit/GPO), and
notifies a `gpupdate /force` handler after changing them so most policies
that support a live refresh apply immediately. However:

- A **handful of settings only take effect after a reboot** (e.g. UAC/LSA
  protection changes, LSASS protected-process, some Kerberos/Netlogon
  settings).
- Section 19 (Administrative Templates - User) is written to
  `HKU:\.DEFAULT` (the Default user profile), so it only affects **new**
  interactive logons, not already-loaded profiles - see the header comment
  in `roles/win2025_cis_hardening/vars/section19_administrative_templates_user.yml`.
- In a real Active Directory environment, prefer delivering section 19 (and
  ideally the whole benchmark) via a proper GPO instead of/in addition to
  this role, since a competing GPO will silently overwrite these registry
  values on its next refresh cycle.

Plan a maintenance window and a reboot after the first full run.

## Test in non-production first

This role changes authentication (LAN Manager / NTLM / Kerberos encryption
policy), remote access (RDP encryption/NLA, WinRM-adjacent LSA settings) and
firewall defaults. **Run it against a non-production Windows Server 2025
Member Server first**, verify RDP/WinRM connectivity and application
functionality, and only then roll out to production. A misconfigured
`ansible_winrm_transport`/certificate combined with the LAN Manager / NTLM
hardening in section 2 can lock out remote management if tested carelessly.

## Repository layout

```
site.yml                                    # entry point playbook
ansible.cfg, requirements.yml
inventory/hosts.example.ini
group_vars/windows.yml                      # win2025cis_level + exception examples
roles/win2025_cis_hardening/
  defaults/main.yml                         # win2025cis_level + one toggle per implemented control
  vars/section*.yml                         # control data (id, level, registry/secedit/right details)
  tasks/main.yml, tasks/section*.yml        # one include per CIS section, loops over vars/*.yml
  handlers/main.yml                         # gpupdate /force
  meta/main.yml
docs/coverage_matrix.csv                    # every one of the 428 extracted controls and its disposition
```

## Acta de Entrega-Recepción

Documento completo (PDF): [docs/Acta_Entrega_Recepcion_Playbook02_Hardening_Windows2025.pdf](docs/Acta_Entrega_Recepcion_Playbook02_Hardening_Windows2025.pdf)

| Campo | Detalle |
|---|---|
| Proyecto | Desarrollo de 18 Playbooks de automatización con Ansible/AWX - Banco Solidario |
| Playbook entregado | Playbook 2 de 18: Hardening CIS Windows Server 2025 (Benchmark v2.1.0, Nivel 1 + 2, Member Server) |
| Commit / etiqueta entregada | Código Completado |
| Fecha de elaboración del documento | 8 de octubre de 2026 |

| ENTREGA - GMS | RECIBE - BANCO SOLIDARIO |
|---|---|
| **Juan Pablo Castillo** | **Jeremy Moreno** |
| Líder de Proyecto | Seguridad de la Información |
| Fecha de elaboración del documento: 8 de octubre de 2026 | Fecha de elaboración del documento: 8 de octubre de 2026 |
| Firma: ______________________ | Firma: ______________________ |
