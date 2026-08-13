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

Within the 430 controls tracked in `docs/coverage_matrix.csv`:

| | Count |
|---|---|
| Total controls tracked (sections 1,2,5,9,17,18,19) | 430 |
| **Implemented** (matches Linea_Base_Hardening_CIS_WindowsServer2025_Final.xlsx, the bank's baseline, exactly) | **333** |
| Excluded per bank baseline (`excluded_baseline_cliente` - code kept, toggle=false) | 55 |
| Manual / not automated | 5 |
| Not applicable (Domain Controller only) | 37 |

**2026-08-07 update:** the bank provided its own compliance-scan baseline
(`Linea_Base_Hardening_CIS_WindowsServer2025_Final.xlsx`). Every implemented
control was cross-checked against it 1:1 - the 333 implemented controls above
are exactly the 333 the bank's own reference scan applies. Controls that were
previously automated but are not in the bank's baseline were disabled by
default (not deleted) via their `win2025cis_rule_*` toggle in
`defaults/main.yml`, and marked `excluded_baseline_cliente` with a note in
`docs/coverage_matrix.csv`. `18.9.41.3` was also corrected: the original PDF
extraction had mis-mapped that ID to a Domain-Controller-only control; the
real 18.9.41.3 ("Configure SAM change password RPC methods policy") is now
implemented per the bank's data.

The 5 remaining "manual" controls are ones CIS itself, or the underlying
setting, cannot be safely auto-remediated (e.g. `1.2.3` Allow Administrator
account lockout, RPC/LAPS settings that are genuinely environment-specific).
Every one of these, plus all 37 DC-only controls, is listed by exact CIS ID
with a note in `docs/coverage_matrix.csv` explaining what the client should
verify/configure manually.

## Requirements

- Control node: `ansible-core >= 2.15`, Python `pywinrm` (`pip install
  pywinrm`).
- Collections: `ansible.windows`, `community.windows` (see
  `requirements.yml`):
  ```
  ansible-galaxy collection install -r requirements.yml
  ```
- Target hosts: Windows Server 2025, WinRM listener over **HTTPS (5986)**,
  reachable with a **dedicated local service account** in the `Administrators`
  group (or a domain account with local admin rights) - see "Cuenta de
  servicio obligatoria" below. **Never `Administrator` or `Guest`.**

## Cuenta de servicio obligatoria (no usar Administrator/Guest)

Este rol tiene una tarea `PREFLIGHT` al inicio de `tasks/main.yml` que
**falla inmediatamente** si `ansible_user` es `administrator` o `guest`
(sin importar mayusculas/minusculas). No es opcional: varios controles
(2.3.1.3/2.3.1.4) renombran esas mismas cuentas locales, y si Ansible se
autentica con la cuenta que se esta renombrando, la sesion WinRM queda
invalida a mitad de la corrida.

Antes de correr el playbook, crea una cuenta de servicio dedicada en el
host de destino:

```powershell
$Password = Read-Host -AsSecureString "Password para la cuenta de automatizacion"
New-LocalUser -Name "ansible" -Password $Password -FullName "Ansible Automation" -Description "Cuenta de servicio para Ansible/WinRM" -PasswordNeverExpires -AccountNeverExpires
Add-LocalGroupMember -Group "Administrators" -Member "ansible"
```

(El password debe cumplir la politica de complejidad ya aplicada por este
mismo playbook: 14+ caracteres, mayusculas, minusculas, numeros y simbolos.)

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
ansible_user=ansible
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

## Advertencias operativas

**Renombrado de cuenta Administrator/Guest (2.3.1.3 / 2.3.1.4).** Ya no
requiere ningun truco de orden: la tarea `PREFLIGHT` descrita arriba impide
que el rol corra si te conectas como `Administrator`/`Guest`, asi que
renombrar esas cuentas nunca afecta a la sesion de Ansible. Estas dos tareas
viven en su lugar natural dentro de `section2_local_policies_security_options.yml`.

**CIS 18.10.90.2.2 (WinRM Service `AllowAutoConfig` -> Disabled) SI debe ser
el ultimo control que se aplica, sin excepcion - y esto NO se soluciona con
una cuenta de servicio.** Vive en su propio archivo
(`roles/win2025_cis_hardening/tasks/final_winrm_autoconfig.yml`), incluido
como la ULTIMA tarea de todo el rol (despues incluso de la Seccion 19). Este
control reconfigura el propio servicio WinRM que sostiene el listener por el
que Ansible esta conectado - si ese listener depende de auto-configuracion
por GPO, aplicarlo puede tumbar la sesion activa en el momento, sin importar
que cuenta se use. Si ves `unreachable`/`ntlm: the specified credentials
were rejected by the server` justo en esta tarea (y solo en esta), es
esperado - todo lo demas ya se aplico antes. Recomendaciones:

- Corre este control por separado, al final de tu ventana de mantenimiento:
  `ansible-playbook -i inventory/hosts.ini site.yml --tags 18.10.90.2.2`
- Verifica que el listener WinRM del host no dependa de auto-config de GPO
  antes de aplicarlo en produccion.
- Si prefieres posponerlo, deshabilita el toggle
  (`win2025cis_rule_18_10_90_2_2: false` en `group_vars`/`host_vars`).

**Seccion 9 (Firewall): "Inbound connections: Block (default)" (9.1.2/9.2.2/9.3.2)
puede dejarte sin acceso remoto si no hay una regla explicita de admin en los
3 perfiles.** La regla incorporada de Windows para WinRM suele estar limitada
a los perfiles Domain/Private, no Public - si la interfaz de red del host
esta clasificada como Public (comun en VMs sin dominio), aplicar el bloqueo
por defecto corta WinRM/RDP de inmediato, sin login fallido ni evento en el
Visor de Eventos (el timeout ocurre a nivel de conexion TCP, no de
autenticacion). Por eso `tasks/section9_firewall.yml` tiene una tarea
"SAFETY NET" que crea una regla de firewall (`Ansible-Managed-Remote-Access`,
puertos 5985/5986/3389, los 3 perfiles) ANTES de aplicar el bloqueo por
defecto. Si aun asi pierdes acceso, la recuperacion es por consola
fuera de banda (hipervisor/nube), no por red - ver notas de troubleshooting
del equipo.

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
