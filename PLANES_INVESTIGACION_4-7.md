# Planes de investigación 4–7 - C2-DECT

> Fecha: 2026-11-19
> Alcance: **laboratorio aislado, alcance declarado y RoE firmada**. Ninguna línea
> implica uso contra activos de terceros sin autorización. Todo artefacto se
> publica con rutas/hashes sanitizados (gobernanza G8) y ningún hallazgo se
> cierra automáticamente (G3): cierre solo tras retest con evidencia.

## Orden de ejecución recomendado

| Orden | Línea | ¿Por qué |
|---|---|---|
| 1 | **5 - Hardening del propio C2** | Solo análisis estático + CI. Cero dependencias de laboratorio. |
| 2 | **6 - Fuzzing/emulación Unicorn** | El código real ya existe; solo falta medirlo y publicarlo. |
| 3 | **7 - Dataset de telemetría** | Requiere ejecutar la campaña en lab para generar datos reales. |
| 4 | **4 - Validación de SOC** | Depende del dataset (7): necesita telemetría etiquetada antes/después. |

---

## Plan 5 - Harness repetible de seguridad del C2

**Hipótesis.** Los hallazgos de `AUDITORIA_OFENSIVA_c2-dect_2026.md` son
reproducibles como gates automáticos de CI, de modo que una regresión de
seguridad se detecte en el pipeline y no en una auditoría manual anual.

**Estado actual.** Existen `AUDITORIA_OFENSIVA_c2-dect_2026.md`,
`AUDIT_REPORT.md`, `THREAT_MODEL.md` y workflows en `.github/workflows/`
(`ci.yml`, `ci-go-modules.yml`, `ci-native.yml`, `ci-kernel-driver.yml`,
`fuzz.yml`, `phase0-baseline.yml`, `ci-interactive.yml`). La auditoría señala
tres brechas concretas: tests cross-tenant solo en `ci-interactive.yml`
(manual/acotado), 0 % de CI para C/C++, Go de raíz y Android en `ci.yml`, y
sin SBOM ni `govulncheck` automático.

**Diseño.**
1. Convertir las 10 recomendaciones de la auditoría en checks con ID estable
   (p. ej. `HARD-01` = sin fallback `c2-dect-dev-secret-change-me`).
2. Añadir gates: `govulncheck`, `gitleaks`/`trufflehog` (historial de Git),
   SBOM CycloneDX por release, `go test ./...`, `pytest` y los tests
   cross-tenant migrados a un job no interactivo.
3. Arranque fail-closed: los escape hatches (`C2_ALLOW_HTTP`,
   `C2_ALLOW_SELF_SIGNED`, `C2_ALLOW_NO_MTLS*`, `C2_SCRIPT_ALLOW_UNSIGNED`)
   deben emitir un aviso visible, no una variable silenciosa.
4. Unificar bind por defecto a loopback
   (`cmd/server/main.go:20` tiene `0.0.0.0:443` frente a
   `server/cmd/main.go:30` con `127.0.0.1:8443`).

**Métricas.** Porcentaje de recomendaciones con gate automático (objetivo
10/10); número de hallazgos reabiertos por regresión; tiempo desde el commit
hasta la alerta; 0 secretos/claves privadas en el historial.

**Entregable.** `tools/hardening/` (harness ejecutable) + metodología publicable
("Security Hardening Harness for Adversary-Emulation C2").

**Riesgo.** Falsos positivos de secret scanning bloqueando builds → mitigar con
allowlist documentada y modo `report-only` previo.

---

## Plan 6 - Fuzzing/emulación con Unicorn (medir y publicar)

**Hipótesis.** El backend de emulación ya produce crashes reales y snapshots
reales; al añadir deduplicación, minimización y métricas de cobertura se convierte
en un resultado publicable y comparable, no solo en una capacidad del catálogo.

**Estado actual.** `api/research/auto.py:102-123` ejecuta mutaciones en Unicorn
(crashes reales de emulación, `fuzzing_backend: unicorn`).
`api/fuzzing/snapshot.py` expone snapshots con backend real
(VBoxManage/virsh/QEMU) y declara `Outcome.simulated` cuando no lo hay.
`api/fuzzing/campaign.py` orquesta K8s + snapshots.
`api/weapon_factory/gadgets_rust.py` usa el finder real `weapon-rs/`
(capstone-rs + rayon), con validación `endbr64` para CET.

**Diseño.**
1. **Triaje de crashes:** hash de la señal + registro/RIP + stack, deduplicar y
   minimizar input (delta-debugging) para cada crash.
2. **Cobertura:** instrumentar `UC_HOOK_CODE` para contar aristas ejecutadas y
   reportar cobertura acumulada por campaña (no solo "crashes encontrados").
3. **Comparación A/B:** misma semilla y presupuesto de tiempo en (a) Unicorn y
   (b) VM snapshot; medir ejecuciones/segundo, crashes únicos y reproducibilidad.
4. **Calidad de gadgets:** comparar el finder Rust contra un baseline Python
   (precisión de gadgets, falsos positivos, cobertura CET/JOP).

**Métricas.** exec/s, crashes únicos tras deduplicación, cobertura de aristas,
tasa de reproducción de crashes, precisión del finder de gadgets.

**Entregable.** Herramienta de triaje + benchmark reproducible + paper/tool.

**Riesgo.** Los crashes de emulación pueden no ser explotables → reportarlos
siempre como "crash de emulación", nunca como RCE validado (coherente con
`truth.Outcome`).

---

## Plan 7 - Dataset de telemetría etiquetado del laboratorio

**Hipótesis.** Se puede publicar un dataset de telemetría de un laboratorio
aislado, etiquetado por técnica y con veredictos de detección, lo bastante
sanitizado para que terceros reproduzcan mediciones sin exponer infraestructura.

**Estado actual (brecha).** `reports/campaign-apt/detection_coverage_matrix.md`
(2026-11-19) muestra **44 TTPs sin ejecutar**, todos los `Hits = 0` y veredictos
`sin-registro / sin-probar`. Los hashes de origen están presentes, pero
`records.json` figura como `no-disponible`. Todavía no hay datos reales que
publicar: este plan depende de ejecutar la campaña bajo RoE firmada.

**Diseño.**
1. Ejecutar campaña en VM con snapshot (`api/exploitlab/lab.py`,
   `tools/fuzzing/snapshot/`); cada técnica debe dejar un `DetectionRecord` con
   `RuleID` y `Source` (G1), y un `truth.Outcome` ejecutado.
2. Fuentes de telemetría: Sysmon/ETW-TI (adaptadas con
   `CyberLens/knowledge/sensor_adapter.py` al contrato `p3.telemetry.v1`),
   pcap del canal C2, `activity_log` y reglas Sigma.
3. Etiquetado por técnica (ATT&CK ID), host, sesión, marca de tiempo y veredicto
   `landed / caught / blocked / needs_tuning` (`CyberLens/core/purple_matrix.py`).
4. Sanitización G8: rutas y hashes sanitizados, sin secretos ni identificadores
   reales; corpus benigno (`p3-benign-corpus.json`) como controles.
5. Versionado con esquema, reparto train/val/test y *datasheet* (motivación,
   composición, captura, usos previstos y límites).

**Métricas.** técnicas ejecutadas/planeadas (objetivo 44/44), eventos por
técnica, fracción de registros con `RuleID`, tasa de falsos positivos sobre el
corpus benigno, completitud de etiquetas.

**Entregable.** `c2dect-lab-telemetry-v1`: dataset abierto + esquema + datasheet
+ resultados baseline de detectores de referencia.

**Riesgo.** Si una técnica no se ejecuta, NO rellenar con telemetría sintética
como si fuera real: se marca `no-ejecutada` y se reporta como brecha (G3).

---

## Plan 4 - Validación de SOC con grupo de control

**Hipótesis.** El uso estructurado de C2-DECT reduce el tiempo de detección y
contención de un SOC frente a un grupo que no lo usa, con control de falsos
positivos.

**Dependencia.** Requiere el dataset del plan 7 y un SOC con telemetría
equivalente en ambos brazos.

**Diseño.**
1. Diseño pre/post con grupo de control: brazo A usa C2-DECT para validar
   detecciones; brazo B mantiene su proceso habitual. Mismo periodo, mismo
   conjunto de técnicas (extraídas del dataset v1).
2. **Métrica de tiempo correcta:** TTD = desde la marca de ejecución de la
   técnica hasta la primera alerta correlacionada; TTC = hasta la contención.
   No usar `session_dwell_seconds` como MTTD: `TECH_DEBT.md:212` documenta que
   ese error ya fue corregido.
3. Calidad: recall por técnica, precisión, falsos positivos por hora de
   telemetría benigna.
4. Estadística: comparación pareada, intervalos de confianza bootstrap,
   pre-registro de hipótesis y métricas antes de ejecutar.

**Métricas.** ΔTTD, ΔTTC, recall, precisión, FP/h, tamaño del efecto con IC.

**Entregable.** Estudio de caso + informe para adopción en el sector privado.

**Riesgo.** Efecto de aprendizaje y sesgo de selección → aleatorizar el orden de
técnicas y documentar la composición de ambos brazos.

---

## Progreso

### Plan 5 - primer corte entregado (2026-11-19)

- `[NUEVO]` `tools/hardening/check_hardening.py`: gates HARD-01..04, stdlib
  puro, salida humana o `--json`, `exit 1` si cualquier gate falla.
- `[NUEVO]` job `hardening` en `.github/workflows/ci.yml`, bloqueante,
  baseline 0 (mismo criterio que el gate de clippy de Rust).
- `[FIX]` HARD-01: eliminado el fallback hardcodeado en `cmd/server/main.go` y
  `cmd/agent/main.go`. Ambos binarios TCP legado ahora **fallan cerrado** si no
  existe `C2_FRAME_SECRET`, con mensaje explicito en stderr.
- `[FIX]` HARD-03: `cmd/server/main.go` enlaza por defecto a `127.0.0.1:443`
  (antes `0.0.0.0:443`). Coincide con el `defaultServer` del agente legado.
- `[DOC]` `C2_FRAME_SECRET` anadido a `.env.example` y `.env.lab.example`. Los
  laboratorios que usen el canal TCP legado deben copiar la plantilla a `.env`
  (start_stack.ps1 ya inyecta las variables de `.env` al entorno).

Verificacion local: 4/4 gates PASS · `go vet ./cmd/server ./cmd/agent` limpio ·
YAML del workflow valido (7 jobs, incluido `hardening`).

**Queda pendiente en Plan 5:** HARD-05 (aviso visible de escape hatches en
arranque), migrar los tests cross-tenant de `ci-interactive.yml` a un job no
interactivo, y SBOM + `govulncheck`.

---

## Entregables y dependencias (resumen)

| Línea | Empieza | Entregable | Depende de |
|---|---|---|---|
| 5 | Ya | Harness `tools/hardening/` + metodología | Nada |
| 6 | Ya | Triaje Unicorn + benchmark + paper | Nada |
| 7 | Tras RoE | Dataset `c2dect-lab-telemetry-v1` | Ejecución real en lab |
| 4 | Último | Estudio SOC controlado | Dataset (7) |
