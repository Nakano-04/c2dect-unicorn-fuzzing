# Plan 6 — Fuzzing/emulación con Unicorn

**Solo información y resultados.** Sin código fuente.

## Hipótesis

El backend de emulación ya produce crashes reales y snapshots reales; añadiendo
deduplicación, minimización y métricas de cobertura se convierte en un resultado
publicable y comparable, no solo en una capacidad del catálogo.

## Estado medido

- Las mutaciones se ejecutan en **Unicorn 2.x**: crashes reales de emulación.
- Snapshots con backend real (VBoxManage / virsh / QEMU); lo que no es real se
  declara `Outcome.simulated`, nunca se presenta como real.
- Finder de gadgets real en Rust (`capstone-rs + rayon`) con validación `endbr64`
  para CET.

## Métricas del experimento

exec/s, crashes únicos tras deduplicación, cobertura de aristas, tasa de
reproducción de crashes y precisión del finder de gadgets frente a un baseline.

## Precisión

Los crashes de emulación se reportan como **crash de emulación**, nunca como RCE
validado, en coherencia con el contrato `truth.Outcome`.

## Ámbito

Laboratorio aislado, alcance declarado y RoE firmada. Uso exclusivamente
autorizado. Ver `PLANES_INVESTIGACION_4-7.md` para el diseño completo.
