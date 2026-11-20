# Ejecutable Zig — `triage_zig`

Triaje de crashes en Zig 0.17.1. Calcula la huella SHA256 (senal|RIP|stack) de
cada registro y agrupa por crash único.

```powershell
zig build
zig build test
.\zig-out\bin\triage_zig.exe fixtures\crashes.json
```

Resultado esperado sobre la fixture: `{"total":5,"unique":3}`.
