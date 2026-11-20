# Reproducción completa del estudio

Esta guía describe la reproducción íntegra en Windows y la verificación de los resultados guardados. Las rutas son relativas a la raíz del repositorio. Los datos pesados (columnas del corpus completo, muestras de validación y binarios de BinRankBench) se distribuyen en el paquete reproducible, no en Git.

Manuscrito: `output/ESTUDIO_CCBHASH.md`. Documento compuesto: `output/pdf/ESTUDIO_CCBHASH.pdf`. Protocolo: `study/PROTOCOL.md`. Fuentes bibliográficas: `study/LITERATURA.md`.

Se evalúa el commit `fd40d49973f5129c171dc5849ec6a8bb5fdd88a0` de pblprz/ccbhash, conservado sin modificar. La evaluación comprende enumeraciones de componentes, testigos con comportamiento demostrado, emulación, compilación en cuatro arquitecturas, calibración separada de prueba, contratos de API y el depósito bruto de Zenodo 20439493. Las cifras verificadas constan en los JSON de `study/results` y en las tablas del documento.

## Reproducción en Windows

Con Python 3.12 y PowerShell, desde la raíz:

```powershell
./study/setup.ps1 -Python 'python'
./study/run_all.ps1 -Python 'python' -ReextractControlled
```

El setup instala las 21 dependencias fijadas en `.tools/python` y descarga las herramientas con comprobación SHA-256: radare2 5.8.8 nativo, el módulo oficial 6.0.4 WASI con Wasmtime 49.0.0, Python 3.9.0 para paridad, Zig 0.14.1 / Clang 19.1.7 y 7zr 26.03. Las fuentes y entradas controladas se incluyen en el paquete.

`run_all.ps1` ejecuta las campañas y sus verificadores. Descarga y comprueba el archivo bruto público de 29.071.158.824 bytes y procesa sus 5.489 perfiles binarios. El contenido expandido supera 574 GB, pero se lee por bloques y no se almacena íntegro. La descarga y el cálculo requieren tiempo, espacio temporal y conexión. Los perfiles completados se reutilizan únicamente si coinciden los CRC de sus entradas.

`-SkipPdf` permite repetir el cálculo sin componer el documento. Sin `-ReextractControlled`, las capturas controladas se reutilizan solo si coinciden fichero, versión, SHA-256 y código de extracción. Corpus e integración se vuelven a ejecutar. Los vacíos de extracción nunca se interpretan como firmas iguales.

El alojamiento WASI conserva las secciones de código y datos oficiales; `prepare_wasi.py` comprueba su igualdad. El host asigna una pila de 64 MiB en memoria ampliada. `compat.py` documenta las conversiones y obtiene las listas reales de variables. Los reductores, intervalos, digests y pesos permanecen intactos.

Radare2 analiza estáticamente los binarios públicos. Unicorn emula las rutinas benignas propias. Las etiquetas compiladas se demuestran mediante una fórmula unsigned de 32 bits; calibración y prueba se separan por fórmula.

## Verificación de los resultados guardados

Antes de regenerarlos, comprobar el manifiesto:

```powershell
python study/provenance.py --verify-manifest
python study/verify_results.py
python study/run_audit.py
python study/verify_extensions.py
python study/verify_compiled.py
python study/verify_large.py
python study/publication_audit.py
python study/close_review.py
python study/check_manuscript.py
```

Estas órdenes necesitan las dependencias del setup. `verify_large.py` usa `signature_columns.npz` y `record_ids.csv.gz`: recontar los registros no exige descargar otra vez los 29 GB. Contrasta agrupación NumPy y SQL, comprueba las siete cantidades de todos los registros y vincula las reconstrucciones brutas por perfil a sus filas exportadas. También verifica los recuentos de advertencias de serialización. `publication_audit.py` comprueba la lógica matemática con pesos racionales, ejecución simbólica de los PE y refinamiento de las particiones del depósito. Su explicación está en `study/REVISION_PUBLICACION.md`. La extracción completa puede repetirse desde el depósito público. Los verificadores escriben evidencia nueva; regenerar el manifiesto si se prepara otro paquete.

El PDF utiliza Georgia, Segoe UI y Consolas; en macOS, donde Segoe UI no está instalada, el generador usa Arial y lo registra en `pdf_checks.json`. Tras regenerarlo, revisar todas sus páginas; el generador marca esa comprobación como pendiente. Las figuras incluyen PNG, SVG y PDF con sus datos. `study/results/pdf_checks.json` registra la revisión del ejemplar distribuido.

## Procedencia y licencias

CCBHash conserva Apache-2.0 en `ccbhash-src/LICENSE`. BinRankBench conserva licencias y atribuciones en `references/binrankbench`. Los scripts propios usan MIT en `study/LICENSE`. El depósito conserva su atribución y licencia en `study/results/literature/zenodo_record.json`.

El manifiesto `study/SHA256SUMS.json` identifica los archivos mediante SHA-256. Excluye su propio archivo y el ZIP para evitar referencias circulares. `study/package.py` genera rutas relativas seguras, comprueba CRC y coteja el manifiesto del paquete.

Se excluyen herramientas y cachés `.tools`, carpetas Git y resultados externos precalculados. Se incluyen los resultados propios, datos portátiles completos, muestras de validación, scripts, figuras, documento y licencias. El objeto de estudio se conserva íntegro.

El documento se entrega para revisión editorial. Las comprobaciones son internas; no se atribuye publicación externa, revisión por pares ni un DOI nuevo.
