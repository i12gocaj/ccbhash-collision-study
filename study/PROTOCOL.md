# Protocolo de evaluación de colisiones de CCBHash

El cierre automático exige la ejecución y verificación de todas las campañas descritas en este archivo. Las enumeraciones completas se identifican por su dominio; los ejemplos de divergencia se apoyan en una prueba algebraica y en ejecución controlada.

Fecha de preparación: 6 de octubre de 2026. Documento local redactado antes de las campañas principales; no constituye prerregistro externo. Cambios y experimentos exploratorios se identificarán en el informe.

## Objeto inmutable

Repositorio solicitado: https://github.com/pblprz/ccbhash.
Commit: fd40d49973f5129c171dc5849ec6a8bb5fdd88a0.
SHA-256 de ccbhash.py: a1d7857c84b262ef50d84e068400e9e2b715e2ec13d1ce6357a12545dd0d1b45 (copia de trabajo con CRLF; el blob del commit, con LF, es 5522164c0b595db171c74b298b79db23c7dff6185d0232c9c449deacf2946193).
Evaluar la versión original, sin correcciones. Cualquier adaptación de entradas de radare se registrará por separado.

## Definiciones y unidades

1. Duplicado de entrada: registrar dos veces el mismo objeto en la unidad del experimento; no contarlo dos veces. En el depósito, la unidad es (perfil binario, dirección). Los registros de perfiles diferentes se conservan, incluso si repiten código; los pares de código recuperado igual y distinto se cuentan por separado. Los recuentos de colisión entre códigos distintos excluyen los primeros.
2. Colisión de representación: artefactos distintos con el mismo vector de características extraídas; puede ser una invariancia deseada.
3. Colisión de cuantización: valores numéricos distintos agrupados en el mismo intervalo.
4. Colisión de compresión: textos de características distintos con el mismo BLAKE2b de 2 bytes.
5. Colisión completa de función: igualdad exacta de las 13 componentes, sin confundirla con una puntuación alta.
6. Colisión perjudicial: firma igual con comportamiento demostrablemente distinto; aportar testigo verificable. La diferencia de bytes por sí sola no demuestra diferencia semántica.
7. Falso positivo por umbral: puntuación igual o superior al umbral y etiqueta negativa definida de forma independiente. Una etiqueta de origen distinto no demuestra necesariamente comportamiento distinto.

La firma completa se compara como diccionario normalizado. No se confunde el almacenamiento JSON con una codificación binaria de 16 bytes. Denominadores: pares no ordenados de entradas distintas; contar por grupos con sumatoria k(k-1)/2. Informar además de clases y excedentes N-U.

## Campañas

- Todos los valores enteros 0..10000 para cada uno de los siete campos numéricos: intervalos, umbrales, saturación, todos los pares agrupados y testigos.
- Textos distintos: 65536 nombres y 65536 subconjuntos de 16 categorías de operación. Distribuciones, colisiones parciales y testigos. Cambiar el tamaño del BLAKE2b a 4/8 bytes como ablación, no como versión original.
- 200 búsquedas de primera colisión en nombres con namespaces separados y semilla documentada; comparar supervivencia con el modelo uniforme de 16 bits. Tope 10000 por búsqueda real; cualquier censura se conserva. El muestreo del modelo nulo utiliza su soporte completo, 2..65537 extracciones, sin truncar su cola.
- Grafos CFG de cuatro vértices, con 0..2 destinos distintos por vértice: enumeración completa de 14641 representaciones. Separar igualdad de texto de igualdad de digest. Comparar cambios de etiquetas de rama, traslación de direcciones y orden de bloques.
- Callgraphs: ciclos, etiquetas, orden, duplicación de aristas y nodos no alcanzables; testigos puntuales y enumeración de grafos pequeños.
- 256 funciones PE64 benignas ensambladas con distintos inmediatos, iguales tipos de operaciones y comportamiento aritmético verificable. Ejecutar la API original mediante radare2, conservar resultados completos y errores. Verificar la fórmula de retorno por emulación.
- Corpus real disponible en fixtures públicos de BinRankBench (Git, zlib, libpng y VLC): todos los registros, sin selección basada en resultados; adaptación de esquema explícita. No usarlo para tasas de malware ni extrapolarlo como muestra aleatoria de programas.
- Vectores sintéticos: controles uniformes independientes y estratos con atributos compartidos; siempre etiquetados sintéticos, sin inferencia a funciones reales.
- Comparación: igualdad, simetría por función, dirección por archivo, empates, entradas vacías, atributos incompletos y conservación de firma tras persistencia.

## Estadística y controles

- Modelo parcial uniforme: E[C]=N(N-1)/(2*2^b); P(C>=1) aproximada por 1-exp(-E[C]), y exacta mediante producto en búsquedas de cumpleaños. No aplicar 128 bits uniformes a la firma estructurada.
- Medir concentración de componentes y colisiones añadidas por compresión frente a la igualdad de características sin comprimir. No multiplicar probabilidades marginales sin comprobar dependencia.
- Un intervalo binomial solo se emplea para ensayos independientes definidos. Los pares de un corpus comparten funciones: no usar N(N-1)/2 como número de observaciones independientes en un intervalo binomial. Los resultados exhaustivos son descriptivos, no estimaciones aleatorias.
- Si se prueban muchos bits o hipótesis: corrección de Holm al 5%; conservar valores p brutos y ajustados. Resultados de uniformidad no equivalen a seguridad criptográfica.
- Controles negativos/positivos: SHA-256 de artefactos, entradas duplicadas excluidas, firma con digest ampliado, igualdad del vector previo a compresión.
- Conservar semillas, entornos, fuentes, código, salidas JSON/CSV, testigos, errores, exclusiones y SHA-256 de artefactos. Validar por una implementación independiente los recuentos esenciales.

## Criterios de interpretación

La existencia de colisiones perjudiciales se establece mediante testigos con comportamiento demostrado. Los recuentos de corpus describen todas las entradas evaluadas y conservan su procedencia. Separar revisión bibliográfica y resultados propios. Utilizar el corpus público de 2026 como entrada para el núcleo original, sin trasladar las firmas de otra variante de CCBHash.

## Extracción, contratos y auditoría

Se añaden, sin sustituir las campañas anteriores:

- Reextracción completa con radare2 6.0.4 WASI. Conservar el módulo oficial, comprobar las secciones de código/datos intactas y registrar el export añadido y la pila asignada por el host. No presentar este entorno como el ejecutable nativo de Windows.
- Las dos entradas públicas de la API sobre los 256 PE, en ambas versiones de radare2: 1.024 llamadas con aserciones de cobertura, firmas y errores.
- Siete rutinas PE64 adicionales: orden, multiplicidades, condición de rama y un control de NOP con cuantización; emulación y fórmulas de retorno. El caso base reutiliza el código del primer PE de la familia original.
- Seis estratos de 20.000 vectores distintos con los siete números fijos y de cero a cinco textos compartidos. Guardar entradas, semillas y firmas de 2/4/8 bytes.
- Contratos con aserciones: 35 grupos, las 8.192 combinaciones de igualdad entre componentes y comparaciones reales seleccionadas con semilla. Los errores esperados ante entradas inválidas se separan de fallos de procesamiento.
- Reconstrucción independiente de las características desde JSON bruto, cotejo de todas las instrucciones con el fichero PE/ELF, todos los campos de los CSV de pares y todos los contrastes de bits. Los límites numéricos se leen del AST del código original.
- Medir destinos CFG externos y variables omitidas por su kind. Repetir el análisis tras excluir funciones con destinos CFG externos; no corregir silenciosamente el algoritmo.
- Comprobar cada frontera numérica y saturación, incluido un argumento que cubra los enteros no negativos posteriores a la última frontera. Aportar 278 testigos completos de los intervalos no unitarios.
- Repetición del núcleo con Python 3.9.0 y sondas de API; contraste independiente discreto de cumpleaños y de los estratos.

## Compilación y evaluación con etiquetas demostradas

- Compilar 64 fórmulas de retorno unsigned de 32 bits mediante Zig 0.14.1 / Clang 19.1.7, para x86-64, ARM32, ARM64 y RISC-V64, con O0/O1/O2/O3/Os: 20 objetos, 1.280 funciones.
- Emular los bytes de cada símbolo para 16 entradas, con fronteras y semilla 20261011: 20.480 comprobaciones. Comprobar el tamaño, las direcciones y los bytes de los símbolos contra cada ELF.
- Etiqueta positiva si la constante de la fórmula coincide; negativa si difiere. La prueba algebraica demuestra la diferencia de retorno para cada entrada del dominio.
- Separar calibración (constantes 0..31) y evaluación (32..63) por fórmula de origen. No compartir variantes de una fórmula entre ambos grupos.
- Examinar los 818.560 pares, incluidos los pares que cruzan la separación. Calibrar 101 umbrales de 0 a 1; seleccionar la mayor exactitud balanceada y, en empate, el umbral mayor, usando solo calibración. Evaluar después el umbral fijado sobre el segundo grupo.
- Verificar por separado todas las filas, las curvas y la selección del umbral. Guardar código, objetos, metadatos y retornos reales.

## Depósito público completo

- Descargar el archivo bruto de Zenodo 20439493, 29.071.158.824 bytes; cotejar el MD5 publicado y calcular SHA-256. No emplear los hashes precalculados de la variante del benchmark.
- Inventariar todos los miembros del archivo. Recorrer los 5.489 perfiles binarios y verificar tamaño y CRC de cada miembro utilizado. Leer por bloques para procesar el contenido completo sin expandir 574 GB a disco.
- Reconciliar por dirección los metadatos de función, CFG, grafo de llamadas y variables. Distinguir el almacenamiento de variables de su papel argumento/local; contrastarlo con extracción directa en las cuatro entradas de control. Enumerar los 65.536 grafos dirigidos de cuatro nodos para comprobar la equivalencia del recorrido indexado con el original.
- Para los grafos grandes, compilar desde `native_callgraph.c` un serializador equivalente. Conservar los hashes del C y del DLL; demostrar el invariante de cola, visitas, identificadores y orden de aristas, y contrastar el resultado con el original y con el recorrido Python en los 66.476 casos. El verificador final de vectores usa la reconstrucción Python separada.
- Clasificar cada función de finfo una sola vez: filtro original, CFG no exportado, variables no exportadas para esa dirección o vector completo. Los datos ausentes no se sustituyen por listas vacías ni por las variables de otra función homónima. Conservar los recuentos de procedencia por perfil y en el agregado.
- Para todos los vectores completos, contar por agrupación exacta todas las parejas con firma igual. Separar los pares de código recuperado igual y distinto, e identificar los recuentos anteriores a cuantización, posteriores a cuantización y posteriores al digest textual de 2/4/8 bytes.
- Exportar todas las columnas de firmas, las siete cantidades brutas, el número de advertencias de serialización y las identidades de registros. Repetir los recuentos con agrupación NumPy, independiente de SQL; recalcular todos los códigos numéricos a partir de los límites del AST original, y cotejar tres reconstrucciones brutas por perfil, o todas si contiene menos de tres funciones. Vincular cada reconstrucción a su fila de datos portables.

La revisión final `publication_audit.py` exige además pesos y métricas con aritmética racional, ejecución simbólica modular de los bytes de las 256 rutinas y los siete casos adicionales, y comprobación de que las particiones del depósito se refinan por etapas. Recuenta los pares con enteros Python y comprueba la atribución de los incrementos a cuantización y compresión.

El cierre de `close_review.py` exige todas estas evidencias y no admite fallos inesperados ni pruebas pendientes. Las revisiones internas se identifican como tales. La matriz de cierre se conserva en `study/results/protocol_completion.json`.
