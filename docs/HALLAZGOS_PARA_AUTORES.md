# Hallazgos técnicos y propuestas para CCBHash

Este documento resume, para quienes mantienen CCBHash, qué observa el estudio en la implementación pública y qué cambios podrían abordar cada efecto. Las referencias de línea corresponden a `ccbhash-src/ccbhash.py` en el commit `fd40d49973f5129c171dc5849ec6a8bb5fdd88a0`, que el estudio conserva sin modificar.

La intención es constructiva. Un fuzzy hash debe agrupar código parecido, y muchas de las coincidencias medidas son precisamente el comportamiento buscado. Lo que el estudio documenta es dónde la representación deja de distinguir funciones cuyo comportamiento difiere de forma demostrable, para que esa frontera pueda elegirse de forma explícita.

Cada hallazgo indica su evidencia en `study/results` y la sección del manuscrito (`output/ESTUDIO_CCBHASH.md`) donde se explica.

## Resumen

| # | Hallazgo | Tipo | Evidencia |
| --- | --- | --- | --- |
| 1 | Los operandos inmediatos no participan en la firma | Diseño de la representación | `controlled/`, sección 3 |
| 2 | Las operaciones se reducen a un conjunto: sin orden ni frecuencia | Diseño de la representación | `adversarial/`, sección 3 |
| 3 | Los saltos condicionales pierden su condición | Diseño de la representación | `adversarial/`, sección 3 |
| 4 | Digests textuales de 16 bits | Parámetro | `core/`, sección 4 |
| 5 | La serialización del CFG pierde `fail`/`jump` y ordena direcciones como texto | Serialización | `audit/`, sección 8 |
| 6 | El callgraph no es una forma canónica | Serialización | `audit/`, sección 8 |
| 7 | Las variables de clase `reg` se descartan | Compatibilidad con radare2 actual | `audit/`, sección 6 |
| 8 | El esquema JSON de radare2 ha cambiado | Compatibilidad | `probe.json`, sección 2 |
| 9 | Bucle de reintento sin límite | Robustez | `contracts.json` |
| 10 | La comparación de ficheros es direccional | Semántica del comparador | `contracts.json`, sección 8 |
| 11 | Suma de pesos en coma flotante | Detalle numérico | `contracts.json`, sección 8 |

## 1. Los operandos inmediatos no participan en la firma

`_get_opcodes` (líneas 142-174) solo usa el campo `type` de cada instrucción. El valor de los inmediatos no entra en ninguna componente.

**Efecto medido.** 256 rutinas x86-64 que calculan `3(x + c) - 1 mod 2^32`, con `c` de 0 a 255, reciben la misma firma. Ningún par devuelve el mismo valor para ninguna entrada de 32 bits: la diferencia es `3(c - d)`, que nunca es cero módulo `2^32`. La colisión se mantiene con digests de 4 y 8 bytes, porque los textos ya eran iguales antes de comprimir.

**Propuesta.** Añadir una componente de bajo peso con un resumen de constantes, por ejemplo un digest del multiconjunto de inmediatos normalizados (por magnitud o por clase: cero, potencia de dos, pequeño, grande). Así se distinguen las constantes sin romper la tolerancia a recompilaciones, que suelen conservarlas.

## 2. Las operaciones se reducen a un conjunto, sin orden ni frecuencia

En las líneas 168-172 solo se serializan las claves del diccionario de recuentos, así que el número de apariciones de cada tipo se calcula pero se descarta.

**Efecto medido.** Intercambiar multiplicación y resta (`3x-1` frente a `3x-5`), o cambiar una suma por una resta sin alterar el conjunto de tipos (`3x-1` frente a `3x-3`), produce firmas completas iguales.

**Propuesta.** Serializar también los recuentos (`tipo:n;`), cuantizados si se quiere tolerancia. Otra opción es un digest de bigramas de tipos de operación dentro de cada bloque, que recoge el orden local con poco coste.

## 3. Los saltos condicionales pierden su condición

radare2 clasifica `je` y `jne` con el mismo `type`, `cjmp`. Además, la línea 160 (`"jmp" in ins_type`) agrupa `cjmp` con `jmp` y con el resto de variantes de salto.

**Efecto medido.** Invertir `je` por `jne` intercambia los retornos 1 y 2 para toda entrada, y la firma completa no cambia.

**Propuesta.** Conservar la familia de condición (igualdad, signo, acarreo...) usando la mnemónica o el campo `cond` de radare2. Como mínimo, distinguir salto condicional de incondicional.

## 4. Digests textuales de 16 bits

La línea 191 usa `blake2b(..., digest_size=2)`.

**Efecto medido.** Sobre dominios enumerados de 65.536 textos distintos aparecen unos 32.600 a 33.200 pares iguales por componente, en línea con la referencia de cumpleaños. La primera colisión de nombres llega, de mediana, hacia el texto 314. Con 4 bytes solo queda un par (en el dominio de nombres) y con 8 bytes ninguno. En el corpus público completo, la compresión añade 522 pares con código diferente a los 25,45 millones que ya coinciden antes de comprimir. Su impacto real es pequeño frente a los hallazgos 1 a 3.

**Propuesta.** Pasar a 4 bytes por componente textual: la firma crece de 16 a 28 bytes y desaparecen las colisiones de compresión observadas. Si el tamaño es crítico, priorizar `opcodes` y `cfg`, que son las de mayor peso.

## 5. La serialización del CFG pierde `fail`/`jump` y ordena direcciones como texto

En la línea 126, los destinos de cada bloque se ordenan como cadenas hexadecimales.

**Efecto medido.**
- Intercambiar los destinos `fail` y `jump` conserva el texto, aunque cambie la semántica de la rama.
- El orden lexicográfico no coincide con el numérico cuando cambia la longitud de la cadena: con `0x10`, `0xf0` y `0x100`, una traslación uniforme de `0x1000` cambia la representación. La invariancia ante traslación, por tanto, no es general.
- La auditoría encuentra 54 destinos fuera de la función en 41 funciones (radare2 5.8.8). En ese caso se imprime un aviso y la arista se pierde (líneas 131-137). El aviso dice "callgraph" aunque se trate del CFG.

**Propuesta.** Etiquetar las aristas (`0:1f,2j;`), ordenar por valor numérico o por identificador relativo, y representar los destinos externos con un marcador explícito en lugar de omitirlos.

## 6. El callgraph no es una forma canónica

`_get_callgraph` (líneas 60-103) reasigna el identificador de un nodo cada vez que sale de la cola (línea 80), y el resultado depende del orden de las llamadas.

**Efecto medido.** Los casos de autorrecursión y recursión mutua terminan, y los nodos no alcanzables y las aristas duplicadas tienen un resultado caracterizado. Pero grafos isomorfos pueden serializarse de forma distinta, y de los 65.536 grafos dirigidos de cuatro vértices solo salen 32.114 textos distintos.

**Propuesta.** Asignar cada identificador una sola vez, en el primer descubrimiento, y ordenar los sucesores de forma estable. Si se busca invariancia frente a isomorfismo, usar una forma canónica (por ejemplo, un hash Weisfeiler-Lehman de pocas iteraciones).

## 7. Las variables de clase `reg` se descartan

`_get_variables` (líneas 36-43) solo acepta las clases `arg` y `var`. Con radare2 actual, los argumentos en registro llegan con clase `reg` y se omiten.

**Efecto medido.** Ocurre en 353 de 468 funciones (5.8.8) y en 356 de 472 (6.0.4) de los binarios de control, y en toda la familia controlada.

**Propuesta.** Tratar `reg` como argumento, o fijar y documentar la versión de radare2 para la que el reductor es correcto.

## 8. El esquema JSON de radare2 ha cambiado

El código espera `offset` en `aflj` y en los bloques de `agj`, y `bpvars`/`spvars`/`regpvars` en `afij`. Con radare2 5.8.8 y 6.0.4, esas claves son `addr`, `regvars` o directamente no aparecen, y las variables hay que pedirlas con `afvj`. Sin adaptación, la implementación no se ejecuta con versiones actuales.

El estudio usa un adaptador explícito (`study/compat.py`) que solo renombra claves y obtiene las listas reales de `afvj`, sin tocar reductores, intervalos, digests ni pesos.

**Propuesta.** Documentar la versión de radare2 soportada, o incorporar una capa de normalización similar y probarla en integración continua contra una versión fijada.

## 9. Bucle de reintento sin límite

En las líneas 259-262 (y en 318-321 y 497-500) se repite `aaa` y `aflj` mientras la lista de funciones esté vacía. Si un fichero no contiene funciones detectables, o radare2 no puede abrirlo, el proceso no termina.

**Propuesta.** Limitar los reintentos y lanzar una excepción descriptiva. Conviene además cerrar la instancia de `r2pipe` en cada reintento, porque ahora se abre una nueva sin cerrar la anterior.

## 10. La comparación de ficheros es direccional

`compare_files` (líneas 359-395) toma, para cada función del primer fichero, su mejor candidata en el segundo, y promedia. Varias funciones pueden elegir la misma candidata.

**Efecto medido.** Un fichero con una función compartida y otra sin coincidencias da 1,00 en un sentido y 0,50 en el contrario. La media vale 1 si y solo si cada función de origen tiene alguna firma idéntica en el destino, aunque el destino tenga muchas más funciones.

**Propuesta.** Documentar que la medida es de cobertura desde el origen, y ofrecer una variante simétrica (media de ambos sentidos) o con asignación uno a uno.

## 11. Suma de pesos en coma flotante

Los pesos suman 1 en decimal, pero la suma en coma flotante puede dar `1.0000000000000002`, de modo que una comparación `score == 1` o `score >= umbral` puede depender del orden de suma.

**Propuesta.** Expresar los pesos en centésimas enteras (25, 16, 15, ...) y dividir solo al presentar el resultado.

## Lo que no se afirma

- No se estima una tasa de falsos positivos en malware real. Los recuentos del corpus público describen ese corpus, y la mayoría de coincidencias reúnen funciones que probablemente proceden del mismo código fuente compilado de otra forma, que es lo que un fuzzy hash debe agrupar.
- La divergencia de comportamiento solo se afirma donde se ha demostrado: en las familias controladas, mediante una fórmula de retorno, emulación y ejecución simbólica.
- Las propuestas no se han evaluado en este estudio. Son puntos de partida para que los autores midan su efecto en la tarea para la que se diseñó CCBHash.
