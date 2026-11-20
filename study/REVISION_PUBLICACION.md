# Revisión lógica y matemática del estudio

Esta revisión interna comprueba los argumentos que sostienen los resultados del manuscrito. Se acompaña de `publication_audit.py` y de su salida verificable `results/publication_audit.json`. Complementa los verificadores de entradas brutas, firmas, CSV, emulación e integridad; no se presenta como revisión por pares externa.

## Igualdad y comparación

Los trece pesos se leen como fracciones decimales exactas del código fijado. Todos son positivos y su suma es uno. La auditoría recorre las 8.192 combinaciones de componentes iguales o distintas y contrasta la API con la suma racional. La igualdad de diccionarios decide la colisión completa; las pequeñas diferencias de coma flotante no se convierten en colisiones ni cambian los umbrales.

La capacidad nominal se obtiene multiplicando seis dominios de 2^16 salidas, un dominio de 256 códigos y seis dominios de 16 códigos: 2^128. Se trata de capacidad combinatoria, no de una distribución uniforme ni de independencia entre características.

En una media de mejores coincidencias, para archivos no vacíos y firmas completas, cada sumando está entre cero y uno. La media es uno exactamente cuando todos los sumandos lo son. Como los pesos son positivos, eso exige una firma igual para cada función de origen. No exige una correspondencia uno a uno ni igualdad de los archivos.

## Retornos de los ejemplos

La prueba algebraica usa aritmética módulo 2^32. El factor tres tiene inverso porque mcd(3, 2^32)=1. Por tanto, 3(c-d) no es cero para constantes distintas del intervalo 0..255. El resultado cubre todas las entradas de 32 bits, no solo las entradas emuladas.

Para comprobar que esta fórmula describe los binarios, la auditoría resuelve la dirección de entrada desde las cabeceras PE y decodifica sus bytes con Capstone. Un ejecutor simbólico separado mantiene expresiones afines (a*x+b) módulo 2^32. Solo admite las instrucciones y operandos cuya semántica se implementa explícitamente; cualquier otro caso detiene la revisión. En los saltos condicionales recorre los dominios x=0 y x!=0, que cubren todas las entradas posibles.

Así se verifican las 256 rutinas de la familia y los siete casos adicionales, incluido el caso base repetido. Las expresiones recuperadas coinciden con las fórmulas del manuscrito. La prueba habla del valor de retorno; los efectos sobre registros auxiliares, pila o tiempo no se usan como definición de equivalencia.

Las etiquetas de la familia compilada proceden del C unsigned y de la misma propiedad algebraica. La comprobación contra ELF y las 20.480 ejecuciones de sus bytes se conservan por separado. Los dos grupos contienen 640 variantes cada uno: 32 fórmulas por 20 compilaciones. Sus 204.480 pares se dividen exactamente en 6.080 positivos y 198.400 negativos. Se recalculan con fracciones las 202 filas de métricas. El criterio de máximo de exactitud balanceada, con empate a favor del umbral mayor, se aplica solamente al grupo de calibración y devuelve 0,58.

## Denominadores y mecanismos en el depósito

La unidad de registro es el par (perfil binario, dirección de función). Repetir código en otro perfil no duplica esa unidad. Los pares de código recuperado igual y distinto se separan; solo estos últimos intervienen en los incrementos de colisión entre códigos diferentes.

Para N=7.224.074 registros, N(N-1)/2=26.093.618.966.701. La partición dentro de perfiles y entre perfiles suma ese total. Las cantidades se recalculan con enteros Python, que evitan un desbordamiento del acumulador.

Restar recuentos de dos etapas solo permite atribuir el incremento si la primera partición refina la segunda. La auditoría comprueba esta condición en todas las filas: una clase de vector bruto pertenece a una sola clase posterior a cuantización, y una clase posterior a cuantización pertenece a una sola clase de firma de cada tamaño. La comprobación se realiza ordenando las claves y examinando todas las adyacencias iguales, no por muestreo.

Además, las firmas de cuatro y ocho bytes tienen tantas clases como la etapa previa al digest. La aplicación entre clases es sobreyectiva: cada clase de firma contiene al menos un registro y ese registro procede de una clase previa. Una aplicación sobreyectiva entre conjuntos finitos de igual cardinalidad es biyectiva. Por ello sus particiones de igualdad coinciden exactamente en los datos estudiados; el resultado es más fuerte que observar la misma suma de pares.

El recuento reproduce 24.860.645 pares de representación, 590.985 añadidos por cuantización y 522 añadidos por digests de dos bytes, para un total de 25.452.152 pares de código recuperado diferente con firma igual. La atribución sigue ese orden de etapas: no trata esos números como causas independientes.

La identidad de los vectores brutos, textos previos y código recuperado se registra mediante claves SHA-256, tal como indican la tabla y los metadatos. La igualdad de la firma CCBHash se comprueba con todos sus bytes. Los recuentos de procedencia se refieren a esas claves y no se presentan como un teorema de inyectividad de SHA-256. Tampoco se usa una diferencia de código para afirmar divergencia semántica.

## Modelo de primera colisión y contrastes

Para M=65.536 salidas, la supervivencia tras n extracciones es el producto de (1-j/M), para j=1..n-1. La primera colisión puede aparecer entre las extracciones 2 y M+1. La simulación utiliza todo ese soporte; la distribución acumulada se calcula mediante sumas de logaritmos y se verifica por una recurrencia de productos distinta. La representación numérica utiliza coma flotante doble.

Se corrigió la tabla del muestreo inverso que antes terminaba en 2.000 extracciones: la probabilidad restante era pequeña, pero no nula. Las semillas conservadas producen las mismas 2.000 réplicas y el mismo resultado publicado tras ampliar la tabla. No cambian D=0,06458360491592272 ni p=0,3308345827086457. Este ajuste pertenece al método de simulación del estudio, sin modificar CCBHash.

El estadístico discreto respeta los empates y examina los extremos de cada salto. El valor p usa (1+réplicas al menos tan extremas)/(1+número de réplicas). Los 80 contrastes de bits conservan sus valores p brutos y la corrección de Holm conjunta. Los pares del corpus comparten funciones: sus recuentos no se utilizan como ensayos binomiales independientes para construir intervalos de confianza.

## Cierre

La revisión se considera superada cuando el ejecutable de auditoría, los verificadores de datos y el cierre del protocolo terminan sin discrepancias. El manifiesto y el comprobador del manuscrito vinculan esas evidencias con los archivos distribuidos. La conclusión publicable es la que se demuestra: existen colisiones completas con retornos diferentes, se identifican sus mecanismos y se documentan los recuentos de las campañas realizadas.
