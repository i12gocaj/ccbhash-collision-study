# Revisión 1.1 · 6 de octubre de 2026

Esta revisión conserva el objeto de estudio y todas las campañas originales. Añade controles y corrige afirmaciones que la primera versión no justificaba por completo.

- Radare2 6.0.4: se completa la evaluación mediante la distribución WASI oficial con un alojamiento de pila documentado. El ejecutable nativo de Windows sigue fallando; no se afirma que haya sido reparado.
- Python 3.9.0: se reproduce el núcleo y se realizan cinco sondas de API. Se elimina la limitación anterior de intérprete sin comprobar.
- API: se prueban ambas entradas públicas en los 256 binarios y las dos versiones de radare2, con adaptador explícito. Se añaden aserciones que impiden declarar éxito con funciones omitidas o workers fallidos.
- CFG: se corrige la afirmación general de invariancia por traslación. El orden lexicográfico de cadenas hexadecimales admite un contraejemplo que queda guardado en los contratos.
- Serialización: se cuantifican los destinos CFG externos y las variables ignoradas por kind. Se añade un análisis de sensibilidad que excluye todas las funciones con esos destinos. Los defectos originales se conservan como hallazgos, sin arreglar silenciosamente el algoritmo.
- Validación: se reconstruyen las características desde JSON bruto, se cotejan 94.285 instrucciones con los PE/ELF y se verifican todas las columnas y umbrales de pares. Los límites numéricos se extraen del AST original.
- Cobertura: se añaden siete rutinas adversarias/positivas, seis estratos de atributos compartidos, 278 testigos numéricos completos, 35 grupos de contratos y todas las 8.192 combinaciones de coincidencias del comparador.
- Estadística: se recalculan independientemente los 80 contrastes y Holm, el modelo discreto de primera colisión y su contraste Monte Carlo. Se verifica la generación por semilla de los 120.000 vectores estratificados.
- Documento: se reescribe la exposición con prosa seguida y una composición tipográfica en blanco y negro. Se mantienen la bibliografía y sus restricciones de acceso.

El cierre automático se refiere al protocolo declarado. No implica que se hayan probado todos los programas, que no pueda existir ningún error desconocido o que haya replicación externa.
