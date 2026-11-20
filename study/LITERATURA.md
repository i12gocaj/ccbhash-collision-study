# Revisión documentada de antecedentes de CCBHash

Fecha de corte: **6 de octubre de 2026**. Revisión dirigida; no revisión sistemática exhaustiva de toda la literatura ni afirmación de primacía. Las búsquedas se hicieron en la web, sitios de autores/instituciones, repositorios y metadatos de citas de OpenAlex. Solo se usan fuentes primarias para afirmaciones técnicas. Las referencias completas y su relación con los experimentos están en `output/ESTUDIO_CCBHASH.md`.

## Estudios directamente pertinentes

| Trabajo | Fuente primaria y acceso revisado | Utilidad para este estudio |
| --- | --- | --- |
| Pérez Jiménez, Onieva y Fernández, RECSI 2022 | [PDF de los autores, 6 páginas](https://www.nics.uma.es/wp-content/papers/2033.pdf); texto completo consultado | Propuesta inicial; identificar componentes y finalidad de similitud. |
| Onieva, Pérez Jiménez y López, Computers & Security 2024, 103856 | [DOI](https://doi.org/10.1016/j.cose.2024.103856), [PDF de autores, 14 páginas](https://www.nics.uma.es/wp-content/papers/Onieva0000.pdf); texto completo consultado | Contrastar diseño y alcance de la evaluación publicada. No se ha reproducido su corpus. |
| Ross, Olukoya y Martínez del Rincón, TrustCom 2025, pp. 332-343 | [Registro institucional](https://pure.qub.ac.uk/en/publications/on-the-limitations-of-fuzzy-hashing-for-malware-similarity-an-ana/), [texto completo](https://pureadmin.qub.ac.uk/ws/portalfiles/portal/656106814/On_the_Limitations_of_Fuzzy_Hashing_for_Uncovering_Code_Homologies_An_Analysis_of_Vulnerable_Code_Detection_in_Malware.pdf), [DOI](https://doi.org/10.1109/Trustcom66490.2025.00044), [código](https://github.com/nross12/fuzzy-vulnerable-malware) | Se obtuvo el manuscrito aceptado completo y se consultaron métodos y resultados. Evaluación de clasificación y recuperación de código vulnerable; etiquetas de malware a nivel de archivo. |
| Bucci, Olukoya y Martínez del Rincón, Computers & Security 2026, 105077 | [Registro institucional](https://pure.qub.ac.uk/en/publications/bridging-the-compilation-gap-a-taxonomy-and-evaluation-of-fuzzy-h/), [texto completo](https://pureadmin.qub.ac.uk/ws/portalfiles/portal/706016442/Bridging_the_compilation_gap_2026.pdf), [DOI](https://doi.org/10.1016/j.cose.2026.105077), [BinRankBench](https://github.com/valbucci/binrankbench) | Se obtuvo la versión publicada completa y se consultaron caracterización, extracción, filtros y resultados. Publicación anticipada de 30/07/2026. Sus métricas de recuperación no se presentan como medidas de colisión exacta. |

**Distinción de versiones:** BinRankBench contiene variantes de caracterización respecto al commit original de `pblprz/ccbhash`. Se reutilizan sus cuatro binarios benignos como entradas, y se recalculan las firmas con el núcleo original. No se trasladan resultados de una variante a otra.

El [depósito Zenodo 20439493](https://zenodo.org/records/20439493), DOI 10.5281/zenodo.20439493, ofrece el corpus amplio asociado a BinRankBench. Se descargó y verificó íntegramente el archivo bruto de 29.071.158.824 bytes. Se procesaron sus 5.489 perfiles y se recalcularon las firmas de 7.224.074 vectores completos mediante el núcleo original. Todos los metadatos de función quedaron clasificados por su procedencia. El volcado separado de base de datos con hashes precalculados no interviene en el cálculo. Las columnas completas y su verificación independiente se incluyen en el paquete.

## Metodología y contexto

| Referencia | Acceso | Uso |
| --- | --- | --- |
| NIST SP 800-168 (2014), Approximate Matching: Definition and Terminology | [NIST](https://csrc.nist.gov/pubs/sp/800/168/final), [PDF](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-168.pdf) | Definiciones y separación entre igualdad y similitud. |
| Martín-Pérez, Rodríguez y Breitinger (2021), Bringing order to approximate matching | [DOI](https://doi.org/10.1016/j.fsidi.2021.301120), [PDF consultado](https://d-nb.info/1351946331/34) | Taxonomía de evaluaciones y ataques a digests de similitud. |
| Göbel, Uhlig, Baier y Breitinger (2022), FRASHER | [DFRWS y PDF consultado](https://dfrws.org/presentation/frasher-a-framework-for-automated-evaluation-of-similarity-hashing/) | Evaluación reproducible y separación de escenarios. |
| Botacin et al. (2021), Understanding uses and misuses of similarity hashing functions | [DOI y resumen editorial consultado](https://doi.org/10.1016/j.fsidi.2021.301220) | Contexto sobre etiquetas, escenarios y umbrales. No es una evaluación directa de CCBHash. |
| Dueñas Ruiz et al. (2026), MNWW-MinHash | [Resumen editorial consultado](https://www.sciencedirect.com/science/article/pii/S016740482600235X), [DOI](https://doi.org/10.1016/j.cose.2026.105059) | Contexto contemporáneo de calibración estadística de similitud binaria; no se ejecutó una comparación nueva con CCBHash. |

## Registro de búsqueda y selección

Consultas principales: `CCBHash collision`, `CCBHash colisiones`, `"Compound Code Block Hash"`, `"ccbhash" "2025"`, `"ccbhash" "2026"`, `"Bridging the compilation gap"`, `"On the limitations of fuzzy hashing"`, y búsquedas de clasificación/evaluación de similarity hashing. Se siguieron los enlaces de los artículos a código y datos. El contenido del repositorio original y el de BinRankBench se inspeccionó localmente con commits fijados.

OpenAlex devolvió ocho trabajos citantes para `W4394985008` en la captura guardada en `study/results/literature/openalex_citations.json`. Es una instantánea de cobertura del índice, no ocho replicaciones de CCBHash ni una garantía de búsqueda completa.

| Trabajo citante recuperado | DOI | Decisión |
| --- | --- | --- |
| Using approximate matching and machine learning to uncover malicious activity in logs | 10.1016/j.cose.2025.104312 | Contexto de logs; no usado como prueba de colisiones en CCBHash. |
| FLSH: A Framework Leveraging Similarity Hashing for Android Malware and Variant Detection | 10.1109/ACCESS.2025.3537110 | Metadatos; texto completo no validado aquí. |
| Binary Code Similarity Detection: Retrospective Review and Future Directions | 10.32604/cmc.2025.070195 | Revisión contextual; no sustituye experimentos directos. |
| Robust Defect Detection Algorithm for Highly Reflective Surfaces Using SIFT Feature Points and Perceptual Hashing | 10.1142/S0218126625502767 | Fuera del ámbito; descartado. |
| On the limitations of fuzzy hashing for malware similarity | 10.1109/Trustcom66490.2025.00044 | Incluido como antecedente directo. |
| No ML, Just Hashes: Code Similarity Distance for Detecting IoT Malware | 10.1109/ICCE67443.2026.11449610 | Metadatos; no se infieren resultados experimentales de un texto no obtenido. |
| MNWW-MinHash | 10.1016/j.cose.2026.105059 | Contexto metodológico, sin comparación propia. |
| Bridging the compilation gap | 10.1016/j.cose.2026.105077 | Incluido; código/fixtures utilizados con atribución. |

Las lecturas parciales están señaladas. Ningún título, resumen, cita entrante o ausencia de resultados de búsqueda demuestra por sí mismo la ausencia de colisiones. La contribución del paquete reúne una clasificación de mecanismos, testigos reproducibles y recuentos completos de las campañas. Las fuentes consultadas y los experimentos propios conservan su procedencia.
