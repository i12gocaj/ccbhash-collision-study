"""Cross-check the manuscript's result tables against the evaluated evidence."""
from common import *
import re
from decimal import Decimal,ROUND_HALF_UP

def read(name):
    return json.loads((ROOT/'study/results'/name).read_text(encoding='utf-8'))
def integer(value):
    return int(value.replace('.',''))

if __name__=='__main__':
    text=(ROOT/'output/ESTUDIO_CCBHASH.md').read_text(encoding='utf-8')
    assert '\ufffd' not in text
    tables=[]
    for block in re.findall(r'(?m)(?:^\|[^\n]+\n)+',text):
        rows=[[c.strip() for c in line.strip().strip('|').split('|')] for line in block.splitlines()]
        tables.append(rows)
    def table(header):
        matches=[t for t in tables if t[0][0]==header]
        assert len(matches)==1,(header,len(matches))
        return matches[0]
    core=read('core/summary.json')
    rows=table('Componente')[2:]
    assert len(rows)==13
    for row,field in zip(rows,ccb.weights):
        assert float(row[2].replace(',','.'))==ccb.weights[field],(row,field)
    family=dict((row[0],integer(row[1])) for row in table('Resultado de la familia')[2:])
    controlled=read('controlled/summary.json')
    assert family['Pares de colisión completa']==controlled['hashes']['2']['collision_pairs']
    assert family['Comprobaciones de retorno mediante emulación']==controlled['emulation']['checks']
    assert family['Funciones y ficheros distintos']==controlled['successful_functions']
    for row,field in zip(table('Texto de característica')[2:],('name','opcodes','args','cfg','callgraph')):
        assert integer(row[1])==core['text'][field]['2']['n']
        for i,w in enumerate((2,4,8),2):
            assert integer(row[i])==core['text'][field][str(w)]['collision_pairs']
    for row,field in zip(table('Cantidad')[2:],('ninstrs','indegree','outdegree','nvars','cc','nblocks','stackframe')):
        assert integer(row[1])==core['numeric'][field]['unique']
        assert integer(row[2])==core['numeric'][field]['saturation_from']
    corpora=[read(folder+'/summary.json') for folder in ('fresh_corpus','fresh_corpus_6.0.4-wasi')]
    for row,binary in zip(table('Binario')[2:-1],('git_2-47-1.exe','libpng16.so.16.43.0','vlc_3-0-20','zlib1_1-2-3.dll')):
        for column,data in enumerate(corpora,1):assert integer(row[column])==data['binary_counts'][binary]
    for row,key in zip(table('Medida')[2:],('pairs','score_ge_0.5','score_ge_0.75','score_ge_0.9','full_collisions','compression_inflated_pairs')):
        for column,data in enumerate(corpora,1):assert integer(row[column])==data['pair_metrics']['all'][key]
    compiled=read('compiled/summary.json')
    for row,key in zip(table('Medida con umbral 0,58')[2:],('tp','fn','fp','tn','tpr','fpr')):
        for column,split in enumerate(('calibration','test'),1):
            expected=compiled['results'][split]['metrics_at_selected_threshold'][key]
            if key in ('tpr','fpr'):
                assert Decimal(row[column].rstrip('%').replace(',','.'))==Decimal(str(expected*100)).quantize(Decimal('.01'),rounding=ROUND_HALF_UP)
            else:assert integer(row[column])==expected
    large=read('large/summary.json')
    rows=table('Registros del depósito')[2:]
    assert len(rows)==5
    for row,key in zip(rows,('input_functions','original_filter','missing_cfg','missing_variables','included')):
        assert integer(row[1])==large['counts'][key]
    rows=table('Nivel de comparación')[2:]
    assert len(rows)==5
    for row,key in zip(rows,('raw','pre_digest','s2','s4','s8')):
        actual=large['collision_counts'][key]
        for index,metric in enumerate(('unique','all_equal_pairs','distinct_recovered_code_collision_pairs'),1):
            assert integer(row[index])==actual[metric],(row,metric)
    assert '5.489' in text
    checks=read('protocol_completion.json')
    assert checks['status']=='passed' and not checks['pending_protocol_tests']
    dump(ROOT/'study/results/manuscript_checks.json',dict(status='passed',tables_checked=len(tables),
        quantitative_tables_checked=9,scope='Reported result tables checked against JSON; prose additionally reviewed',
        manuscript_sha256=hashlib.sha256((ROOT/'output/ESTUDIO_CCBHASH.md').read_bytes()).hexdigest()))
    print('Manuscript result tables verified against evaluated evidence')
