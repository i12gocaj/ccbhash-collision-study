from common import *
import csv
import math
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

OUT=ROOT/'output/figures';OUT.mkdir(parents=True,exist_ok=True)
plt.rcParams.update({'font.family':'DejaVu Serif','font.size':10,'axes.spines.top':False,'axes.spines.right':False,
                     'savefig.dpi':240,'axes.titleweight':'normal'})

trials=json.loads((ROOT/'study/results/core/birthday_trials.json').read_text(encoding='utf-8'))
samples=np.array([x['evaluated'] for x in trials]);grid=np.arange(0,1001)
log_survival=0.;cdf=[]
for n in grid:
    if n>1:log_survival+=math.log1p(-(n-1)/65536)
    cdf.append(-math.expm1(log_survival))
empirical=np.array([(samples<=n).mean() for n in grid])
fig,ax=plt.subplots(figsize=(6.5,3.6));ax.plot(grid,cdf,color='#183c52',label='Modelo uniforme de 16 bits',lw=1.8)
ax.step(grid,empirical,where='post',color='#934854',linestyle='--',label='200 búsquedas con espacios de nombres separados',lw=1.5)
ax.set(xlabel='Textos evaluados hasta la primera colisión',ylabel='Probabilidad acumulada',ylim=(0,1.025),xlim=(0,1000))
ax.legend(frameon=False,loc='lower right',fontsize=8);ax.grid(alpha=.18);fig.tight_layout()
for ext in ('png','svg','pdf'):fig.savefig(OUT/f'birthday_cdf.{ext}')
plt.close(fig)
with (OUT/'birthday_cdf.csv').open('w',newline='',encoding='utf-8') as f:
    w=csv.writer(f);w.writerow(['n','uniform_cdf','empirical_cdf']);w.writerows(zip(grid,cdf,empirical))

core=json.loads((ROOT/'study/results/core/summary.json').read_text(encoding='utf-8'))
fields=['name','opcodes','args','cfg','callgraph'];labels=['Nombres','Operaciones','Tipos de argumentos','CFG','Callgraph']
actual=[core['text'][k]['2']['collision_pairs'] for k in fields]
expected=[core['text'][k]['2']['uniform_expected_pairs'] for k in fields]
fig,ax=plt.subplots(figsize=(6.5,3.6));x=np.arange(5)
ax.bar(x-.18,actual,width=.36,label='Pares observados',color='#246b73');ax.bar(x+.18,expected,width=.36,label='Esperanza uniforme',color='#e7d7b4',edgecolor='#bc8a46',hatch='///',linewidth=.6)
ax.set_xticks(x,labels,rotation=12,ha='right');ax.set(ylabel='Pares de colisión de 2 bytes');ax.legend(frameon=False,fontsize=9)
ax.grid(axis='y',alpha=.18);ax.set_axisbelow(True);fig.tight_layout()
for ext in ('png','svg','pdf'):fig.savefig(OUT/f'partial_collisions.{ext}')
plt.close(fig)

with (ROOT/'study/results/fresh_corpus/pairs.csv').open(encoding='utf-8',newline='') as f:rows=list(csv.DictReader(f))
grid=np.arange(0,101)/100
fig,ax=plt.subplots(figsize=(6.5,3.6))
tail_rows=[]
for same,label,color in [('True','Dentro del mismo binario','#246b73'),('False','Entre binarios','#934854')]:
    s=np.array([float(x['score']) for x in rows if x['same_binary']==same])
    tail=np.array([(s>=t-1e-12).mean() for t in grid])
    tail_rows.extend((same,float(t),len(s),int((s>=t-1e-12).sum()),float(p)) for t,p in zip(grid,tail))
    # Zero cannot be represented on a log axis; do not draw a fabricated floor.
    ax.plot(grid,np.where(tail>0,tail,np.nan),color=color,label=label,lw=1.5,linestyle='-' if same=='True' else '--')
ax.set_yscale('log');ax.set(xlabel='Umbral de puntuación (>=)',ylabel='Fracción descriptiva de pares',xlim=(0,1),ylim=(1e-5,1.1))
ax.legend(frameon=False,fontsize=9);ax.grid(alpha=.18);fig.tight_layout()
for ext in ('png','svg','pdf'):fig.savefig(OUT/f'corpus_score_tail.{ext}')
plt.close(fig)
with (OUT/'corpus_score_tail.csv').open('w',newline='',encoding='utf-8') as f:
    w=csv.writer(f);w.writerow(['same_binary','threshold','pairs','pairs_ge_threshold','fraction']);w.writerows(tail_rows)
compiled=json.loads((ROOT/'study/results/compiled/summary.json').read_text(encoding='utf-8'))
roc=compiled['results']['test']['roc'];chosen=compiled['results']['test']['metrics_at_selected_threshold']
fig,ax=plt.subplots(figsize=(6.5,3.6))
ax.plot([r['fpr'] for r in roc],[r['tpr'] for r in roc],color='#183c52',lw=1.8,label='Funciones compiladas: evaluación separada')
ax.plot([0,1],[0,1],color='#b5c4cb',linestyle=':',lw=1)
ax.scatter([chosen['fpr']],[chosen['tpr']],color='#934854',s=45,zorder=4,label='Umbral elegido en calibración: 0,58')
ax.set(xlabel='Fracción de parejas diferentes aceptadas',ylabel='Fracción de parejas equivalentes recuperadas',xlim=(0,1),ylim=(0,1))
ax.legend(frameon=False,fontsize=8,loc='lower right');ax.grid(alpha=.15);fig.tight_layout()
for ext in ('png','svg','pdf'):fig.savefig(OUT/f'compiled_roc.{ext}')
plt.close(fig)
with (OUT/'compiled_roc.csv').open('w',newline='',encoding='utf-8') as f:
    writer=csv.DictWriter(f,fieldnames=list(roc[0]));writer.writeheader();writer.writerows(roc)
large=json.loads((ROOT/'study/results/large/summary.json').read_text(encoding='utf-8'))
projects=sorted(large['projects'].items(),key=lambda item:item[1])
fig,ax=plt.subplots(figsize=(6.5,3.7))
ax.barh([name for name,n in projects],[n for name,n in projects],color=['#246b73']*6+['#934854'],height=.62)
maximum=max(n for name,n in projects)
for i,(name,n) in enumerate(projects):
    ax.text(n+maximum*.015,i,format(n,',').replace(',','.'),va='center',fontsize=8)
ax.set_xlim(0,maximum*1.23)
ax.set_xlabel('Funciones con las trece componentes reconstruidas')
from matplotlib.ticker import FuncFormatter
ax.xaxis.set_major_formatter(FuncFormatter(lambda n,p:format(int(n),',').replace(',','.')))
ax.grid(axis='x',alpha=.15);ax.set_axisbelow(True);fig.tight_layout()
for ext in ('png','svg','pdf'):fig.savefig(OUT/f'large_projects.{ext}')
plt.close(fig)
with (OUT/'large_projects.csv').open('w',newline='',encoding='utf-8') as f:
    writer=csv.writer(f);writer.writerow(['project','complete_functions']);writer.writerows(projects)
print('Created 5 figures in PNG, SVG and PDF, with source data')
