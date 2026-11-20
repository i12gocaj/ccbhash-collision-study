/* Exact traversal-index serialization for immutable CCBHash semantics.
 * The Python wrapper supplies unique outgoing edges in their original order.
 * On a revisit, only the visit ID changes: all outgoing edges were emitted
 * on the first visit. Each edge can append a node at most once, so the queue
 * contains at most m+1 entries. See large_model.py for the equivalence proof.
 * This accelerator belongs to the evaluation harness, not the studied source.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#define API __declspec(dllexport)
typedef struct {
    uint32_t n;
    uint64_t m;
    const uint64_t *offset;
    const uint32_t *target;
    const unsigned char *present;
    uint64_t *id;
    uint32_t *queue,*order;
    unsigned char *active,*emitted;
    char *text;
} Graph;
API void ccb_graph_destroy(Graph *g) {
    if (!g) return;
    free(g->id);free(g->queue);free(g->order);free(g->active);free(g->emitted);free(g->text);free(g);
}
API Graph *ccb_graph_create(uint32_t n,uint64_t m,const uint64_t *offset,const uint32_t *target,const unsigned char *present) {
    if (!n || m>UINT64_MAX-n-1 || m>(SIZE_MAX/sizeof(uint32_t))-1) return NULL;
    Graph *g=calloc(1,sizeof(Graph));if(!g)return NULL;
    g->n=n;g->m=m;g->offset=offset;g->target=target;g->present=present;
    g->id=malloc((size_t)n*sizeof(uint64_t));g->queue=malloc(((size_t)m+1)*sizeof(uint32_t));
    g->order=malloc((size_t)n*sizeof(uint32_t));g->active=malloc(n);g->emitted=malloc(n);
    unsigned digits=1;for(uint64_t v=m+1;v>=10;v/=10)digits++;
    if (n+m>SIZE_MAX/(digits+3)-1) {ccb_graph_destroy(g);return NULL;}
    g->text=malloc((size_t)(n+m)*(digits+3)+1);
    if(!g->id || !g->queue || !g->order || !g->active || !g->emitted || !g->text){ccb_graph_destroy(g);return NULL;}
    return g;
}
static char *decimal(char *out,uint64_t value) {
    char reverse[20];unsigned size=0;
    do{reverse[size++]=(char)('0'+value%10);value/=10;}while(value);
    while(size)*out++=reverse[--size];return out;
}
API const char *ccb_graph_text(Graph *g,uint32_t root,uint64_t *length) {
    if(!g || root>=g->n)return NULL;
    memset(g->active,0,g->n);memset(g->emitted,0,g->n);
    uint64_t head=0,tail=1,visits=0;uint32_t count=0;
    g->queue[0]=root;g->active[root]=1;
    while(head<tail) {
        uint32_t node=g->queue[head++];g->active[node]=0;g->id[node]=visits++;
        if(!g->present[node] || g->emitted[node])continue;
        g->emitted[node]=1;g->order[count++]=node;
        for(uint64_t edge=g->offset[node];edge<g->offset[node+1];edge++) {
            uint32_t target=g->target[edge];
            if(!g->active[target]) {
                if(tail>g->m)return NULL;
                g->queue[tail++]=target;g->active[target]=1;
            }
        }
    }
    char *out=g->text;
    for(uint32_t i=0;i<count;i++) {
        uint32_t node=g->order[i];out=decimal(out,g->id[node]);*out++=':';
        for(uint64_t edge=g->offset[node];edge<g->offset[node+1];edge++) {
            if(edge>g->offset[node])*out++=',';
            out=decimal(out,g->id[g->target[edge]]);
        }
        *out++=';';
    }
    *out=0;*length=(uint64_t)(out-g->text);return g->text;
}
