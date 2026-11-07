"""Production metric-spec/v1: all expected members remain in denominators."""
import math


def evaluate(population,records,k,model):
    expected={x['id']:x for x in population}
    if len(expected)!=len(population) or len(records)!=len(population) or len({r['id'] for r in records})!=len(records) or {r['id'] for r in records}!=set(expected): raise ValueError('population')
    matrix=[[0]*k for _ in range(k)]; cells={f'{a}:{b}':[] for a in range(k) for b in range(k)}
    missing=[]; support=[0]*k; ce=0.; ok=0
    for r in records:
        p=expected[r['id']]
        if r['label']!=p['label'] or r['sha256']!=p['sha256'] or r['model']!=model or r['status'] not in ['ok','missing','decode_failed','inference_failed']: raise ValueError('identity')
        a=p['label']; support[a]+=1
        if r['status']!='ok': missing.append(r['id']); continue
        logits=r['logits']
        if len(logits)!=k or not all(math.isfinite(x) for x in logits): raise ValueError('scores')
        b=max(range(k),key=lambda i:logits[i]); matrix[a][b]+=1; cells[f'{a}:{b}'].append(r['id']);ok+=1
        mx=max(logits);ce+=mx+math.log(sum(math.exp(x-mx) for x in logits))-logits[a]
    pred=[sum(matrix[a][b] for a in range(k)) for b in range(k)]
    f1=[2*matrix[i][i]/(support[i]+pred[i]) if support[i]+pred[i] else None for i in range(k)]
    recall=[matrix[i][i]/support[i] if support[i] else None for i in range(k)]
    result=dict(n=len(population),ok=ok,accuracy=sum(matrix[i][i] for i in range(k))/len(population) if population else None,coverage=ok/len(population) if population else None,matrix=matrix,cells={key:sorted(v) for key,v in cells.items()},missing=sorted(missing),support=support,recall=recall,f1=f1,macro_f1=sum(f1)/k if all(support) else None,cross_entropy=ce/ok if ok else None,status='complete' if ok==len(population) and ok else 'incomplete')
    result['precision']=[matrix[i][i]/pred[i] if pred[i] else None for i in range(k)]
    result['null_reasons']={'precision':['no_predicted_support' if not pred[i] else None for i in range(k)],'recall':['no_true_support' if not support[i] else None for i in range(k)],'f1':['no_true_or_predicted_support' if not support[i]+pred[i] else None for i in range(k)],'macro_f1':None if all(support) else 'missing_planned_class_support','accuracy':None if population else 'empty_population','coverage':None if population else 'empty_population','cross_entropy':None if ok else 'no_successful_predictions'}
    result['missing_by_class']=[sorted(r['id'] for r in records if r['status']!='ok' and r['label']==i) for i in range(k)]
    result['disposition_counts']={status:sum(r['status']==status for r in records) for status in ['ok','missing','decode_failed','inference_failed']}
    result['cross_entropy_complete']=bool(population) and ok==len(population)
    result['wilson_accuracy']=None
    if population:
        n=len(population);p=result['accuracy'];z=1.959963984540054
        center=(p+z*z/(2*n))/(1+z*z/n);half=z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))/(1+z*z/n)
        result['wilson_accuracy']=[max(0.,center-half),min(1.,center+half)]
    result['group_support']=None;result['group_accuracy_interval']=None
    result['group_interval_reason']='missing_group_identity'
    if population and all(isinstance(p.get('group'),str) and p['group'] for p in population):
        import random
        groups=sorted({p['group'] for p in population});correct_ids={r['id'] for r in records if r['status']=='ok' and max(range(k),key=lambda j:r['logits'][j])==r['label']}
        result['group_support']=[len({p['group'] for p in population if p['label']==i}) for i in range(k)]
        group_counts={g:(sum(p['id'] in correct_ids for p in population if p['group']==g),sum(p['group']==g for p in population)) for g in groups}
        rng=random.Random(42);draws=[]
        for _ in range(2000):
            chosen=[group_counts[rng.choice(groups)] for __ in groups];draws.append(sum(x[0] for x in chosen)/sum(x[1] for x in chosen))
        draws.sort();result['group_accuracy_interval']={'lower':draws[49],'upper':draws[1949],'replicates':2000,'seed':42,'method':'group-bootstrap/nearest-rank-v1'};result['group_interval_reason']=None
    return result
