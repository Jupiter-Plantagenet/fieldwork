"""Independent stdlib oracle. Does not import the service or trust its totals."""
import math, json, argparse


def verify(population, records, classes, model):
    ids=[p['id'] for p in population]
    seen=set(); truth={p['id']:p for p in population}
    if len(set(ids))!=len(ids): raise ValueError('duplicate population')
    cells={f'{i}:{j}':[] for i in range(classes) for j in range(classes)}
    support=[0 for _ in range(classes)]; counts=[[0 for _ in range(classes)] for _ in range(classes)]; missing=[]; losses=[]
    for row in records:
        key=row['id']
        if key in seen or key not in truth: raise ValueError('duplicate/extra')
        seen.add(key); source=truth[key]
        if any(row.get(f)!=source[f] for f in ['label','sha256']) or row.get('model')!=model: raise ValueError('identity')
        actual=source['label'];support[actual]+=1
        if row['status'] in ('missing','decode_failed','inference_failed'): missing.append(key); continue
        if row['status']!='ok': raise ValueError('status')
        values=row['logits']
        if len(values)!=classes or any(not math.isfinite(v) for v in values): raise ValueError('logits')
        winner=0
        for j in range(1,classes):
            if values[j]>values[winner]: winner=j
        counts[actual][winner]+=1;cells[str(actual)+':'+str(winner)].append(key)
        maximum=max(values);losses.append(math.log(math.fsum(math.exp(v-maximum) for v in values))+maximum-values[actual])
    if seen!=set(ids): raise ValueError('missing disposition')
    n=len(ids); valid=len(losses); correct=sum(counts[j][j] for j in range(classes))
    f1=[];recall=[]
    for j in range(classes):
        predicted=sum(row[j] for row in counts);den=support[j]+predicted
        f1.append(2*counts[j][j]/den if den else None)
        recall.append(counts[j][j]/support[j] if support[j] else None)
    report={'n':n,'ok':valid,'accuracy':correct/n if n else None,'coverage':valid/n if n else None,'matrix':counts,'cells':{key:sorted(value) for key,value in cells.items()},'missing':sorted(missing),'support':support,'recall':recall,'f1':f1,'macro_f1':sum(f1)/classes if all(support) else None,'cross_entropy':sum(losses)/valid if valid else None,'status':'complete' if valid==n and n else 'incomplete'}
    predicted_support=[sum(row[j] for row in counts) for j in range(classes)]
    report['precision']=[counts[j][j]/predicted_support[j] if predicted_support[j] else None for j in range(classes)]
    report['null_reasons']={'precision':[None if x else 'no_predicted_support' for x in predicted_support],'recall':[None if x else 'no_true_support' for x in support],'f1':[None if support[j]+predicted_support[j] else 'no_true_or_predicted_support' for j in range(classes)],'macro_f1':None if all(support) else 'missing_planned_class_support','accuracy':None if n else 'empty_population','coverage':None if n else 'empty_population','cross_entropy':None if valid else 'no_successful_predictions'}
    report['missing_by_class']=[sorted(x for x in missing if truth[x]['label']==j) for j in range(classes)]
    report['disposition_counts']={s:len([r for r in records if r['status']==s]) for s in ('ok','missing','decode_failed','inference_failed')}
    report['cross_entropy_complete']=bool(n) and valid==n
    report['wilson_accuracy']=None
    if n:
        z=1.959963984540054;p=correct/n;denominator=1+z*z/n
        midpoint=(p+z*z/(2*n))/denominator
        radius=z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))/denominator
        report['wilson_accuracy']=[max(0.,midpoint-radius),min(1.,midpoint+radius)]
    report['group_support']=None;report['group_accuracy_interval']=None;report['group_interval_reason']='missing_group_identity'
    if n and all(isinstance(p.get('group'),str) and p['group'] for p in population):
        import random
        identities=sorted(set(p['group'] for p in population));members={g:[] for g in identities}
        for r in records:
            good=r['status']=='ok' and r['label']==max(range(classes),key=lambda j:r['logits'][j])
            members[truth[r['id']]['group']].append(int(good))
        report['group_support']=[len(set(p['group'] for p in population if p['label']==j)) for j in range(classes)]
        generator=random.Random(42);distribution=[]
        for iteration in range(2000):
            successes=0;trials=0
            for unused in identities:
                group=generator.choice(identities);successes+=sum(members[group]);trials+=len(members[group])
            distribution.append(successes/trials)
        distribution.sort();report['group_accuracy_interval']={'lower':distribution[49],'upper':distribution[1949],'replicates':2000,'seed':42,'method':'group-bootstrap/nearest-rank-v1'};report['group_interval_reason']=None
    return report

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--population',required=True);p.add_argument('--records',required=True);p.add_argument('--model',required=True);a=p.parse_args()
    print(json.dumps(verify(json.load(open(a.population)),[json.loads(line) for line in open(a.records)],5,a.model),sort_keys=True))
