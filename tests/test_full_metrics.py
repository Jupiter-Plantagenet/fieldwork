import math
from fieldwork.metrics import evaluate
from tools.verify_metrics import verify


def test_full_metric_denominators_missing_bucket_and_independent_intervals():
    population=[{'id':str(i),'label':i%2,'sha256':str(i),'group':'g'+str(i//2)} for i in range(8)]
    rows=[dict(p,model='model',status='ok',logits=[3.,1.,-5.] if p['label']==0 else [0.,2.,-5.]) for p in population]
    rows[1].update(status='decode_failed');rows[3].update(status='missing')
    a=evaluate(population,rows,3,'model');b=verify(population,rows,3,'model')
    assert a['precision']==[1.,1.,None]
    assert a['missing_by_class']==[[],['1','3'],[]]
    assert a['disposition_counts']=={'ok':6,'missing':1,'decode_failed':1,'inference_failed':0}
    assert a['null_reasons']['recall'][2]=='no_true_support'
    assert a['null_reasons']['precision'][2]=='no_predicted_support'
    assert a['null_reasons']['macro_f1']=='missing_planned_class_support'
    assert a['cross_entropy_complete'] is False
    assert a['group_support']==[4,4,0]
    assert a['group_accuracy_interval']['replicates']==2000
    assert a['group_accuracy_interval']['seed']==42
    assert 0<a['wilson_accuracy'][0]<a['accuracy']<a['wilson_accuracy'][1]<1
    assert a.keys()==b.keys()
    for key in a:
        if key=='cross_entropy':assert abs(a[key]-b[key])<=1e-12
        else:assert a[key]==b[key],key
