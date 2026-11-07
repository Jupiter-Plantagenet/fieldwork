import pytest


def test_exact_population_keeps_missing_denominator_and_zero_support():
    from fieldwork.metrics import evaluate
    from tools.verify_metrics import verify
    population=[{'id':'a','label':0,'sha256':'x'},{'id':'b','label':0,'sha256':'y'}]
    rows=[{'id':'a','label':0,'sha256':'x','model':'m','status':'ok','logits':[1.,1.,0.]},{'id':'b','label':0,'sha256':'y','model':'m','status':'missing','logits':None}]
    a=evaluate(population,rows,3,'m')
    b=verify(population,rows,3,'m')
    assert a==b
    assert a['accuracy']==.5 and a['coverage']==.5
    assert a['matrix']==[[1,0,0],[0,0,0],[0,0,0]]
    assert a['macro_f1'] is None
    assert a['cells']['0:0']==['a']
    assert a['missing']==['b']
    with pytest.raises(ValueError): evaluate(population,rows+rows[:1],3,'m')
    with pytest.raises(ValueError): verify(population,rows+rows[:1],3,'m')
    with pytest.raises(ValueError): evaluate(population,rows[:1],3,'m')
    rows[0]['model']='other'
    with pytest.raises(ValueError): evaluate(population,rows,3,'m')
