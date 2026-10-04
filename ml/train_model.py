from pathlib import Path
import pandas as pd, joblib
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score,precision_score,recall_score,f1_score
ROOT=Path(__file__).resolve().parents[1]; df=pd.read_csv(ROOT/'data/phishing_email_dataset.csv'); text=df.subject.fillna('')+' '+df.body.fillna(''); y=(df.label=='PHISHING').astype(int)
Xtr,Xte,ytr,yte=train_test_split(text,y,test_size=.25,random_state=42,stratify=y)
model=Pipeline([('tfidf',TfidfVectorizer(ngram_range=(1,2),min_df=1)),('clf',LogisticRegression(max_iter=1000))]); model.fit(Xtr,ytr); p=model.predict(Xte)
metrics={'accuracy':accuracy_score(yte,p),'precision':precision_score(yte,p),'recall':recall_score(yte,p),'f1':f1_score(yte,p)}
joblib.dump(model,ROOT/'ml/phishing_model.joblib'); (ROOT/'ml/metrics.json').write_text(__import__('json').dumps(metrics,indent=2)); print(metrics)
