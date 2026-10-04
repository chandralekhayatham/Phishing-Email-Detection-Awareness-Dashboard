# Quickstart

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python data/generate_dataset.py
python backend/app.py
```
Open http://127.0.0.1:5000

Optional ML training: `python ml/train_model.py`
Tests: `pytest -v`
