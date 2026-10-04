# Architecture
User → Dashboard → Flask API → preprocessing/analyzers → risk engine → explainable findings → SQLite history → dashboard.

Analyzers include sender, content, URL, and attachment filename analysis. Suspicious URLs are analyzed as strings only; the application never visits them.
