from backend.services.risk_engine import calculate_phishing_score

def test_legitimate_is_low():
 r=calculate_phishing_score('training@example.org','Workshop Reminder','Hello, this is an informational reminder.','', '')
 assert r['risk_score']<=40

def test_phishing_signals_raise_score():
 r=calculate_phishing_score('security-alert@account-check.invalid.test','URGENT Verify Your Account','Urgent. Confirm your password immediately or your account will be suspended.','http://198.51.100.10/verify-account','invoice.pdf.exe')
 assert r['risk_score']>40
 assert r['classification'] in {'SUSPICIOUS','HIGH RISK / LIKELY PHISHING'}
 assert len(r['findings'])>=3

def test_url_is_static():
 r=calculate_phishing_score('a@example.org','Notice','Please review','http://198.51.100.10/login','')
 assert r['url_risk_score']>0
