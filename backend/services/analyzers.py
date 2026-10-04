import re
from urllib.parse import urlparse

URGENT = ["urgent", "immediately", "act now", "as soon as possible", "verify now", "final warning"]
CREDENTIAL = ["password", "otp", "one-time code", "login", "verify your account", "credentials"]
FINANCIAL = ["invoice", "payment", "refund", "bank", "transfer", "billing"]
THREAT = ["suspended", "blocked", "deactivated", "legal action", "will be closed"]
REWARD = ["you have won", "winner", "prize", "reward", "congratulations"]
PERSONAL = ["personal details", "date of birth", "address", "identity", "confirm your details"]

def _hits(text, words):
    t=(text or "").lower(); return [w for w in words if w in t]

def analyze_sender(sender):
    sender=(sender or "").strip(); findings=[]; score=0
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", sender): score+=20; findings.append("Sender format is unusual or invalid")
    domain=sender.split('@',1)[1].lower() if '@' in sender else ''
    if domain.count('.')>=3: score+=10; findings.append("Sender domain has many subdomains")
    if re.search(r"[^a-zA-Z0-9.\-]", domain): score+=10; findings.append("Sender domain contains unusual characters")
    if len(domain)>35: score+=10; findings.append("Sender domain is unusually long")
    if domain.endswith(('.invalid','.test')): findings.append("Sender uses a synthetic/test domain")
    return min(score,100), findings

def analyze_content(subject, body):
    text=f"{subject or ''} {body or ''}"; findings=[]; counts={}; score=0
    groups=[('Urgency',URGENT),('Credential request',CREDENTIAL),('Financial pressure',FINANCIAL),('Threat/fear',THREAT),('Reward claim',REWARD),('Personal-information request',PERSONAL)]
    weights={'Urgency':10,'Credential request':20,'Financial pressure':10,'Threat/fear':10,'Reward claim':10,'Personal-information request':10}
    for name,words in groups:
        h=_hits(text,words)
        counts[name]=h
        if h: score+=weights[name]; findings.append(f"{name}: {', '.join(h[:3])}")
    if re.search(r"\b(dear customer|dear user|hello customer)\b", text.lower()): score+=5; findings.append('Generic greeting detected')
    if text.count('!')>=3: score+=5; findings.append('Multiple exclamation marks detected')
    letters=[c for c in text if c.isalpha()]
    if letters and sum(c.isupper() for c in letters)/len(letters)>.35: score+=5; findings.append('High uppercase ratio detected')
    return min(score,100), findings, counts

def analyze_urls(urls):
    findings=[]; score=0; details=[]
    for raw in re.findall(r"https?://[^\s<>]+", urls or ''):
        u=raw.rstrip('.,);]'); p=urlparse(u); host=p.hostname or ''; uscore=0; uf=[]
        if p.scheme!='https': uscore+=10; uf.append('Non-HTTPS URL')
        if re.fullmatch(r'\d+(\.\d+){3}',host): uscore+=20; uf.append('Raw IP address')
        if host.count('.')>=3: uscore+=10; uf.append('Excessive subdomains')
        if len(u)>90: uscore+=10; uf.append('Unusually long URL')
        if any(k in (p.path+'?'+p.query).lower() for k in ['verify','login','password','otp','account','payment']): uscore+=10; uf.append('Security-sensitive keyword in URL')
        if any(k in host.lower() for k in ['bit.ly','tinyurl','shorturl']): uscore+=10; uf.append('Shortened URL pattern')
        if any(ch in host for ch in ['@','_']): uscore+=10; uf.append('Unusual hostname characters')
        uscore=min(uscore,100); score+=uscore; findings.extend(uf); details.append({'url':u,'risk_score':uscore,'findings':uf})
    return min(score,100), findings, details

def analyze_attachment(filename):
    if not filename: return 0, []
    f=filename.lower(); findings=[]; score=0
    risky=('.exe','.scr','.bat','.cmd','.js','.vbs','.ps1')
    if f.endswith(risky): score+=25; findings.append('Potentially executable/script attachment')
    if re.search(r'\.[a-z0-9]{2,5}\.(exe|scr|bat|cmd|js|vbs|ps1)$',f): score+=25; findings.append('Double-extension attachment pattern')
    return min(score,100),findings

def extract_features(sender,subject,body,urls,attachment):
    cs,cf,_=analyze_content(subject,body); us,uf,_=analyze_urls(urls); ss,sf=analyze_sender(sender); ats,af=analyze_attachment(attachment)
    text=f"{subject} {body}".lower()
    return {'urgent_keyword_count':sum(text.count(w) for w in URGENT),'credential_keyword_count':sum(text.count(w) for w in CREDENTIAL),'financial_keyword_count':sum(text.count(w) for w in FINANCIAL),'threat_keyword_count':sum(text.count(w) for w in THREAT),'url_count':len(re.findall(r"https?://[^\s<>]+",urls or '')),'suspicious_url_score':us,'sender_risk_score':ss,'content_risk_score':cs,'attachment_risk_score':ats}
