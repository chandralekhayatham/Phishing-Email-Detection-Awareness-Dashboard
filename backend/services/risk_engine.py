from .analyzers import analyze_sender, analyze_content, analyze_urls, analyze_attachment

def calculate_phishing_score(sender,subject,body,urls,attachment):
    ss,sf=analyze_sender(sender); cs,cf,counts=analyze_content(subject,body); us,uf,ud=analyze_urls(urls); ats,af=analyze_attachment(attachment)
    score=min(100, round(ss+cs+us+ats,1))
    if score<=20: label='LOW RISK'
    elif score<=40: label='MODERATE RISK'
    elif score<=70: label='SUSPICIOUS'
    else: label='HIGH RISK / LIKELY PHISHING'
    findings=[('Sender',x) for x in sf]+[('Content',x) for x in cf]+[('URL',x) for x in uf]+[('Attachment',x) for x in af]
    actions=['Do not click unexpected links.','Do not open unexpected attachments.','Verify the sender through a trusted channel.','Use the organization’s official website/app directly.','Report suspicious email to the security team.']
    return {'risk_score':score,'classification':label,'sender_risk_score':ss,'content_risk_score':cs,'url_risk_score':us,'attachment_risk_score':ats,'findings':findings,'url_details':ud,'recommendations':actions,'features':counts}
