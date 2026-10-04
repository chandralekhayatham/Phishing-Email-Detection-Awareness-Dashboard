from pathlib import Path
import csv, random
random.seed(42)
root=Path(__file__).resolve().parents[1]; out=root/'data/phishing_email_dataset.csv'
legit=[('training@example.org','Cybersecurity Workshop Reminder','Hello student, this is a reminder about the cybersecurity workshop. Please check the official college portal for schedule details.'),('hr@example.com','HR Policy Update','Hello team, the updated policy document is available in the internal portal. No action is required by email.'),('news@example.net','Monthly Newsletter','Here is this month’s community newsletter with project and event updates.')]
phish=[('security-alert@account-check.invalid.test','URGENT: Verify Your Account Immediately','Urgent action required. Verify your account and confirm your password immediately or your account will be suspended.'),('billing@invoice-check.invalid.test','Invoice Payment Required','Your invoice is overdue. Make payment immediately and verify your billing details.'),('reward@winner.invalid.test','Congratulations You Have Won','You have won a reward. Confirm your personal details to claim your prize.')]
rows=[]
for i in range(600):
    if i%2==0:
        s,sub,b=random.choice(legit); rows.append([i+1,s,s.split('@')[1],sub,b,'','', 'LEGITIMATE'])
    else:
        s,sub,b=random.choice(phish); u='http://198.51.100.10/verify-account' if i%3==0 else ''; rows.append([i+1,s,s.split('@')[1],sub,b,u,'','PHISHING'])
with out.open('w',newline='',encoding='utf-8') as f: csv.writer(f).writerows([['email_id','sender','sender_domain','subject','body','urls','attachment_name','label'],*rows])
print(f'Generated {len(rows)} records at {out}')
if __name__=='__main__': pass
