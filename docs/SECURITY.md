# Security & Privacy
- Synthetic/authorized data only.
- No credential collection.
- Suspicious URLs are never automatically visited.
- Attachments are never executed; only filenames are inspected.
- Email bodies are not stored by default; analysis history stores safe metadata.
- Validate inputs and avoid rendering raw email HTML.
- Production deployments should use HTTPS, authentication, authorization, rate limits, and secure secret management.
