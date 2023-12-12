patterns = {
    'IP': r'(?!(?:\b0\.0\.0\.0\b|\b127\.0\.0\.1\b))\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
    'ERROR' : r'\bERROR\b|\bWARN\b|\bFAILURE\b|\bCRITICAL\b',
    'DOMAIN' : '\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,6}\b',
    'MAC' : '\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b',
    'EMAIL' : '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    'DEFAULT GATEWAY' : r'Default Gateway .+?:\s+([0-9]{1,3}(?:\.[0-9]{1,3}){3})',
    'OS_pattern' : r'OS Version:\s+([^\n\r]+)',
}

def store_vulnerabilities(file_path):
    data = []

    with open(file_path, 'r') as file:
        for line in file:
            parts = line.strip().split('|')
            if len(parts) == 3:
                path, severity, description = parts
                data.append({
                    'path': path,
                    'severity': severity,
                    'description': description
                })

    return data
