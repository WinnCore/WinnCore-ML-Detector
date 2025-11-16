#!/usr/bin/env python3
"""Extract features from bash scripts for LOTL detection"""

import os
import re
from pathlib import Path
import csv

def extract_script_features(script_path):
    """Extract features from bash script"""
    try:
        with open(script_path, 'r') as f:
            content = f.read()
        
        features = {}
        
        # File size
        features['file_size'] = len(content)
        
        # Command counts
        features['pipe_count'] = content.count('|')
        features['redirect_count'] = content.count('>') + content.count('<')
        features['curl_wget_count'] = content.count('curl') + content.count('wget')
        features['nc_netcat_count'] = content.count('nc ') + content.count('netcat')
        features['bash_sh_count'] = content.count('bash') + content.count('sh ')
        features['eval_exec_count'] = content.count('eval') + content.count('exec')
        
        # Suspicious patterns
        features['reverse_shell'] = 1 if '/dev/tcp' in content or 'nc -e' in content else 0
        features['base64_encoding'] = 1 if 'base64' in content else 0
        features['credential_access'] = 1 if '/etc/shadow' in content or '/etc/passwd' in content else 0
        features['ssh_usage'] = 1 if 'ssh ' in content else 0
        features['cron_systemd'] = 1 if 'cron' in content or 'systemd' in content else 0
        features['sudo_usage'] = 1 if 'sudo' in content else 0
        features['hidden_files'] = 1 if re.search(r'/\.[\w]+', content) else 0
        
        # Network indicators
        features['has_ip_address'] = 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', content) else 0
        features['has_port'] = 1 if re.search(r':\d{2,5}', content) else 0
        
        # String analysis
        features['script_length'] = len(content)
        features['line_count'] = content.count('\n')
        features['comment_ratio'] = content.count('#') / max(1, features['line_count'])
        
        # Command chaining
        features['semicolon_count'] = content.count(';')
        features['ampersand_count'] = content.count('&')
        
        # Obfuscation indicators
        features['hex_encoding'] = 1 if '\\x' in content else 0
        features['long_lines'] = 1 if any(len(line) > 200 for line in content.split('\n')) else 0
        
        return features
    except Exception as e:
        print(f"Error processing {script_path}: {e}")
        return None

def main():
    print("📊 Extracting features from LOTL bash scripts...")
    
    output_file = "lotl_features.csv"
    
    # Get all bash scripts
    lotl_dir = Path("synthetic-malware/lotl-attacks")
    benign_scripts_dir = Path("data/benign-scripts")
    
    all_samples = []
    
    # LOTL attacks (malicious)
    if lotl_dir.exists():
        for script in lotl_dir.glob("*.sh"):
            all_samples.append((script, 1))  # label=1 (malicious)
    
    # Benign scripts
    if benign_scripts_dir.exists():
        for script in benign_scripts_dir.glob("*.sh"):
            all_samples.append((script, 0))  # label=0 (benign)
    
    print(f"Found {len(all_samples)} samples")
    
    # Extract features
    rows = []
    for script_path, label in all_samples:
        features = extract_script_features(script_path)
        if features:
            row = features.copy()
            row['label'] = label
            row['path'] = str(script_path)
            rows.append(row)
    
    # Write to CSV
    if rows:
        fieldnames = list(rows[0].keys())
        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        
        print(f"✅ Extracted {len(rows)} feature vectors")
        print(f"📁 Output: {output_file}")
    else:
        print("❌ No features extracted")

if __name__ == "__main__":
    main()
