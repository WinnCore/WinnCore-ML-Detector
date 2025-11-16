#!/usr/bin/env python3
"""
WinnCore ML Detector - Feature Extraction
Handles broken ELF files gracefully by wrapping ALL parsing in try-except
"""

import os
import math
from pathlib import Path
from elftools.elf.elffile import ELFFile
import pandas as pd

def calculate_entropy(data):
    """Calculate Shannon entropy of binary data"""
    if not data:
        return 0.0
    
    entropy = 0.0
    for x in range(256):
        p_x = float(data.count(bytes([x]))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy

def count_suspicious_strings(binary_data):
    """Count suspicious string patterns"""
    suspicious = [
        b'/tmp/', b'/dev/shm', b'wget', b'curl',
        b'chmod', b'sh -c', b'/bin/sh', b'exec',
        b'LD_PRELOAD', b'setuid', b'ptrace'
    ]
    count = sum(1 for s in suspicious if s in binary_data)
    return count

def extract_feature_row(binary_path, label):
    """
    Extract features from a single ELF binary
    
    CRITICAL: Entire function wrapped in try-except to handle any ELF parsing errors
    Returns None if file cannot be parsed (broken ELF structure)
    """
    try:
        # Read binary data
        with open(binary_path, 'rb') as f:
            binary_data = f.read()
        
        # Parse ELF structure - this can fail in many ways with broken files
        with open(binary_path, 'rb') as f:
            elf = ELFFile(f)
            
            # Helper function to safely get section size
            def safe_section_size(name):
                try:
                    section = elf.get_section_by_name(name)
                    return section['sh_size'] if section else 0
                except:
                    return 0
            
            # Helper function to safely count symbols
            def safe_symbol_count(section_name):
                try:
                    section = elf.get_section_by_name(section_name)
                    return len(list(section.iter_symbols())) if section else 0
                except:
                    return 0
            
            # Extract all features
            features = {
                # File characteristics
                'file_size': len(binary_data),
                'entropy': calculate_entropy(binary_data),
                'entry_point': elf.header['e_entry'],
                
                # ELF structure
                'num_sections': elf.num_sections(),
                'num_segments': len(list(elf.iter_segments())),
                
                # Section sizes
                'text_size': safe_section_size('.text'),
                'data_size': safe_section_size('.data'),
                'rodata_size': safe_section_size('.rodata'),
                'bss_size': safe_section_size('.bss'),
                
                # Symbols
                'num_dynsym': safe_symbol_count('.dynsym'),
                'num_symtab': safe_symbol_count('.symtab'),
                
                # Security flags
                'is_stripped': 1 if safe_symbol_count('.symtab') == 0 else 0,
                'is_pie': 1 if elf.header['e_type'] == 'ET_DYN' else 0,
                
                # Malicious indicators
                'suspicious_strings': count_suspicious_strings(binary_data),
                
                # Label
                'label': label
            }
            
            return features
            
    except Exception as e:
        # Skip any file that can't be parsed - don't crash the entire job
        # This is NORMAL for malformed malware samples
        print(f"  ⚠️  SKIP: {Path(binary_path).name} ({type(e).__name__})")
        return None

def main():
    """
    Extract features from all sample directories
    """
    
    # Define sample directories - UPDATED to match actual structure
    sample_dirs = [
        ('data/benign', 0),              # Benign system binaries
        ('real-malware-safe', 1),        # Real malware samples (if exists)
        ('synthetic-malware', 1),        # Synthetic malware
        ('compiled-malware', 1),         # NEW: Compiled malware patterns
    ]
    
    all_features = []
    total_processed = 0
    total_skipped = 0
    
    for directory, label in sample_dirs:
        if not os.path.exists(directory):
            print(f"⚠️  Directory not found: {directory}")
            continue
        
        files = list(Path(directory).glob("*"))
        if not files:
            continue
            
        print(f"\n[+] Processing {directory} (label={label})")
        print(f"    Found {len(files)} files")
        
        processed_in_dir = 0
        skipped_in_dir = 0
        
        for binary in files:
            if not binary.is_file():
                continue
                
            features = extract_feature_row(binary, label)
            if features is not None:
                all_features.append(features)
                processed_in_dir += 1
                total_processed += 1
                
                # Progress indicator
                if processed_in_dir % 200 == 0:
                    print(f"    ... processed {processed_in_dir}/{len(files)}")
            else:
                skipped_in_dir += 1
                total_skipped += 1
        
        print(f"    ✓ Processed: {processed_in_dir}, Skipped: {skipped_in_dir}")
    
    # Create DataFrame and save
    df = pd.DataFrame(all_features)
    df.to_csv('features.csv', index=False)
    
    benign_count = len(df[df['label'] == 0])
    malware_count = len(df[df['label'] == 1])
    
    print(f"\n{'='*60}")
    print(f"FEATURE EXTRACTION COMPLETE")
    print(f"{'='*60}")
    print(f"Total processed:   {total_processed:,}")
    print(f"Total skipped:     {total_skipped:,}")
    print(f"Benign samples:    {benign_count:,} ({benign_count/len(df)*100:.1f}%)")
    print(f"Malware samples:   {malware_count:,} ({malware_count/len(df)*100:.1f}%)")
    print(f"Features:          {len(df.columns) - 1}")
    print(f"Output:            features.csv")
    print(f"{'='*60}")

if __name__ == '__main__':
    main()
