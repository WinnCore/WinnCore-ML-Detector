use anyhow::{Context, Result};
use capstone::prelude::*;
use chrono::Utc;
use clap::Parser;
use goblin::elf::Elf;
use log::{info, warn};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// ARM64 binary feature extractor for malware detection
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Directory containing ARM64 binaries to analyze
    #[arg(short, long)]
    input: PathBuf,

    /// Output JSONL file path
    #[arg(short, long)]
    output: PathBuf,

    /// Label for these samples (0=benign, 1=malicious)
    #[arg(short, long)]
    label: u8,

    /// Source identifier (e.g., "ubuntu_packages", "internal_sandbox")
    #[arg(short, long, default_value = "unknown")]
    source: String,

    /// Only process ARM64/AArch64 binaries
    #[arg(long, default_value = "true")]
    arm64_only: bool,
}

/// Feature vector extracted from a binary
/// These are the features the ML model will train on
#[derive(Debug, Serialize, Deserialize)]
struct BinaryFeatures {
    // Identification
    sha256: String,
    label: u8,
    arch: String,
    source: String,
    timestamp: String,

    // File-level features
    file_size: u64,
    entropy: f64, // Shannon entropy - measures randomness/packing

    // ELF header features
    entry_point: u64,
    num_sections: usize,
    num_program_headers: usize,
    is_stripped: bool, // Are debugging symbols removed?
    is_dynamic: bool,  // Dynamically linked?
    is_pie: bool,      // Position-independent executable?

    // Section features
    has_executable_stack: bool,
    has_writable_code: bool, // W^X violation indicator
    text_section_size: u64,
    data_section_size: u64,
    rodata_section_size: u64,
    bss_section_size: u64,

    // Symbol/import features
    num_imports: usize,
    num_exports: usize,
    num_dynamic_symbols: usize,

    // Disassembly features (ARM64-specific)
    instruction_count: usize,
    branch_count: usize,
    load_store_count: usize,
    syscall_count: usize,
    crypto_instruction_count: usize, // AES, SHA, etc.
    simd_instruction_count: usize,   // NEON SIMD instructions
    
    // Suspicious patterns
    has_self_modifying_code_pattern: bool,
    has_anti_debug_patterns: bool,
    suspicious_string_count: usize,
}

impl Default for BinaryFeatures {
    fn default() -> Self {
        Self {
            sha256: String::new(),
            label: 0,
            arch: String::from("aarch64"),
            source: String::new(),
            timestamp: Utc::now().to_rfc3339(),
            file_size: 0,
            entropy: 0.0,
            entry_point: 0,
            num_sections: 0,
            num_program_headers: 0,
            is_stripped: false,
            is_dynamic: false,
            is_pie: false,
            has_executable_stack: false,
            has_writable_code: false,
            text_section_size: 0,
            data_section_size: 0,
            rodata_section_size: 0,
            bss_section_size: 0,
            num_imports: 0,
            num_exports: 0,
            num_dynamic_symbols: 0,
            instruction_count: 0,
            branch_count: 0,
            load_store_count: 0,
            syscall_count: 0,
            crypto_instruction_count: 0,
            simd_instruction_count: 0,
            has_self_modifying_code_pattern: false,
            has_anti_debug_patterns: false,
            suspicious_string_count: 0,
        }
    }
}

/// Calculate SHA-256 hash of a file
fn calculate_sha256(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path)?;
    let hash = Sha256::digest(&bytes);
    Ok(hex::encode(hash))
}

/// Calculate Shannon entropy of byte data
/// Higher entropy (closer to 8.0) indicates encryption/packing
fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u32; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &counts {
        if count > 0 {
            let probability = count as f64 / len;
            entropy -= probability * probability.log2();
        }
    }

    entropy
}

/// Extract features from an ARM64 ELF binary
fn extract_features(
    path: &Path,
    label: u8,
    source: &str,
    arm64_only: bool,
) -> Result<BinaryFeatures> {
    // Read the binary file
    let bytes = std::fs::read(path)
        .with_context(|| format!("Failed to read file: {}", path.display()))?;

    // Parse ELF structure
    let elf = Elf::parse(&bytes)
        .with_context(|| format!("Failed to parse ELF: {}", path.display()))?;

    // Check if it's ARM64/AArch64
    if arm64_only && elf.header.e_machine != goblin::elf::header::EM_AARCH64 {
        anyhow::bail!("Not an ARM64 binary (machine type: {})", elf.header.e_machine);
    }

    let mut features = BinaryFeatures {
        sha256: calculate_sha256(path)?,
        label,
        source: source.to_string(),
        timestamp: Utc::now().to_rfc3339(),
        file_size: bytes.len() as u64,
        entropy: calculate_entropy(&bytes),
        entry_point: elf.header.e_entry,
        num_sections: elf.section_headers.len(),
        num_program_headers: elf.program_headers.len(),
        ..Default::default()
    };

    // Check if stripped (no symbol table)
    features.is_stripped = elf.syms.is_empty();

    // Check dynamic linking
    features.is_dynamic = elf.dynamic.is_some();

    // Check if PIE (Position Independent Executable)
    features.is_pie = elf.header.e_type == goblin::elf::header::ET_DYN;

    // Analyze sections
    for section in &elf.section_headers {
        let section_name = elf.shdr_strtab.get_at(section.sh_name).unwrap_or("");
        let section_size = section.sh_size;

        match section_name {
            ".text" => features.text_section_size = section_size,
            ".data" => features.data_section_size = section_size,
            ".rodata" => features.rodata_section_size = section_size,
            ".bss" => features.bss_section_size = section_size,
            _ => {}
        }

        // Check for writable + executable sections (security risk)
        let is_writable = (section.sh_flags as u32) & goblin::elf::section_header::SHF_WRITE != 0;
        let is_executable = (section.sh_flags as u32) & goblin::elf::section_header::SHF_EXECINSTR != 0;
        
        if is_writable && is_executable {
            features.has_writable_code = true;
        }

        // Check for executable stack
        if section_name == ".stack" && is_executable {
            features.has_executable_stack = true;
        }
    }

    // Count symbols
    features.num_imports = elf.dynsyms.len();
    features.num_exports = elf.syms.len();
    features.num_dynamic_symbols = elf.dynsyms.len();

    // Disassemble and analyze instructions
    if let Some(text_section) = find_section(&elf, &bytes, ".text") {
        analyze_instructions(&text_section, &mut features)?;
    }

    // Check for suspicious strings
    features.suspicious_string_count = count_suspicious_strings(&bytes);

    Ok(features)
}

/// Find a section's data by name
fn find_section<'a>(elf: &Elf, bytes: &'a [u8], name: &str) -> Option<&'a [u8]> {
    for section in &elf.section_headers {
        if let Some(section_name) = elf.shdr_strtab.get_at(section.sh_name) {
            if section_name == name {
                let start = section.sh_offset as usize;
                let end = start + section.sh_size as usize;
                return Some(&bytes[start..end]);
            }
        }
    }
    None
}

/// Disassemble ARM64 code and count instruction patterns
fn analyze_instructions(code: &[u8], features: &mut BinaryFeatures) -> Result<()> {
    // Initialize Capstone disassembler for ARM64
    let cs = Capstone::new()
        .arm64()
        .mode(arch::arm64::ArchMode::Arm)
        .detail(true)
        .build()
        .context("Failed to create Capstone instance")?;

    // Disassemble the .text section
    let insns = cs
        .disasm_all(code, 0x1000)
        .context("Failed to disassemble code")?;

    features.instruction_count = insns.len();

    // Analyze each instruction
    for insn in insns.iter() {
        let mnemonic = insn.mnemonic().unwrap_or("");

        // Count branch instructions
        if mnemonic.starts_with('b') || mnemonic == "bl" || mnemonic == "blr" {
            features.branch_count += 1;
        }

        // Count load/store instructions
        if mnemonic.starts_with("ld") || mnemonic.starts_with("st") {
            features.load_store_count += 1;
        }

        // Count syscall instructions
        if mnemonic == "svc" {
            features.syscall_count += 1;
        }

        // Count crypto instructions (ARM64 crypto extensions)
        if matches!(
            mnemonic,
            "aese" | "aesd" | "aesmc" | "aesimc" | "sha1c" | "sha1p" | "sha1m" | "sha256h"
        ) {
            features.crypto_instruction_count += 1;
        }

        // Count SIMD/NEON instructions
        if mnemonic.starts_with('v') || mnemonic.contains("fmov") {
            features.simd_instruction_count += 1;
        }
    }

    // Detect self-modifying code patterns
    // (writes to executable sections)
    if features.has_writable_code {
        features.has_self_modifying_code_pattern = true;
    }

    Ok(())
}

/// Count suspicious strings in the binary
fn count_suspicious_strings(bytes: &[u8]) -> usize {
    let suspicious_patterns: &[&[u8]] = &[
        b"/bin/sh",
        b"/bin/bash",
        b"curl",
        b"wget",
        b"http://",
        b"https://",
        b"exec",
        b"system",
        b"ptrace",
        b"LD_PRELOAD",
        b"password",
        b"passwd",
        b".onion",
    ];

    let mut count = 0;
    for pattern in suspicious_patterns {
        count += bytes
            .windows(pattern.len())
            .filter(|window| window == pattern)
            .count();
    }
    count
}

fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    info!("Starting ARM64 feature extraction");
    info!("Input directory: {}", args.input.display());
    info!("Output file: {}", args.output.display());
    info!("Label: {}", args.label);

    // Open output file
    let output_file = File::create(&args.output)
        .with_context(|| format!("Failed to create output file: {}", args.output.display()))?;
    let mut writer = BufWriter::new(output_file);

    // Walk through input directory
    let mut processed = 0;
    let mut errors = 0;

    for entry in WalkDir::new(&args.input)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();

        // Skip directories
        if !path.is_file() {
            continue;
        }

        // Try to extract features
        match extract_features(path, args.label, &args.source, args.arm64_only) {
            Ok(features) => {
                // Write features as a JSON line
                serde_json::to_writer(&mut writer, &features)?;
                writeln!(&mut writer)?;
                processed += 1;

                if processed % 100 == 0 {
                    info!("Processed {} binaries", processed);
                }
            }
            Err(e) => {
                warn!("Failed to process {}: {}", path.display(), e);
                errors += 1;
            }
        }
    }

    writer.flush()?;

    info!("Extraction complete!");
    info!("Processed: {} binaries", processed);
    info!("Errors: {} files", errors);
    info!("Output: {}", args.output.display());

    Ok(())
}
