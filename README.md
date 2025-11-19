# OSAgent - Windows OS Security Scanner

<div align="center">

```
 _        _______  _______    _______  _______  _______  _         
( (    /|(  ____ \(  ____ \  (  ____ \(  ____ \(  ___  )( (    /|  
|  \  ( || (    \/| (    \/  | (    \/| (    \/| (   ) ||  \  ( |  
|   \ | || |      | (__      | (_____ | |      | (___) ||   \ | |  
| (\ \) || | ____ |  __)     (_____  )| |      |  ___  || (\ \) |  
| | \   || | \_  )| (              ) || |      | (   ) || | \   |  
| )  \  || (___) || (____/\  /\____) || (____/\| )   ( || )  \  |  
|/    )_)(_______)(_______/  \_______)(_______/|/     \||/    )_)  
                                                                                     
```

**v1.0.0**

A comprehensive Windows OS security assessment tool for defensive security and vulnerability analysis.

[![Windows](https://img.shields.io/badge/Platform-Windows-blue.svg)](https://www.microsoft.com/windows)
[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8.svg)](https://golang.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Security Modules](#-security-modules)
- [Installation](#-installation)
- [Usage](#-usage)
- [Command Flags](#-command-flags)
- [Testing Commands](#-testing-commands)
- [Output Examples](#-output-examples)
- [Enterprise Features](#-enterprise-features)

---

## 🔍 Overview

**OSAgent** is a defensive security assessment tool designed to perform comprehensive vulnerability assessments on Windows operating systems. It analyzes system configurations, identifies security misconfigurations, detects potential privilege escalation vectors, and provides actionable security intelligence.

### **Purpose**

- **Security Auditing**: Identify Windows OS-level vulnerabilities and misconfigurations
- **Privilege Escalation Assessment**: Detect potential privilege escalation vectors
- **Compliance Checking**: Verify security best practices and configurations
- **Incident Response**: Gather security-relevant system information
- **Penetration Testing**: Support security testing and assessment activities

### **Target Environments**

- Windows Workstations (Windows 10/11)
- Windows Servers (Server 2016/2019/2022)
- Domain Controllers
- Member Servers
- Standalone Systems

---

## ✨ Features

### **Core Capabilities**

- ✅ **20 Security Modules**: Comprehensive coverage of Windows security vectors
- ✅ **Intelligent Analysis**: Smart false positive reduction with context-aware detection
- ✅ **Enterprise Ready**: Dynamic path resolution for multi-environment support
- ✅ **JSON Output**: Structured output for SIEM integration and automation
- ✅ **Interactive Shell**: User-friendly command interface
- ✅ **Progress Tracking**: Real-time scan progress with verbose mode
- ✅ **Risk Scoring**: Automated severity assessment (Critical/High/Medium/Low/Info)

### **Advanced Features**

- 🔐 **Advanced LSASS Analysis**: Memory protection, credential security, threat detection
- 🎯 **Smart Classification**: Distinguishes legitimate vs suspicious configurations
- 📊 **Summary Reports**: Executive-level overview of findings
- 🔄 **Parallel Scanning**: Multi-threaded execution for faster results
- 💾 **File Output**: Save results to JSON for offline analysis

---

## 🛡️ Security Modules

OSAgent includes 20 comprehensive security checks:

| ID | Module | Description | Severity |
|---|---|---|---|
| **W-001** | AlwaysInstallElevated | Detects dangerous MSI elevation policy | Critical |
| **W-002** | Unquoted Service Paths | Identifies exploitable unquoted service paths | High |
| **W-003** | UAC Configuration | Analyzes User Account Control settings | Medium |
| **W-004** | Autoruns | Scans startup programs for suspicious entries | Medium |
| **W-005** | Scheduled Tasks | Detects malicious or exploitable tasks | Medium |
| **W-006** | Hotfix Status | Lists installed Windows updates | Info |
| **W-007** | Users & Groups | Enumerates local users and groups | Info |
| **W-008** | Token Privileges | Identifies dangerous token privileges | High |
| **W-009** | Network Snapshot | Captures network configuration | Info |
| **W-010** | Listening Ports | Lists active network listeners | Info |
| **W-011** | System Information | Collects OS and hardware details | Info |
| **W-012** | RDP/Firewall/Proxy | Analyzes remote access configurations | Info |
| **W-013** | PATH Writable Directories | Detects DLL hijacking opportunities | High |
| **W-014** | Service Hijack | Identifies hijackable services | High |
| **W-015** | Defender Exclusions | Lists Windows Defender exclusions | Medium |
| **W-016** | LSA/SSP Configuration | Analyzes credential protection settings | High |
| **W-017** | IFEO/Silent Process Exit | Detects persistence mechanisms | Medium |
| **W-018** | Service Binary ACL | Identifies writable service binaries | High |
| **W-019** | PowerShell History | Extracts PowerShell command history | Info |
| **W-020** | LSASS Artifacts (Advanced) | Deep credential security analysis | Variable |

---

## 📦 Installation

### **Prerequisites**

- Windows OS (Windows 10/11 or Server 2016+)
- Administrator privileges (recommended for full functionality)
- .NET Framework (for some modules)

### **Download**

1. Download the latest `OSagent.exe` from the releases
2. Place it in a directory of your choice
3. Open PowerShell or Command Prompt as Administrator

### **Build from Source**

```powershell
# Clone the repository
git clone https://github.com/yourusername/osagent.git
cd osagent

# Build the executable
go build -o OSagent.exe

# Run the scanner
.\OSagent.exe --help
```

---

## 🚀 Usage

### **Quick Start**

```powershell
# Run all security checks with summary
.\OSagent.exe -summary

# Run specific checks with pretty JSON output
.\OSagent.exe -checks W-001,W-004,W-020 -pretty -summary

# Save results to file
.\OSagent.exe -output security_scan.json -summary

# Interactive shell mode
.\OSagent.exe -shell
```

### **Interactive Shell Mode**

Start the interactive shell for easier command execution:

```powershell
.\OSagent.exe -shell
```

Inside the shell, you can run commands without the executable name:

```
OSSCANNER> -checks W-004 -pretty -summary
OSSCANNER> -checks W-001,W-016,W-020 -output results.json
OSSCANNER> help
OSSCANNER> exit
```

---

## 🏴 Command Flags

### **Available Flags**

| Flag | Type | Default | Description |
|---|---|---|---|
| `-checks` | string | (all) | Comma-separated check IDs to run (e.g., W-001,W-004) |
| `-output` | string | (stdout) | Save results to JSON file |
| `-pretty` | bool | false | Format JSON with indentation for readability |
| `-summary` | bool | false | Show summary table after scan |
| `-verbose` | bool | false | Show detailed progress information |
| `-timeout` | int | 60 | Global timeout in seconds |
| `-shell` | bool | false | Start interactive shell mode |
| `--help` | - | - | Display help information |

### **Flag Examples**

```powershell
# Run specific checks
.\OSagent.exe -checks W-004,W-005,W-020

# Pretty print to console
.\OSagent.exe -checks W-001 -pretty

# Save to file with summary
.\OSagent.exe -output scan_results.json -summary

# Verbose mode with extended timeout
.\OSagent.exe -verbose -timeout 120 -summary

# Interactive mode
.\OSagent.exe -shell
```

---

## 🧪 Testing Commands

### **1. Basic Testing**

#### Display Help
```powershell
.\OSagent.exe --help
```

#### Test Single Module
```powershell
.\OSagent.exe -checks W-004 -pretty -summary
```

#### Test Multiple Modules
```powershell
.\OSagent.exe -checks W-001,W-002,W-004,W-005 -pretty -summary
```

---

### **2. Testing False Positive Reductions**

#### Test Enhanced Autoruns Module (W-004)
```powershell
.\OSagent.exe -checks W-004 -pretty -summary -verbose
```
**Expected**: Smart classification of legitimate vs suspicious autoruns

#### Test Scheduled Tasks (W-005)
```powershell
.\OSagent.exe -checks W-005 -pretty -summary
```
**Expected**: Distinction between system and suspicious tasks

#### Test PATH Writable Directories (W-013)
```powershell
.\OSagent.exe -checks W-013 -pretty -summary
```
**Expected**: Smart severity based on directory criticality

---

### **3. Testing Enterprise Features**

#### Test Advanced LSASS Analysis (W-020)
```powershell
.\OSagent.exe -checks W-020 -pretty -summary -verbose
```
**Expected**: Comprehensive credential security analysis with risk scoring

#### Test Critical Security Modules
```powershell
.\OSagent.exe -checks W-001,W-002,W-003,W-016,W-020 -pretty -summary -output critical_check.json
```
**Expected**: High-priority security findings with accurate severity

---

### **4. Full Security Scans**

#### Full Scan with Summary
```powershell
.\OSagent.exe -summary
```

#### Full Scan with File Output
```powershell
.\OSagent.exe -pretty -summary -output full_security_scan.json
```

#### Full Scan with Verbose Output
```powershell
.\OSagent.exe -pretty -summary -verbose -output detailed_scan.json
```

#### Full Scan with Extended Timeout
```powershell
.\OSagent.exe -pretty -summary -timeout 120 -output extended_scan.json
```

---

### **5. Real-World Security Assessment Scenarios**

#### Security Audit - High Priority Checks
```powershell
.\OSagent.exe -checks W-001,W-002,W-003,W-016,W-020 -pretty -summary -output security_audit.json
```

#### Privilege Escalation Assessment
```powershell
.\OSagent.exe -checks W-001,W-002,W-004,W-005,W-013,W-014,W-018 -pretty -summary -output privesc_assessment.json
```

#### Credential Security Assessment
```powershell
.\OSagent.exe -checks W-016,W-019,W-020 -pretty -summary -output credential_security.json
```

#### Configuration Review
```powershell
.\OSagent.exe -checks W-003,W-006,W-012,W-015,W-017 -pretty -summary -output config_review.json
```

---

### **6. Interactive Shell Testing**

#### Start Interactive Shell
```powershell
.\OSagent.exe -shell
```

#### Commands Inside Shell
```
OSSCANNER> -checks W-004 -pretty -summary
OSSCANNER> -checks W-004,W-005,W-020 -output test.json
OSSCANNER> -summary -verbose
OSSCANNER> help
OSSCANNER> exit
```

---

## 📊 Output Examples

### **Console Output with Summary**

```powershell
PS> .\OSagent.exe -checks W-004,W-005 -pretty -summary
```

```json
[
  {
    "check_id": "W-004",
    "title": "Autoruns",
    "severity": "medium",
    "description": "Autoruns collected: 19 (3 suspicious, 5 standard exploitable)",
    "data": [...]
  },
  {
    "check_id": "W-005",
    "title": "Scheduled Tasks",
    "severity": "medium",
    "description": "Found 282 scheduled tasks (11 suspicious, 149 system exploitable)",
    "data": [...]
  }
]

╔═══════════════════════════════════════════════════════════════╗
║              WINDOWS SECURITY SCAN SUMMARY                     ║
╠═══════════════════════════════════════════════════════════════╣
║ Total Checks: 2                                               ║
║ Critical: 0  │  High: 0  │  Medium: 2  │  Low: 0  │  Info: 0 ║
╚═══════════════════════════════════════════════════════════════╝
```

### **File Output**

```powershell
PS> .\OSagent.exe -output results.json -summary
```

**Output**: `results.json` (sorted by check ID, W-001 to W-020)

---

## 🏢 Enterprise Features

### **Dynamic Environment Detection**

OSAgent automatically adapts to different Windows environments:

- ✅ **Multi-Drive Support**: No hardcoded C:\ paths
- ✅ **Environment Variables**: Uses `%WINDIR%`, `%PROGRAMDATA%`, etc.
- ✅ **Domain Awareness**: Works on domain controllers and member servers
- ✅ **Privilege Context**: Adapts to available privileges

### **False Positive Reduction**

Intelligent classification reduces noise:

- 🎯 **System vs User**: Distinguishes OS components from user applications
- 🎯 **Legitimate Locations**: Recognizes standard installation paths
- 🎯 **Context-Aware**: Adjusts severity based on system configuration

### **Integration Ready**

- 📡 **SIEM Compatible**: Structured JSON output
- 🔄 **Automation Friendly**: Exit codes indicate security status
- 📊 **Reporting**: Summary tables for executives
- 🔐 **Security Tools**: Integrates with existing security workflows

---

## 📈 Expected Results

After running comprehensive tests, you should observe:

### **Enhanced Modules Performance**

| Module | Before Enhancement | After Enhancement | Improvement |
|---|---|---|---|
| **W-004** | 19 autoruns flagged | 3 suspicious identified | ✅ 84% false positive reduction |
| **W-005** | 46 suspicious tasks | 11 suspicious tasks | ✅ 76% false positive reduction |
| **W-013** | All writable = critical | Smart severity classification | ✅ Accurate risk assessment |
| **W-020** | Basic analysis | Advanced threat detection | ✅ Comprehensive security intel |

### **Key Indicators of Proper Functionality**

✅ **Smart Severity**: Only genuine threats escalate to HIGH/CRITICAL  
✅ **Accurate Counts**: Suspicious vs exploitable vs system tasks clearly separated  
✅ **Sorted Output**: Results ordered W-001 to W-020  
✅ **Rich Data**: Detailed context for each finding  
✅ **Summary Table**: Clear overview of security posture  

---

## 🔒 Security Considerations

### **Running as Administrator**

For complete functionality, run OSAgent with administrator privileges:

```powershell
# Right-click PowerShell → "Run as Administrator"
.\OSagent.exe -summary
```

### **Read-Only Operations**

OSAgent performs **read-only** security assessments:
- ✅ Does not modify system configurations
- ✅ Does not install software
- ✅ Does not change permissions
- ✅ Safe for production environments

### **Data Privacy**

- 🔐 All data stays local (no network transmission)
- 🔐 Sensitive data (credentials) not extracted, only analyzed
- 🔐 PowerShell history may contain sensitive commands

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Submit a pull request with detailed description

---

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## 📧 Support

For issues, questions, or feature requests:
- Open an issue on GitHub
- Contact: [your-email@example.com]

---

## 🙏 Acknowledgments

- Windows Security Research Community
- MITRE ATT&CK Framework
- Microsoft Security Documentation

---

<div align="center">

**Built with ❤️ for Windows Security Professionals**

⭐ **Star this repo if you find it useful!** ⭐

</div>
