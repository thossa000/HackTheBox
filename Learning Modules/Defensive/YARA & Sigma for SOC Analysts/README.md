# YARA & Sigma for SOC Analysts
Brief notes for the YARA & Sigma module in the HackTheBox Defensive Security learning path.

YARA excels in file and memory analysis, as well as pattern matching, whereas Sigma is particularly adept at log analysis and SIEM systems.
Both YARA and Sigma rules empower SOC analysts to locate and identify IOCs, which are distinct artifacts or behaviors linked to security incidents or breaches. By embedding IOCs into their rules, analysts can swiftly detect and counter potential threats

## YARA Rules
YARA rules are typically written in a rule syntax that defines the conditions and patterns to be matched within files. When applied, YARA scans files or directories and matches them against the defined rules. If a file matches a specific pattern or condition, it can trigger an alert or warrant further examination as a potential security threat.

### How Does YARA Work?
The YARA scan engine, equipped with YARA modules, scans a set of files by comparing their content against the patterns defined in a set of rules. When a file matches the patterns and conditions specified in a YARA rule, it is considered a detected file. 

<img width="1718" height="663" alt="image" src="https://github.com/user-attachments/assets/f23d04d6-6ac9-461c-9404-7549cdc51b35" />

- Set of Rules (containing suspicious patterns): First of all, we have one or more YARA rules, which are created by security analysts. These rules define specific patterns, characteristics, or indicators that need to be matched within files. Rules can include strings, regular expressions, byte sequences, and other indicators of interest. The rules are typically stored in a YARA rule file format (e.g., .yara or .yar file) for easy management and reuse.
- Set of Files (for scanning): A set of files, such as executables, documents, or other binary or text-based files, are provided as input to the YARA scan engine. The files can be stored on a local disk, within a directory, or even within memory images or network traffic captures.
- YARA Scan Engine: The YARA scan engine is the core component responsible for performing the actual scanning and matching of files against the defined YARA rules. It utilizes YARA modules, which are sets of algorithms and techniques, to efficiently compare the content of files against the patterns specified in the rules.
- Scanning and Matching: The YARA scan engine iterates through each file in the set, one at a time. For each file, it analyzes the content byte by byte, looking for matches against the patterns defined in the YARA rules. The YARA scan engine uses various matching techniques, including string matching, regular expressions, and binary matching, to identify patterns and indicators within the files.
- Detection of Files: When a file matches the patterns and conditions specified in a YARA rule, it is considered a detected file. The YARA scan engine records information about the match, such as the matched rule, the file path, and the offset within the file where the match occurred and provides output indicating the detection, which can be further processed, logged, or used for subsequent actions.

### YARA Rule Structure
