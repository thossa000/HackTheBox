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
YARA rule example:

```
rule my_rule {

    meta:
        author = "Author Name"
        description = "example rule"
        hash = ""
    
    strings: 
        $string1 = "test"
        $string2 = "rule"
        $string3 = "htb"

    condition: 
        all of them
} 
```

Each rule in YARA starts with the keyword rule followed by a rule identifier. Rule identifiers are case sensitive where the first character cannot be a digit, and cannot exceed 128 characters.

The following keywords are reserved and cannot be used as an identifier:

<img width="1366" height="456" alt="image" src="https://github.com/user-attachments/assets/361d5d20-ca19-4da2-97e8-cea2827ed115" />

The rule below instructs YARA to flag any file containing all three specified strings as Ransomware_WannaCry.

```
rule Ransomware_WannaCry {

    meta:
        author = "Madhukar Raina"
        version = "1.0"
        description = "Simple rule to detect strings from WannaCry ransomware"
        reference = "https://www.virustotal.com/gui/file/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa/behavior" 
    
    strings:
        $wannacry_payload_str1 = "tasksche.exe" fullword ascii
        $wannacry_payload_str2 = "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii
        $wannacry_payload_str3 = "mssecsvc.exe" fullword ascii
    
    condition:
        all of them
}
```

Rule Header: The rule header provides metadata and identifies the rule. It typically includes:

- Rule name: A descriptive name for the rule.
- Rule tags: Optional tags or labels to categorize the rule.
- Rule metadata: Additional information such as author, description, and creation date.

```
rule Ransomware_WannaCry {
    meta:
  ...
}  
```

Rule Meta: The rule meta section allows for the definition of additional metadata for the rule. This metadata can include information about the rule's author, references, version, etc.

```
rule Ransomware_WannaCry {
    meta:
        author = "Madhukar Raina"
        version = "1.0"
        description = "Simple rule to detect strings from WannaCry ransomware"
        reference = 	"https://www.virustotal.com/gui/file/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa/behavior" 
    ...
}
```

Rule Body: The rule body contains the patterns or indicators to be matched within the files. This is where the actual detection logic is defined.

```
rule Ransomware_WannaCry {

    ...    

    strings:
        $wannacry_payload_str1 = "tasksche.exe" fullword ascii
        $wannacry_payload_str2 = "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii
        $wannacry_payload_str3 = "mssecsvc.exe" fullword ascii

    ...

}
```

Rule Conditions: Rule conditions define the context or characteristics of the files to be matched. Conditions can be based on file properties, strings, or other indicators. Conditions are specified within the condition section.

```
rule Ransomware_WannaCry {
    ...

    condition:
        all of them
}
```
In this YARA rule, the condition section simply states all of them, which means that all the strings defined in the rule must be present for the rule to trigger a match.

One more example of a condition which specifies that the file size of the analyzed file must be less than 100 kilobytes (KB).
```
 condition:
        filesize < 100KB and (uint16(0) == 0x5A4D or uint16(0) == 0x4D5A)
```
This condition also specifies that the first 2 bytes of the file must be either 0x5A4D (ASCII MZ) or 0x4D5A (ASCII ZM), by using uint16(0):
```
uint16(offset)
```

- uint16: This indicates the data type to be extracted, which is a 16-bit unsigned integer (2 bytes).
- (0): The value inside the parentheses represents the offset from where the extraction should start. In this case, 0 means the function will extract the 16-bit value starting from the beginning of the data being scanned. The condition uses uint16(0) to compare the first 2 bytes of the file with specific values.
