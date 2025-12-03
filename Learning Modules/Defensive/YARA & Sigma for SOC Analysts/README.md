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

## Developing YARA Rules
yarGen is our go-to tool when we need an automatic YARA rule generator. What makes it a gem is its ability to churn out YARA rules based on strings found in malicious files while sidestepping strings common in benign software. This is possible because yarGen comes equipped with a vast database of goodware strings and opcodes. Before diving in, we need to unpack the ZIP archives containing these databases.

Here's how we get yarGen up and running:

- Download the latest release from the release section
- Install all dependencies with pip install -r requirements.txt
- Run python yarGen.py --update to automatically download the built-in databases. They will be saved into the './dbs' subfolder
- See help with python yarGen.py --help for more information on the command line parameters

Let's place our sample in a temp directory (there is one available at /home/htb-student/temp inside this section's target) and specify the path using the following command-line arguments.

```
thossa00@htb[/htb]$ python3 yarGen.py -m /home/htb-student/temp -o htb_sample.yar
```

Command Breakdown:

- yarGen.py: This is the name of the yarGen Python script that will be executed.
- -m /home/htb-student/temp: This option specifies the source directory where the sample files (e.g., malware or suspicious files) are located. The script will analyze these samples to generate YARA rules.
- -o htb_sample.yar: This option indicates the output file name for the generated YARA rules. In this case, the YARA rules will be saved to a file named htb_sample.yar.

The resulting YARA rules will be written to the htb_sample.yar:

```
thossa00@htb[/htb]$ cat htb_sample.yar
/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2023-08-24
   Identifier: temp
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule dharma_sample {
   meta:
      description = "temp - file dharma_sample.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-24"
      hash1 = "bff6a1000a86f8edf3673d576786ec75b80bed0c458a8ca0bd52d12b74099071"
   strings:
      $x1 = "C:\\crysis\\Release\\PDB\\payload.pdb" fullword ascii
      $s2 = "sssssbs" fullword ascii
      $s3 = "sssssbsss" fullword ascii
      $s4 = "RSDS%~m" fullword ascii
      $s5 = "{RDqP^\\" fullword ascii
      $s6 = "QtVN$0w" fullword ascii
      $s7 = "Ffsc<{" fullword ascii
      $s8 = "^N3Y.H_K" fullword ascii
      $s9 = "tb#w\\6" fullword ascii
      $s10 = "-j6EPUc" fullword ascii
      $s11 = "8QS#5@3" fullword ascii
      $s12 = "h1+LI;d8" fullword ascii
      $s13 = "H;B cl" fullword ascii
      $s14 = "Wy]z@p]E" fullword ascii
      $s15 = "ipgypA" fullword ascii
      $s16 = "+>^wI{H" fullword ascii
      $s17 = "mF@S/]" fullword ascii
      $s18 = "OA_<8X-|" fullword ascii
      $s19 = "s+aL%M" fullword ascii
      $s20 = "sXtY9P" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      1 of ($x*) and 4 of them
}
```

Running the new rule:
```
thossa00@htb[/htb]$ yara htb_sample.yar /home/htb-student/Samples/YARASigma
RESULTS:
dharma_sample /home/htb-student/Samples/YARASigma/dharma_sample.exe
dharma_sample /home/htb-student/Samples/YARASigma/pdf_reader.exe
dharma_sample /home/htb-student/Samples/YARASigma/microsoft.com
dharma_sample /home/htb-student/Samples/YARASigma/check_updates.exe
dharma_sample /home/htb-student/Samples/YARASigma/KB5027505.exe
```

### Manually Developing a YARA Rule
#### Example 1: ZoxPNG RAT Used by APT17
We want to develop a YARA rule to scan for a specific variation of the ZoxPNG RAT used by APT17 based on:

- A sample named legit.exe residing in the /home/htb-student/Samples/YARASigma directory of this section's target
- String analysis
- Imphash
- Common sample file size

Let's start with our string analysis endeavors as follows.
```
thossa00@htb[/htb]$ strings legit.exe
```
File size can be determined by researching the hashes mentioned for common sample sizes. It looks like there are no related samples whose size is bigger than 200KB.

Finally, the sample's Imphash can be calculated as follows, using the imphash_calc.py script
```
thossa00@htb[/htb]$ python3 imphash_calc.py /home/htb-student/Samples/YARASigma/legit.exe
414bbd566b700ea021cfae3ad8f4d9b9
```
YARA Rule:
```
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-10-03
   Identifier: APT17 Oct 10
   Reference: https://goo.gl/puVc9q
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule APT17_Malware_Oct17_Gen {
   meta:
      description = "Detects APT17 malware"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/puVc9q"
      date = "2017-10-03"
      hash1 = "0375b4216334c85a4b29441a3d37e61d7797c2e1cb94b14cf6292449fb25c7b2"
      hash2 = "07f93e49c7015b68e2542fc591ad2b4a1bc01349f79d48db67c53938ad4b525d"
      hash3 = "ee362a8161bd442073775363bf5fa1305abac2ce39b903d63df0d7121ba60550"
   strings:
      $x1 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NETCLR 2.0.50727)" fullword ascii
      $x2 = "http://%s/imgres?q=A380&hl=en-US&sa=X&biw=1440&bih=809&tbm=isus&tbnid=aLW4-J8Q1lmYBM" ascii

      $s1 = "hWritePipe2 Error:%d" fullword ascii
      $s2 = "Not Support This Function!" fullword ascii
      $s3 = "Cookie: SESSIONID=%s" fullword ascii
      $s4 = "http://0.0.0.0/1" fullword ascii
      $s5 = "Content-Type: image/x-png" fullword ascii
      $s6 = "Accept-Language: en-US" fullword ascii
      $s7 = "IISCMD Error:%d" fullword ascii
      $s8 = "[IISEND=0x%08X][Recv:] 0x%08X %s" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and (
            pe.imphash() == "414bbd566b700ea021cfae3ad8f4d9b9" or
            1 of ($x*) or
            6 of them
         )
      )
}
```

1. Rule Imports: Modules are extensions to YARA's core functionality.
- import "pe": By importing the PE module the YARA rule gains access to a set of specialized functions and structures that can inspect and analyze the details of PE files. This makes the rule more precise when it comes to detecting characteristics in Windows executables.
2. Rule Meta:
- description: Tells us the main purpose of the rule, which is to detect APT17 malware.
- license: Points to the location and version of the license governing the use of this YARA rule.
- author: The rule was written by Florian Roth from Nextron Systems.
- reference: Provides a link that goes into more detail about the malware or context of this rule.
- date: The date the rule was either created or last updated, in this case, 3rd October 2017.
- hash1, hash2, hash3: Hash values, probably of samples related to APT17, which the author used as references or as foundational data to create the rule.
3. Rule Body: The rule contains a series of strings, which are potential indicators of the APT17 malware. These strings are split into two categories
- $x* strings
- $s* strings
4. Rule Condition: This is the heart of the rule, where the actual detection logic resides.
- uint16(0) == 0x5a4d: Checks if the first two bytes of the file are MZ, which is the magic number for Windows executables. So, we're focusing on detecting Windows binaries.
- filesize < 200KB: Limits the rule to scan only small files, specifically those smaller than 200KB.
- pe.imphash() == "414bbd566b700ea021cfae3ad8f4d9b9": This checks the import hash (imphash) of the PE (Portable Executable) file. Imphashes are great for categorizing and clustering malware samples based on the libraries they import.
- 1 of ($x*): At least one of the $x strings (from the strings section) must be present in the file.
- 6 of them: Requires that at least six of the strings (from both $x and $s categories) be found within the scanned file.

#### Example 2: Neuron Used by Turla
We want to develop a YARA rule to scan for instances of Neuron Service used by Turla based on:

- A sample named Microsoft.Exchange.Service.exe residing in the /home/htb-student/Samples/YARASigma directory of this section's target
- An analysis report from the National Cyber Security Centre

Since the report mentions that both the Neuron client and Neuron service are written using the .NET framework we will perform .NET "reversing" instead of string analysis. This can be done using the monodis tool as follows:
```
thossa00@htb[/htb]$ monodis --output=code Microsoft.Exchange.Service.exe

thossa00@htb[/htb]$ cat code
```
A good YARA rule to identify instances of Neuron Service resides in the /home/htb-student/Rules/yara directory of this section's target, saved as neuron_1.yar.

```
rule neuron_functions_classes_and_vars {
 meta:
   description = "Rule for detection of Neuron based on .NET functions and class names"
   author = "NCSC UK"
   reference = "https://www.ncsc.gov.uk/file/2691/download?token=RzXWTuAB"
   reference2 = "https://www.ncsc.gov.uk/alerts/turla-group-malware"
   hash = "d1d7a96fcadc137e80ad866c838502713db9cdfe59939342b8e3beacf9c7fe29"
 strings:
   $class1 = "StorageUtils" ascii
   $class2 = "WebServer" ascii
   $class3 = "StorageFile" ascii
   $class4 = "StorageScript" ascii
   $class5 = "ServerConfig" ascii
   $class6 = "CommandScript" ascii
   $class7 = "MSExchangeService" ascii
   $class8 = "W3WPDIAG" ascii
   $func1 = "AddConfigAsString" ascii
   $func2 = "DelConfigAsString" ascii
   $func3 = "GetConfigAsString" ascii
   $func4 = "EncryptScript" ascii
   $func5 = "ExecCMD" ascii
   $func6 = "KillOldThread" ascii
   $func7 = "FindSPath" ascii
   $dotnetMagic = "BSJB" ascii
 condition:
   (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and $dotnetMagic and 6 of them
}
```

YARA Rule Breakdown:

1. Strings Section:
- $class1 = "StorageUtils" ascii to $class8 = "W3WPDIAG" ascii: These are eight ASCII strings corresponding to class names within the .NET assembly.
- $func1 = "AddConfigAsString" ascii to $func7 = "FindSPath" ascii: These seven ASCII strings represent class or function names within the .NET assembly.
- $dotnetMagic = "BSJB" ascii: This signature is present in the CLI (Common Language Infrastructure) header of .NET binaries, and its presence can be used to indicate the file is a .NET assembly. Specifically, it's in the Signature field of the CLI header, which follows the PE header and additional tables.
2. Condition Section:
- uint16(0) == 0x5A4D: This checks if the first two bytes at the start of the file are MZ, a magic number indicating a Windows Portable Executable (PE) format.
- uint16(uint32(0x3c)) == 0x4550: A two-step check. First, it reads a 32-bit (4 bytes) value from offset 0x3c of the file. In PE files, this offset typically contains a pointer to the PE header. It then checks whether the two bytes at that pointer are PE (0x4550), indicating a valid PE header. This ensures the file is a legitimate PE format and not a corrupted or obfuscated one.
- $dotnetMagic: Verifies the presence of the BSJB string. This signature is present in the CLI (Common Language Infrastructure) header of .NET binaries, and its presence can be used to indicate the file is a .NET assembly.
- 6 of them: This condition states that at least six of the previously defined strings (either classes or functions) must be found within the file. This ensures that even if a few signatures are absent or have been modified, the rule will still trigger if a substantial number remain.

#### Example 3: Stonedrill Used in Shamoon 2.0 Attacks

We want to develop a YARA rule to scan for instances of Stonedrill used in Shamoon 2.0 attacks

Encrypted/compressed/obfuscated in PE files usually means high entropy. We can use the entropy_pe_section.py script that resides in the /home/htb-student directory of this section's target to check if our sample's resource section contains anything encrypted/compressed as follows.

```
thossa00@htb[/htb]$ python3 entropy_pe_section.py -f /home/htb-student/Samples/YARASigma/sham2.exe
        virtual address: 0x1000
        virtual size: 0x25f86
        raw size: 0x26000
        entropy: 6.4093453613451885
.rdata
        virtual address: 0x27000
        virtual size: 0x62d2
        raw size: 0x6400
        entropy: 4.913675128870228
.data
        virtual address: 0x2e000
        virtual size: 0xb744
        raw size: 0x9000
        entropy: 1.039771174750106
.rsrc
        virtual address: 0x3a000
        virtual size: 0xc888
        raw size: 0xca00
        entropy: 7.976847940518103
```

We notice that the resource section (.rsrc) has high entropy (8.0 is the maximum entropy value). We can take for granted that the resource section contains something suspicious.

A good YARA rule to identify instances of Stonedrill resides in the /home/htb-student/Rules/yara directory of this section's target, saved as stonedrill.yar.
```
import "pe"
import "math"

rule susp_file_enumerator_with_encrypted_resource_101 {
meta:
  copyright = "Kaspersky Lab"
  description = "Generic detection for samples that enumerate files with encrypted resource called 101"
  reference = "https://securelist.com/from-shamoon-to-stonedrill/77725/"
  hash = "2cd0a5f1e9bcce6807e57ec8477d222a"
  hash = "c843046e54b755ec63ccb09d0a689674"
  version = "1.4"
strings:
  $mz = "This program cannot be run in DOS mode."
  $a1 = "FindFirstFile" ascii wide nocase
  $a2 = "FindNextFile" ascii wide nocase
  $a3 = "FindResource" ascii wide nocase
  $a4 = "LoadResource" ascii wide nocase

condition:
uint16(0) == 0x5A4D and
all of them and
filesize < 700000 and
pe.number_of_sections > 4 and
pe.number_of_signatures == 0 and
pe.number_of_resources > 1 and pe.number_of_resources < 15 and for any i in (0..pe.number_of_resources - 1):
( (math.entropy(pe.resources[i].offset, pe.resources[i].length) > 7.8) and pe.resources[i].id == 101 and
pe.resources[i].length > 20000 and
pe.resources[i].language == 0 and
not ($mz in (pe.resources[i].offset..pe.resources[i].offset + pe.resources[i].length))
)
}
```

YARA Rule Breakdown:

1. Rule Imports: Modules are extensions to YARA's core functionality.
- import "pe": By importing the PE module the YARA rule gains access to a set of specialized functions and structures that can inspect and analyze the details of PE files. This makes the rule more precise when it comes to detecting characteristics in Windows executables.
- import "math": Imports the math module, providing mathematical functions like entropy calculations.
2. Rule Meta:
- copyright = "Kaspersky Lab": The rule was authored or copyrighted by Kaspersky Lab.
- description = "Generic detection for samples that enumerate files with encrypted resource called 101": The rule aims to detect samples that list files and have an encrypted resource with the identifier "101".
- reference = "https://securelist.com/from-shamoon-to-stonedrill/77725/": Provides an URL for additional context or information about the rule.
- hash: Two hashes are given, probably as examples of known malicious files that match this rule.
- version = "1.4": The version number of the YARA rule.
3. Strings Section:
- $mz = "This program cannot be run in DOS mode.": The ASCII string that typically appears in the DOS stub part of a PE file.
- $a1 = "FindFirstFile", $a2 = "FindNextFile": Strings for Windows API functions used to enumerate files. The usage of FindFirstFileW and FindNextFileW API functions can be idenfitied through string analysis.
- $a3 = "FindResource", $a4 = "LoadResource": As already mentioned Stonedrill samples feature encrypted resources. These strings can be found through string analysis and they are related to Windows API functions used for handling resources within the executable.
4. Rule Condition:
- uint16(0) == 0x5A4D: Checks if the first two bytes of the file are "MZ," indicating a Windows PE file.
- all of them: All the strings $a1, $a2, $a3, $a4 must be present in the file.
- filesize < 700000: The file size must be less than 700,000 bytes.
- pe.number_of_sections > 4: The PE file must have more than four sections.
- pe.number_of_signatures == 0: The file must not be digitally signed.
- pe.number_of_resources > 1 and pe.number_of_resources < 15: The file must contain more than one but fewer than 15 resources.
- for any i in (0..pe.number_of_resources - 1): ( (math.entropy(pe.resources[i].offset, pe.resources[i].length) > 7.8) and pe.resources[i].id == 101 and pe.resources[i].length > 20000 and pe.resources[i].language == 0 and not ($mz in (pe.resources[i].offset..pe.resources[i].offset + pe.resources[i].length))): Go through each resource in the file and check if the entropy of the resource data is more than 7.8 and the resource identifier is 101 and the resource length is greater than 20,000 bytes and the language identifier of the resource is 0 and the DOS stub string is not present in the resource. It's not required for all resources to match the condition; only one resource meeting all the criteria is sufficient for the overall YARA rule to be a match.

## Hunting Evil with YARA (Windows Edition)
We will be using a sample that we analyzed previously named dharma_sample.exe residing in the C:\Samples\YARASigma directory of this section's target.

We'll first examine the malware sample inside a hex editor (HxD, located at C:\Program Files\HxD) to identify the previously discovered string C:\crysis\Release\PDB\payload.pdb. If we scroll almost to the bottom, we will notice yet another seemingly unique sssssbsss string.


Note: In a Linux machine the hexdump utility could have been used to identify the aforementioned hex bytes as follows.

```
remnux@remnux:~$ hexdump dharma_sample.exe -C | grep crysis -n3

remnux@remnux:~$ hexdump dharma_sample.exe -C | grep sssssbsss -n3
```
YARA Rule:

```
rule ransomware_dharma
{

    meta:
        author = "Madhukar Raina"
        version = "1.0"
        description = "Simple rule to detect strings from Dharma ransomware"
        reference = "https://www.virustotal.com/gui/file/bff6a1000a86f8edf3673d576786ec75b80bed0c458a8ca0bd52d12b74099071/behavior"

    strings:
        $string_pdb = {  433A5C6372797369735C52656C656173655C5044425C7061796C6F61642E706462 }
        $string_ssss = { 73 73 73 73 73 62 73 73 73 }

        condition: all of them
}
```

Initiating the YARA executable with this rule: 
```
PS C:\Users\htb-student> yara64.exe -s C:\Rules\yara\dharma_ransomware.yar C:\Samples\YARASigma\ -r 2>null
ransomware_dharma C:\Samples\YARASigma\\dharma_sample.exe
```

Command Breakdown:

- yara64.exe: Refers to the YARA64 executable, which is the YARA scanner specifically designed for 64-bit systems.
- -s C:\Rules\yara\dharma_ransomware.yar: Specifies the YARA rules file to be used for scanning. In this case, the rules file named dharma_ransomware.yar located in the C:\Rules\yara directory is provided.
- C:\Samples\YARASigma: Specifies the path or directory to be scanned by YARA. In this case, the directory being scanned is C:\Samples\YARASigma.
- -r: Indicates that the scanning operation should be performed recursively, meaning YARA will scan files within subdirectories of the specified directory as well.
- 2>nul: Redirects the error output (stream 2) to a null device, effectively hiding any error messages that might occur during the scanning process.



### Hunting for Evil Within Running Processes with YARA

YARA rule that targets Metasploit's meterpreter shellcode, believed to be lurking in a running process:
```
rule meterpreter_reverse_tcp_shellcode {
    meta:
        author = "FDD @ Cuckoo sandbox"
        description = "Rule for metasploit's  meterpreter reverse tcp raw shellcode"

    strings:
        $s1 = { fce8 8?00 0000 60 }     // shellcode prologe in metasploit
        $s2 = { 648b ??30 }             // mov edx, fs:[???+0x30]
        $s3 = { 4c77 2607 }             // kernel32 checksum
        $s4 = "ws2_"                    // ws2_32.dll
        $s5 = { 2980 6b00 }             // WSAStartUp checksum
        $s6 = { ea0f dfe0 }             // WSASocket checksum
        $s7 = { 99a5 7461 }             // connect checksum

    condition:
        5 of them
}
```

htb_sample_shell.exe injects Metasploit's meterpreter shellcode into the cmdkey.exe process. Let's activate it, ensuring successful injection:

```
PS C:\Samples\YARASigma> .\htb_sample_shell.exe
```
With the injection executed, let's scan every active system process as follows, through another PowerShell terminal (Run as administrator).

```
PS C:\Windows\system32> Get-Process | ForEach-Object { "Scanning with Yara for meterpreter shellcode on PID "+$_.id; & "yara64.exe" "C:\Rules\yara\meterpreter_shellcode.yar" $_.id }
```

The Get-Process command fetches running processes, and with the help of the pipe symbol (|), this data funnels into the script block ({...}). Here, ForEach-Object dissects each process, prompting yara64.exe to apply our YARA rule on each process's memory.

From the results, the meterpreter shellcode seems to have infiltrated a process with PID 9084. We can also guide the YARA scanner with a specific PID as follows.
```
PS C:\Windows\system32> yara64.exe C:\Rules\yara\meterpreter_shellcode.yar 9084 --print-strings
```

### Hunting for Evil Within ETW Data with YARA
A quick recap first. According to Microsoft, Event Tracing For Windows (ETW) is a general-purpose, high-speed tracing facility provided by the operating system. Using a buffering and logging mechanism implemented in the kernel, ETW provides a tracing mechanism for events raised by both user-mode applications and kernel-mode device drivers.

SilkETW is an open-source tool to work with Event Tracing for Windows (ETW) data. SilkETW provides enhanced visibility and analysis of Windows events for security monitoring, threat hunting, and incident response purposes. It includes YARA functionality to filter or tag event data.
```
PS C:\Tools\SilkETW\v8\SilkETW> .\SilkETW.exe -h
```

### Example 1: YARA Rule Scanning on Microsoft-Windows-PowerShell ETW Data
The command below executes the SilkETW tool with specific options to perform event tracing and analysis on PowerShell-related events in Windows:

```
PS C:\Tools\SilkETW\v8\SilkETW> .\SilkETW.exe -t user -pn Microsoft-Windows-PowerShell -ot file -p ./etw_ps_logs.json -l verbose -y C:\Rules\yara  -yo Matches
```

Command Breakdown:

- -t user: Specifies the event tracing mode. In this case, it is set to "user," indicating that the tool will trace user-mode events (events generated by user applications).
- -pn Microsoft-Windows-PowerShell: Specifies the name of the provider or event log that you want to trace. In this command, it targets events from the "Microsoft-Windows-PowerShell" provider, which is responsible for generating events related to PowerShell activity.
- -ot file: Specifies the output format for the collected event data. In this case, it is set to "file," meaning that the tool will save the event data to a file.
- -p ./etw_ps_logs.json: Specifies the output file path and filename. The tool will save the collected event data in JSON format to a file named "etw_ps_logs.json" in the current directory.
- -l verbose: Sets the logging level to "verbose." This option enables more detailed logging information during the event tracing and analysis process.
- -y C:\Rules\yara: Enables YARA scanning and specifies a path containing YARA rules. This option indicates that the tool will perform YARA scanning on the collected event data.
- -yo Matches: Specifies the YARA output option. In this case, it is set to "Matches," meaning that the tool will display YARA matches found during the scanning process.

etw_powershell_hello.yar that looks for certain strings in PowerShell script blocks:
```
rule powershell_hello_world_yara {
	strings:
		$s0 = "Write-Host" ascii wide nocase
		$s1 = "Hello" ascii wide nocase
		$s2 = "from" ascii wide nocase
		$s3 = "PowerShell" ascii wide nocase
	condition:
		3 of ($s*)
}
```

Let's now execute the following PowerShell command through another PowerShell terminal and see if it will get detected by SilkETW (where the abovementioned YARA rule has been loaded):

```
PS C:\Users\htb-student> Invoke-Command -ScriptBlock {Write-Host "Hello from PowerShell"}
```

### Example 2: YARA Rule Scanning on Microsoft-Windows-DNS-Client ETW Data
The command below executes the SilkETW tool with specific options to perform event tracing and analysis on DNS-related events in Windows:
```
PS C:\Tools\SilkETW\v8\SilkETW> .\SilkETW.exe -t user -pn Microsoft-Windows-DNS-Client -ot file -p ./etw_dns_logs.json -l verbose -y C:\Rules\yara  -yo Matches
```
etw_dns_wannacry.yar that looks for a hardcoded domain that exists in Wannacry ransomware samples in DNS events:
```
rule dns_wannacry_domain {
	strings:
		$s1 = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii wide nocase
	condition:
		$s1
}
```

## Hunting Evil with YARA (Linux Edition)
### Hunting for Evil Within Memory Images with YARA

YARA's memory image scanning mirrors its disk-based counterpart. Let's map out the process:

- Create YARA Rules: Either develop bespoke YARA rules or lean on existing ones that target memory-based malware traits or dubious behaviors.
- Compile YARA Rules: Compile the YARA rules into a binary format using the yarac tool (YARA Compiler). This step creates a file containing the compiled YARA rules with a .yrc extension. This step is optional, as we can use the normal rules in text format as well. While it is possible to use YARA in its human-readable format, compiling the rules is a best practice when deploying YARA-based detection systems or working with a large number of rules to ensure optimal performance and effectiveness. Also, compiling rules provides some level of protection by converting them into binary format, making it harder for others to view the actual rule content.
- Obtain Memory Image: Capture a memory image using tools such as DumpIt, MemDump, Belkasoft RAM Capturer, Magnet RAM Capture, FTK Imager, and LiME (Linux Memory Extractor).
- Memory Image Scanning with YARA: Use the yara tool and the compiled YARA rules to scan the memory image for possible matches.

Here's an example command for YARA-based memory scanning:

```
thossa00@htb[/htb]$ yara /home/htb-student/Rules/yara/wannacry_artifacts_memory.yar /home/htb-student/MemoryDumps/compromised_system.raw --print-strings
```

The Volatility framework is a powerful open-source memory forensics tool used to analyze memory images from various operating systems. YARA can be integrated into the Volatility framework as a plugin called yarascan allowing for the application of YARA rules to memory analysis.

### Single Pattern YARA Scanning Against a Memory Image

In this case, we'll specify a YARA rule pattern directly in the command-line which is searched within the memory image by the yarascan plugin of Volatility. The string should be enclosed in quotes (") after the -U option. This is useful when we have a specific YARA rule or pattern that we want to apply without creating a separate YARA rules file.

From previous analysis we know that WannaCry malware attempt to connect to the following hard-coded URI www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com

Introducing this pattern within the command line using -U "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" prompts a search within the compromised_system.raw memory image.

```
thossa00@htb[/htb]$ vol.py -f /home/htb-student/MemoryDumps/compromised_system.raw yarascan -U "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"
```

### Multiple YARA Rule Scanning Against a Memory Image
When we have multiple YARA rules or a set of complex rules that we want to apply to a memory image, we can use the -y option followed by the rule file path in the Volatility framework, which allows us to specify the path to a YARA rules file. The YARA rules file (wannacry_artifacts_memory.yar in our case) should contain one or more YARA rules in a separate file.

```
thossa00@htb[/htb]$ cat /home/htb-student/Rules/yara/wannacry_artifacts_memory.yar
rule Ransomware_WannaCry {

    meta:
        author = "Madhukar Raina"
        version = "1.1"
        description = "Simple rule to detect strings from WannaCry ransomware"
        reference = "https://www.virustotal.com/gui/file/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa/behavior"


    strings:
        $wannacry_payload_str1 = "tasksche.exe" fullword ascii
        $wannacry_payload_str2 = "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii
        $wannacry_payload_str3 = "mssecsvc.exe" fullword ascii
        $wannacry_payload_str4 = "diskpart.exe" fullword ascii
        $wannacry_payload_str5 = "lhdfrgui.exe" fullword ascii

    condition:
        3 of them
```

```
thossa00@htb[/htb]$ vol.py -f /home/htb-student/MemoryDumps/compromised_system.raw yarascan -y /home/htb-student/Rules/yara/wannacry_artifacts_memory.yar
```
We can see in the results that the yarascan plugin in Volatility is able to find the process svchost.exe with PID 1576 in the memory image of the compromised system.

In summary, the -U option allows us to directly specify a YARA rule string within the command-line, while the -y option is used to specify the path to a file containing one or more YARA rules.

## Hunting Evil with YARA (Web Edition)
Unpac.Me is tool tailored for malware unpacking. The great thing about Unpac.Me is that it grants us the capability to run our YARA rules over their amassed database of malware submissions.
