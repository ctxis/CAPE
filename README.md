CAPE: Config And Payload Extraction

CAPE is an addition to Cuckoo specifically designed to extract payloads and configuration from malware.

CAPE can detect a number of malware techniques or behaviours, as well as specific malware families, from its initial run on a sample. 

This detection then triggers a second run with a specific package, in order to extract the malware payload and possibly its configuration, for further analysis.

The techniques or behaviours that CAPE detects and has packages for include:
    - Process injection
        - Shellcode injection
        - DLL injection
        - Process Hollowing
    - Decompression of executable modules in memory
    - Extraction of executable modules or shellcode in memory

Packages for these behaviours will dump the payloads being injected, extracted or decompressed for further analysis. This is often the malware payload in unpacked form.    

In addition to specific behaviours, CAPE also automatically creates a process dump for each process' main executable, or, in the case of a DLL, the DLL's module image in memory. This is useful for samples packed with simple packers, where often the module image dump is fully unpacked.
    
CAPE can also extract the payloads from 'hacked' (modified) packers derived from UPX, a favourite with malware authors.
    
Currently CAPE has specific packages for the following malware families:
    - PlugX
    - EvilGrab
    - Azzy

Detection to trigger a CAPE package can be based from on 'Cuckoo' (API) or Yara signatures.
    
Many other malware families have their payloads extracted by some of the behavioural packages, with their configuration in the clear in the resulting output. Configuration parsing may then be performed on this by virtue of yara-based detection, and config parsing based on CAPE's primary config parsing framework, DC3-MWCP (Defense Cyber Crime Center - Malware Configuration Parser). Thanks to the creators at the Defense Cyber Crime Center. Parsers may also be written using the RATDecoders parser from malwareconfig.com (Kevin Breen/TechAnarchy). The publicly available decoders from malwareconfig.com are also included in CAPE.

Currently CAPE has config parsers for the following malware families, whose payloads are extracted by a behavioural package:
    - HttpBrowser

There are a number of other behavioural and malware family packages and parsers currently in the works, so watch this space.
    
Packages can be written based on API hooks, the CAPE debugger, or a combination of both.

The CAPE debugger allows four breakpoints to be set on each malware thread to detect on read, write or execute of a memory region, as well as single-step mode. This allows fine control over malware execution until it is possible to dump the memory regions of interest, containing code or configuration data.

Processes, modules and memory regions can variously be dumped by CAPE through use of a simple API.

Executable modules are fixed on being dumped, and may also have their imports automatically reconstructed (thanks to Scylla authors).

It is derived from spender-sandbox, thanks to Brad Spengler and the rest of the Cuckoo contributors.

Please contribute to this project by helping create new packages for further malware families, packers, techniques or configuration parsers. Alternatively contact us for further details of CAPE development.