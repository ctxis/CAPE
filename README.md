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
    
CAPE can also extract the payloads from 'hacked' (modified) packers derived from UPX, a favourite with malware authors.
    
Currently CAPE has packages for the following malware families:
    - PlugX
    - EvilGrab
    - Azzy

There are a number of other malware family packages currently in the works, so watch this space.

A number of other malware families have their payloads extracted by some of the behavioural packages, configuration parsing on the output of some of these is also currently being worked on.

In addition, a number of malware families are covered by static configuration extraction based on malwareconfig.com (thanks to Kevin Breen/TechAnarchy for this).

Detection to trigger a CAPE package can be based from either 'Cuckoo' (API) or Yara signatures.

Packages can be written based on API hooks, the CAPE debugger, or a combination of both.

The CAPE debugger allows four breakpoints to be set on each malware thread to detect on read, write or execute of a memory region, as well as single-step mode. This allows fine control over malware execution until it is possible to dump the memory regions of interest, containing code or configuration data.

Processes, modules and memory regions can variously be dumped by CAPE through use of a simple API.

Executable modules are fixed on being dumped, and may also have their imports automatically reconstructed (thanks to Scylla authors).

It is derived from spender-sandbox, thanks to Brad Spengler and the rest of the Cuckoo contributors.

Please contribute to this project by helping create new packages for further malware families, packers, techniques or configuration parsers. Alternatively contact us for further details of CAPE development.