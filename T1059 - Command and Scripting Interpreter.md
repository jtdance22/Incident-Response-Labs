
# Incident Response Simulation (T1059 - Command and Scripting Interpreter)

## Description
- In this project, I will simulate a basic script execution attack by running an Atomic Red script called AutoIt Script Execution in an Azure Windows VM.
- “Script execution attacks” are when a bad actor infects your endpoint with malware that uses a “script interpreter” (in this case, AutoIt.exe) to automatically launch malicious programs within the target machine, silently. This typically happens when you download this malware from a website or click a malicious link.
- The “malicious program” that will be remotely launched by this attack will be Windows Calculator. Once the attack runs successfully, I'll then conduct a complete incident response investigation based on NIST 800-61 guidelines.

## Tools and Frameworks
- Azure Virtual Machines
- Microsoft Defender for Endpoint
- Microsoft Sentinel
- Wireshark
- Powershell
- Atomic Red Scripts
- DeepBlueCLI
- NIST 800-61 Incident Response
