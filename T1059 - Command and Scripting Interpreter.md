
<img width="400" src="https://github.com/user-attachments/assets/7eab7f34-ad1c-423d-93bb-3b66b8043ecb" alt="Atomic Red Team logo"/>

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

## Table of Contents
- Step 1 - Prepare Virtual Machine
- Step 2 - Setup MDE to Detect Attack
- Step 3 - Run Atomic Script
- Step 4 - Review MDE Alerts Post-Attack
- Step 5 - Detection and Analysis
- Step 6 - Containment, Eradication, and Recovery

## Steps

### 1. Prepare VM for attack
- Create a Windows virtual machine (VM) in Azure with a public IP.
- Disable the VM's firewall and configure the NSG to allow all inbound traffic
  ![image](https://github.com/user-attachments/assets/8d2efd9f-5134-4e4b-9bc9-a746f0eab8fe)
- Onboard VM to Microsoft Defender for Endpoint (EDR)
- Download and install Wireshark with default settings - https://www.wireshark.org/download.html
- Download and install DeepBlueCLI and unzip - https://github.com/sans-blue-team/DeepBlueCLI
- Download and install Git for Windows - https://git-scm.com/downloads/win

