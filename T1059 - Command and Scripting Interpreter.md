
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

### 1. Prepare VM for Attack
- Create a Windows virtual machine (VM) in Azure with a public IP.
- Disable the VM's firewall and configure the NSG to allow all inbound traffic
  ![image](https://github.com/user-attachments/assets/8d2efd9f-5134-4e4b-9bc9-a746f0eab8fe)
- Onboard VM to Microsoft Defender for Endpoint (EDR)
- Download and install Wireshark with default settings - https://www.wireshark.org/download.html
- Download and install DeepBlueCLI and unzip - https://github.com/sans-blue-team/DeepBlueCLI
- Download and install Git for Windows - https://git-scm.com/downloads/win

### 2. Setup MDE To Detect the Attack
#### Based on the behavior of the [AutoIt Script Execution](https://www.atomicredteam.io/atomic-red-team/atomics/T1059#atomic-test-1---autoit-script-execution) script, we know that this script is designed to do the following actions in our VM:
- Check to see if AutoIt.exe is installed on the machine.
- If AutoIt3.exe is NOT present, then it will silently download the program from this website via Powershell and install it into the machine: https://www.autoitscript.com/cgi-bin/getfile.pl?autoit3/autoit-v3-setup.exe
- Once Autolt3.exe is installed, it will then run this program in combination with the malicious calc.au3 script found in the following directory: PathToAtomicsFolder\T1059\src\calc.au3
- This will result in Windows Calculator being launched.
#### Therefore, I will create the following MDE detection rules using KQL query language to alert when any of these steps are executed on the VM:
#### Note: For each rule I created, I did the following in the setup process:
- General: Add the correct MITRE category and technique + High Severity
- Impacted Entities: DeviceName
- Automated Actions: None

#### Rule 1: Alert when AutoIt.exe is launched from a User, Temp or Downloads folder AND the command line runs the malicious calc.au3 script file:
```kql
DeviceProcessEvents
| where DeviceName == "JD-win10"
| where FileName =~ "AutoIt3.exe"
| where ProcessCommandLine has_any (".au3", "calc.au3")
| where FolderPath has_any ("Users", "Temp", "Downloads")
```
#### Rule 2: Alert when Autolt.exe launches calc.exe (this is an abnormal parent-child process relationship):
```kql
DeviceProcessEvents
| where DeviceName == "JD-win10"
| where InitiatingProcessFileName =~ "AutoIt3.exe"
| where FileName =~ "calc.exe"
```
#### Rule 3: Alert when PowerShell is used to download something from the internet via the “Invoke-WebRequest” command:
```kql
DeviceProcessEvents
| where DeviceName == "JD-win10"
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("Invoke-WebRequest", "wget", "curl")
| where ProcessCommandLine has "autoit" "getfile.pl"
```
#### Rule 4: Alert when Powershell is being used to install Autolt.exe (Powershell is not typically used to install programs like these in a normal enterprise environment):
```kql
DeviceFileEvents
| where DeviceName == "JD-win10"
| where FileName has "autoit" and FileName endswith ".exe"
| where InitiatingProcessFileName =~ "powershell.exe"
```
#### Rule 5: Alert when non-standard scripting engines are found in the VM (like Autolt.exe, add others to the query, etc.). The “standard” scripting engines for Windows 10 are JScript and VBScript:
```kql
DeviceProcessEvents
| where DeviceName == "JD-win10"
| where FileName has_any ("AutoIt3.exe", "cscript.exe", "wscript.exe", "mshta.exe")
| summarize count() by DeviceName, FileName, bin(Timestamp, 1d)
| order by count_ desc
```
#### Screenshot of Rules
![image](https://github.com/user-attachments/assets/d9a42627-ee74-4b21-bd6f-0e1b5cb2a3f1)

### 3. Run the Atomic Script Attack

