![image](https://github.com/user-attachments/assets/70552740-fbd2-47b0-aff8-43f8a6434449)

# Exfiltration and Escalation Of Privilege Lab
In this lab we will be simulating a scenario where a user has gained access to a computer with root privileges and has inserted a script that grants a specific user sudo access, extracts data (for simplification I assume that the attacker knows where the PII data is) and then the script deletes itself right after. 

Once we have the lab setup and the script in place, we will observe the logs in MDE and write a report. We will conduct an incident response investigation using the NIST 800-61 guidelines.



**Scenario**: A Company has been notfied that some of their employee PII data was posted on a reddit forum. At the same time, an alert for potential privilege escalation was generated in Microsoft Sentinel. All of the PII information is stored on a linux server in a hidden file where only the root/sudo users have read and write access. There was also a report from an employee of a fellow co worker messing with an admins computer while they were in the bathroom. The company has decided to investigate this. 

## Platforms and Languages Leveraged
- Ubuntu Server 22.04 LTS
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Azure Blob Storage
- Microsoft Sentinel

---

## Microsoft Sentinel Alert
Below is the query that has created an incident. This is a scheduled query that alerts if the command "usermod" was used or if the command contains sensitive groups, such as sudo.

![image](https://github.com/user-attachments/assets/998dadb7-ff2e-43d4-ade4-b25801c73606)



## Steps Taken

### 1. Search for user permission changes.

Since we were alerted that privileges may have been escalated on the server containing employee PII. We will use MS Defender for Endpoint to begin the investigation. We confirm with the following query and results. The command "usermod -aG" was used to escalate the user "badactor" into the sudo group, granting root privileges. This is most likely a backdoor that the attacker has created.

```kql
DeviceFileEvents
| where DeviceName contains "vm-linux-jd"
| where InitiatingProcessCommandLine contains "usermod"
| where Timestamp > ago(3d)
| order by Timestamp desc
| project Timestamp, DeviceName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
```
![image](https://github.com/user-attachments/assets/6df847cc-7e4c-4b5c-9de3-cffc9827b60b)



### 2. Searched for file creation

One of the things we can look for next is a file creation that the attacker might have performed in the time span that the company suspects. 

I used a query that searches for “FileCreated” Action type using the query below:

```kql
DeviceFileEvents
| where DeviceName contains "vm-linux-jd"
| where ActionType == "FileCreated"
| where Timestamp > ago(3d)
| order by Timetamp desc
```
![image](https://github.com/user-attachments/assets/cc8dd264-ef00-4319-a97f-c9850b75878f)

Looking at the query results above, we see a suspicious looking shell script file was created at 2025-06-21T21:48:16.642466Z. Upon inspecting the record further, we can see the exact command that was used to create and edit the file.

![image](https://github.com/user-attachments/assets/915f2764-90d8-4ba9-adf7-bb951225d733)

### 3. Searched the DeviceProcessEvents For Script Execution

```kql
DeviceProcessEvents
| where Timestamp >= datetime(TIME_STAMP)
| where DeviceName contains "VM_NAME"
| project Timestamp, DeviceName, ActionType, InitiatingProcessCommandLine
| order by Timestamp asc
```
