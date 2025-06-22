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

### 3. Searched the DeviceProcessEvents for Script Execution

Since we have found a suspicious file, lets see if the attacker did indeed execute it.

```kql
DeviceProcessEvents
| where Timestamp >= datetime(2025-06-21T21:48:16.642466Z)
| where DeviceName contains "vm-linux-jd"
| project Timestamp, DeviceName, ActionType, InitiatingProcessCommandLine
| order by Timestamp asc
```
The date above is used to narrow down the timespan after the secretscript.sh was created and ordered by ascending to see events immediately after the file creation. 

![image](https://github.com/user-attachments/assets/3b2d9df8-ecb3-4cdf-96d6-5f7a78f8273f)

As we can see from the logs, one of the first rows at 2025-06-21T21:49:03.612371Z has value “/bin/bash ./secretscript.sh” for the InitiatingProcessCommandLine column. /bin/bash indicates the interpreter that is used, which is bash, and the next part is “./secretscript.sh” which shows that the script was executed by the attacker. Shortly after, we see a bunch of commands that indicate some suspicious behavior involving using the Azure CLI. At 2025-06-21T21:49:03.616899Z, we see a command involving uploading to an Azure storage blob account (storage blob upload), using an account key and a storage account. We also checked for anything resembling the script self-deleting since an audit of the VM was done, and the exact file and its contents were not found, but could not find a record referring to this outcome in this table or the DeviceFileEvents table. 

### 4. Looked at the DeviceNetworkEvents

Using command:

```kql
DeviceNetworkEvents
| where DeviceName contains "vm-linux-jd"
| where Timestamp >= datetime(2025-06-21T21:49:03.616899Z)
| project Timestamp, ActionType, InitiatingProcessCommandLine
| order by Timestamp asc
```

![image](https://github.com/user-attachments/assets/d7016b56-a8d7-4919-8ff5-713846083ce6)

We can see that we have a ConnectionRequest ActionType row involving Azure CLI blob storage, followed by a ConnectionSuccess row for the same request. When expanding the "ConnectionSuccess" record, we see the Azure CLI commands that were used in the suspicious script. The script connects to an Azure storage account and copies a file from the company's server. 

![image](https://github.com/user-attachments/assets/98d46e60-05b6-465f-b0ba-e71bef1f1586)

## Chronological Event Timeline 

### 1. File creation - secretscript.sh

- **Timestamp:** `2025-06-21T21:48:16.642466Z`
- **Event:** The user creates a file called secretscript.sh through the nano command in Linux.
- **Action:** Bash script file created and edited.
- **File Path:** `/home/jdance/secretscript.sh`


### 2. Process Execution - secretscript.sh execution

- **Timestamp:** `2025-06-21T21:49:03.612371Z`
- **Event:** The user executes the secretscript.sh.
- **Action:** Process creation detected.
- **File Path:** `/home/jdance/secretscript.sh`

### 3. Escalation of privilege - making "badactor" a sudo user

- **Timestamp:** `2025-06-21T21:49:03.604899Z`
- **Event:** The script grants sudo access to john_smith user.
- **Action:** Escalation of privilege.
- **File Path:** `/home/jdance/secretscript.sh`

### 4. Network Request to upload file to Azure Storage Account

- **Timestamp:** `2025-06-16T12:23:19.007669Z`
- **Event:** The script uploads file .my_secret_file.txt to Azure Storage account named storagejd2 through the Azure CLI. 
- **Action:** Exfiltration of PII data.
- **File Path:** `/home/jdance/.secret_data/.my_secret_file.txt`

---

## Summary

An employee gained access to a root account on a server containing PII and installed a script. This script had 2 main functions. One function uploaded a file that contained the PII information to an Azure storage account. The second function of the script was to create a backdoor by escalating the privileges of  employee's account which would allow access to the data in the future. The script was then deleted. It was determined that this was an insider threat. 

---

## Response Taken

The user account "badactor" was disabled. The user who left their laptop unlocked and unattended was forced to reset their password and undergo security training. This report was provided to the employee’s manager and upper management for further action.

