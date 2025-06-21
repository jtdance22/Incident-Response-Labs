![image](https://github.com/user-attachments/assets/70552740-fbd2-47b0-aff8-43f8a6434449)

# Exfiltration and Escalation Of Privilege Lab
In this lab we will be simulating a scenario where a user has gained access to a computer with root privileges and has inserted a script that grants a specific user sudo access, extracts data (for simplification I assume that the attacker knows where the PII data is) and then the script deletes itself right after. 

Once we have the lab setup and the script in place, we will observe the logs in MDE and write a report. We will conduct an incident response investigation using the NIST 800-61 guidelines.



**Scenario**: A Company has been notfied that some of their employee PII data was posted on a reddit forum. The company believes this could be do to recent phishing attempts. Such information includes the employees home address, email address, and phone number. All of this information is stored on a linux server in a hidden file where only the root/sudo users have read and write access. There was also a report from an employee of a fellow co worker messing with an admins computer while they were in the bathroom. The company has decided to investigate this. 

## Platforms and Languages Leveraged
- Ubuntu Server 22.04 LTS
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Azure Blob Storage
- Microsoft Sentinel

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

One of the things we can look for is a file creation that the attacker might have performed in the time span that the company suspects. 

I used a query that searches for “FileCreated” Action type using the query below:

```kql
DeviceFileEvents
| where DeviceName contains "VM_HOST_NAME"
| where ActionType == "FileCreated"
```
