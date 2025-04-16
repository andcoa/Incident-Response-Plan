# Incident Response Plan

## Summary of findings

Based on the analysis, the following incidents were detected:

Incident #1: Unauthorized Opening of Port 22 on Linux:
o	Description: A port change alert was logged by NixGuard indicating that port 22 (SSH) was opened or closed.
o	Containment: Block the port to stop any attacks while conducting forensic analysis of the configuration of port 22.
o	Eradication: Verify all inbound/outbound connections using port 22 and block any suspicious addresses using those connections
o	Recovery: Re-enable port 22 and continuously monitor for unusual connections patterns.
o	Mitigation: Disable unused services and whitelist only trusted IPs to use port 22. Disable password-based logins for SSH and use SSH keys instead. Enable port knocking and Multi-Factor Authentication (MFA) such as Google Authenticator.

Incident #2: Possible kernel level rootkit from SSHServer installation on Linux:
o	Description: A possible kernel level rootkit was found by NixGuard after installing SSHServer on the Ubuntu VM.
o	Containment: Isolate the affected system by disconnecting it from the network to prevent lateral movement. Use a forensic environment such as Kali or Tails to prevent the rootkit from hiding itself.
o	Eradication: Wipe and reinstall the OS from a known clean image.
o	Recovery: Patch and update the system ensuring the latest kernel and security updates are installed. Reconfigure SSH, firewall and other controls manually to avoid using potentially compromised configuration files.
o	Mitigation: Restrict user permissions by implementing strong least privilege rules. Disable root login over SSH and use a Host-based Intrusion Detection System (HIDS) such as Wazuh for real-time file integrity monitoring. Enable SELinux to harden kernel security and disable unnecessary kernel modules.

Incident #3: EICAR File download and detection on Linux:
o	Description: A ‘file added’ alert was logged by NixGuard after downloading the EICAR file used for malware detection purposes.
o	Containment: The EICAR test file was detected, confirming NixgGuard detected it in real time but did not quarantine it.
o	Eradication: Remove the EICAR file from the system and conduct a full malware scan to ensure no additional files or configurations are present.
o	Recovery: Validate the integrity of system files and restore OS functionality.
o	Mitigation: Train end-users on verifying download sources and suspicious files downloads, fine-tune NixGuard to quarantine/remove potentially infected files consistently and run regular system integrity checks.

Incident #4: Hydra Brute-Force Attack:
o	Description: A Hydra Brute-Force attack went unnoticed by NixGuard and no trace of it was logged in the system.
o	Containment: Identify the attack source, block attacking IPs and disable compromised accounts.
o	Eradication: Implement Fail2Ban to prevent future brute-force attacks, create a rule to block repeated SSH login failures. Review and rotate compromised credentials such as user passwords by resetting/forcing password changes on next login.
o	Recovery: Verify system integrity, reinforce authentication security (MFA, SSH key-based authentication), and reconfigure network security settings by restricting SSH to trusted IP addresses.
o	Mitigation: Update NixGuard to consistently detect and prevent brute force attacks. Apply rate-limit to login attempts, change default ports by obfuscating SSH use to a non-standard port (ex: port 3333) and monitor authentication logs in real time.

## Conclusion
NixGuard is a powerful security monitoring and incident management tool which provides real-time insights to system vulnerabilities, file integrity and network traffic. The investigation conducted revealed critical security incidents including the unauthorized access of port 22, a possible kernel level rootkit, detection of a malicious file and undetected Kali Linux attack on an Ubuntu machine. Through comprehensive network analysis, threat detection and incident response planning, I identified vulnerabilities that could be exploited by attackers to compromise system integrity. It is crucial to keep systems up to date and enforce best practices to ensure potential risks are adequately prevented and defended from. 
