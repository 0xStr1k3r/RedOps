package mitre

// Tactic is one ATT&CK enterprise tactic in canonical order.
type Tactic struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// Tactics in canonical ATT&CK enterprise order.
var Tactics = []Tactic{
	{"TA0043", "Reconnaissance", "Gather information to plan future operations."},
	{"TA0042", "Resource Development", "Establish resources to support operations."},
	{"TA0001", "Initial Access", "Gain an initial foothold."},
	{"TA0002", "Execution", "Run adversary-controlled code."},
	{"TA0003", "Persistence", "Maintain a foothold across restarts."},
	{"TA0004", "Privilege Escalation", "Gain higher-level permissions."},
	{"TA0005", "Defense Evasion", "Avoid being detected."},
	{"TA0006", "Credential Access", "Steal account names and passwords."},
	{"TA0007", "Discovery", "Learn about the environment."},
	{"TA0008", "Lateral Movement", "Move through the environment."},
	{"TA0009", "Collection", "Gather data of interest."},
	{"TA0011", "Command and Control", "Communicate with compromised systems."},
	{"TA0010", "Exfiltration", "Steal data."},
	{"TA0040", "Impact", "Manipulate, interrupt, or destroy systems and data."},
}

// ExtraTechniques extends the Phase-1 subset with the techniques RedOps
// references across recon, enumeration, findings, and future attack paths.
// IDs/names follow the public MITRE ATT&CK enterprise matrix.
var ExtraTechniques = []Technique{
	// Reconnaissance
	{"T1595.001", "Scanning IP Blocks", "Reconnaissance", "", "Host discovery sweeps."},
	{"T1595.002", "Vulnerability Scanning", "Reconnaissance", "", "Service/version probing for known weaknesses."},
	{"T1590.001", "Domain Properties", "Reconnaissance", "", "WHOIS/registration data."},
	{"T1590.002", "DNS", "Reconnaissance", "", "DNS record collection."},
	{"T1593", "Search Open Websites/Domains", "Reconnaissance", "", "Open-source site search."},
	{"T1596.002", "WHOIS", "Reconnaissance", "", "Registration lookups."},
	{"T1591", "Gather Victim Org Information", "Reconnaissance", "", "Org structure and roles."},
	{"T1589", "Gather Victim Identity Information", "Reconnaissance", "", "Accounts and credentials surface."},
	// Resource Development
	{"T1583", "Acquire Infrastructure", "Resource Development", "", "Lab/assessment infrastructure setup."},
	{"T1587", "Develop Capabilities", "Resource Development", "", "Tooling built for the assessment."},
	{"T1588", "Obtain Capabilities", "Resource Development", "", "Tooling acquired (nmap, httpx, ...)."},
	{"T1608", "Stage Capabilities", "Resource Development", "", "Payloads staged in lab."},
	// Initial Access
	{"T1190", "Exploit Public-Facing Application", "Initial Access", "", "Web app exploitation (lab validation)."},
	{"T1133", "External Remote Services", "Initial Access", "", "Exposed remote services."},
	{"T1078.001", "Default Accounts", "Initial Access", "", "Unchanged default credentials (lab)."},
	{"T1078.002", "Domain Accounts", "Initial Access", "", "Domain credential use (lab)."},
	{"T1078.003", "Local Accounts", "Initial Access", "", "Local credential use (lab)."},
	{"T1110.001", "Password Guessing", "Initial Access", "", "Guessing weak passwords (lab, rate-limited)."},
	{"T1110.003", "Password Spraying", "Initial Access", "", "Spraying across accounts (lab)."},
	{"T1110.004", "Credential Stuffing", "Initial Access", "", "Reused credential testing (lab)."},
	{"T1566.001", "Spearphishing Attachment", "Initial Access", "", "Simulated phishing attachment (lab)."},
	{"T1566.002", "Spearphishing Link", "Initial Access", "", "Simulated phishing link (lab)."},
	// Execution
	{"T1059.001", "PowerShell", "Execution", "Windows", "PowerShell execution."},
	{"T1059.003", "Windows Command Shell", "Execution", "Windows", "cmd execution."},
	{"T1059.004", "Unix Shell", "Execution", "Linux/macOS", "Shell execution."},
	{"T1059.006", "Python", "Execution", "All", "Python execution."},
	{"T1053.002", "At", "Execution", "", "At-scheduled execution."},
	{"T1053.003", "Cron", "Execution", "", "Cron-scheduled execution."},
	{"T1053.005", "Scheduled Task", "Execution", "Windows", "Scheduled task execution."},
	{"T1106", "Native API", "Execution", "", "OS API execution."},
	{"T1203", "Exploitation for Client Execution", "Execution", "", "Client-side exploitation (lab)."},
	// Persistence
	{"T1136.001", "Local Account", "Persistence", "", "Rogue local account (lab)."},
	{"T1136.002", "Domain Account", "Persistence", "", "Rogue domain account (lab)."},
	{"T1543.003", "Windows Service", "Persistence", "Windows", "Service-based persistence (lab)."},
	{"T1547.001", "Registry Run Keys / Startup Folder", "Persistence", "Windows", "Autostart persistence (lab)."},
	{"T1505.003", "Web Shell", "Persistence", "", "Web shell persistence (lab)."},
	{"T1556", "Modify Authentication Process", "Persistence", "", "Auth subversion (lab)."},
	// Privilege Escalation
	{"T1068", "Exploitation for Privilege Escalation", "Privilege Escalation", "", "Privesc exploits (lab)."},
	{"T1134", "Access Token Manipulation", "Privilege Escalation", "Windows", "Token theft/impersonation (lab)."},
	{"T1548.002", "Bypass User Account Control", "Privilege Escalation", "Windows", "UAC bypass (lab)."},
	{"T1055", "Process Injection", "Privilege Escalation", "", "Code injection (lab)."},
	{"T1484", "Domain or Tenant Policy Modification", "Privilege Escalation", "", "GPO/tenant abuse (lab)."},
	// Defense Evasion
	{"T1027", "Obfuscated Files or Information", "Defense Evasion", "", "Obfuscation (detection lab)."},
	{"T1036", "Masquerading", "Defense Evasion", "", "Name/path masquerading."},
	{"T1070.004", "File Deletion", "Defense Evasion", "", "Log/artifact deletion (lab)."},
	{"T1112", "Modify Registry", "Defense Evasion", "Windows", "Registry tampering (lab)."},
	{"T1218", "System Binary Proxy Execution", "Defense Evasion", "", "LOLBins (detection lab)."},
	{"T1562.001", "Disable or Modify Tools", "Defense Evasion", "", "Disabling defenses (lab)."},
	// Credential Access
	{"T1003.001", "LSASS Memory", "Credential Access", "Windows", "LSASS dumping (lab only)."},
	{"T1003.008", "/etc/passwd and /etc/shadow", "Credential Access", "Linux", "Shadow file access (lab)."},
	{"T1552.001", "Credentials In Files", "Credential Access", "All", "Creds in configs (lab)."},
	{"T1555", "Credentials from Password Stores", "Credential Access", "", "Vault/keychain reads (lab)."},
	{"T1539", "Steal Web Session Cookie", "Credential Access", "", "Session theft (lab)."},
	{"T1040", "Network Sniffing", "Credential Access", "", "Traffic capture (lab)."},
	{"T1056", "Input Capture", "Credential Access", "", "Keylogging (lab)."},
	// Discovery
	{"T1016", "System Network Configuration Discovery", "Discovery", "", "Interfaces/routes/ARP."},
	{"T1033", "System Owner/User Discovery", "Discovery", "", "Logged-on user discovery."},
	{"T1082", "System Information Discovery", "Discovery", "", "OS/hardware fingerprinting."},
	{"T1007", "System Service Discovery", "Discovery", "", "Service enumeration."},
	{"T1057", "Process Discovery", "Discovery", "", "Process listing."},
	{"T1069.001", "Local Groups", "Discovery", "", "Local group enumeration."},
	{"T1069.002", "Domain Groups", "Discovery", "", "Domain group enumeration."},
	{"T1087", "Account Discovery", "Discovery", "", "Account enumeration."},
	{"T1201", "Password Policy Discovery", "Discovery", "", "Policy enumeration."},
	// Lateral Movement
	{"T1021.001", "Remote Desktop Protocol", "Lateral Movement", "", "RDP movement (lab)."},
	{"T1021.002", "SMB/Windows Admin Shares", "Lateral Movement", "Windows", "SMB movement (lab)."},
	{"T1021.004", "SSH", "Lateral Movement", "", "SSH movement (lab)."},
	{"T1021.006", "Windows Remote Management", "Lateral Movement", "Windows", "WinRM movement (lab)."},
	{"T1210", "Exploitation of Remote Services", "Lateral Movement", "", "Remote exploits (lab)."},
	{"T1570", "Lateral Tool Transfer", "Lateral Movement", "", "Tool staging between hosts (lab)."},
	// Collection
	{"T1005", "Data from Local System", "Collection", "", "Local file collection (lab)."},
	{"T1039", "Data from Network Shared Drive", "Collection", "", "Share collection (lab)."},
	{"T1074", "Data Staged", "Collection", "", "Staging for exfil (lab)."},
	{"T1114", "Email Collection", "Collection", "", "Mailbox collection (lab)."},
	{"T1213", "Information Repository Mining", "Collection", "", "Repo/wiki mining (lab)."},
	// Command and Control
	{"T1071.001", "Web Protocols", "Command and Control", "", "HTTP(S) C2 (lab)."},
	{"T1090", "Proxy", "Command and Control", "", "Proxy chains (lab)."},
	{"T1105", "Ingress Tool Transfer", "Command and Control", "", "Downloading tools (lab)."},
	{"T1132", "Data Encoding", "Command and Control", "", "Encoding for C2 (lab)."},
	{"T1573", "Encrypted Channel", "Command and Control", "", "Encrypted C2 (lab)."},
	// Exfiltration
	{"T1020", "Automated Exfiltration", "Exfiltration", "", "Automated exfil (lab)."},
	{"T1041", "Exfiltration Over C2 Channel", "Exfiltration", "", "Exfil over C2 (lab)."},
	{"T1048", "Exfiltration Over Alternative Protocol", "Exfiltration", "", "DNS/ICMP exfil (lab)."},
	// Impact
	{"T1485", "Data Destruction", "Impact", "", "Wiping (lab)."},
	{"T1486", "Data Encrypted for Impact", "Impact", "", "Ransomware sim (lab)."},
	{"T1490", "Inhibit System Recovery", "Impact", "", "Recovery sabotage (lab)."},
	{"T1496", "Resource Hijacking", "Impact", "", "Crypto mining sim (lab)."},
	{"T1498", "Network Denial of Service", "Impact", "", "DoS (lab, never prod)."},
}

func init() {
	Techniques = append(Techniques, ExtraTechniques...)
	byID = func() map[string]Technique {
		m := map[string]Technique{}
		for _, t := range Techniques {
			m[t.ID] = t
		}
		return m
	}()
}

// TechniquesByTactic groups the matrix for dashboard rendering.
func TechniquesByTactic(tactic string) []Technique {
	var out []Technique
	for _, t := range Techniques {
		if t.Tactic == tactic {
			out = append(out, t)
		}
	}
	return out
}
