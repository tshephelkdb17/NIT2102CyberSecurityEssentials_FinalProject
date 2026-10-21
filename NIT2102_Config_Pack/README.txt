NIT2102 Cyber Security Essentials - Configuration Pack

Files
-----
architecture.mmd             Mermaid.js source for the requested conceptual architecture.
local.rules                  Snort 3 lab/tuned IDS rules.
local_decoder.xml            Wazuh custom decoder for Snort fast-alert output.
local_rules.xml              Wazuh custom Rule 100100 and ransomware Rule 100200.
ossec_fim_snippet.xml        Wazuh File Integrity Monitoring configuration excerpt.
active_response_binding.xml  Wazuh manager binding for Rule 100200 to custom response.
ransomware_response.py       Reversible/safe containment script.

Evidence note
-------------
The supplied screenshots demonstrate Snort and the Wazuh endpoint agent/FIM on the
Kali security endpoint, with Metasploitable acting as the protected vulnerable target.
The Mermaid source represents the conceptual target placement requested in the project
parameters. The report distinguishes the conceptual design from the lab implementation.

Safety
------
Use only in the isolated 192.168.64.0/24 lab. Review paths, permissions and timeouts
before deploying to any real environment.
