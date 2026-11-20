# EMERGENCY SECURITY ADVISORY — Release v3.4.1

**Issued by:** Protocol Incident Response Board  
**Severity:** Critical — Immediate Deployment Halt

Forensic analysis of release v3.4.1 build artifacts has confirmed an active compromise of the v3.4.1 release signing key. Unauthorized signatures were generated outside hardware custody, and an active critical exploit targeting the v3.4.1 settlement handler has been observed in staging replay traces. All operators must immediately halt rollout of release v3.4.1 while the compromised key is revoked and emergency remediation is prepared.
