# Questionnaire with Prompt Sequences

Below is a consolidated questionnaire for scenarios related to cybersecurity in power grid systems.  
Each question includes placeholders for multiple prompts, reflecting a scoring mechanism where the  
number of prompts used to reach the correct response determines the allocated points.

---

## Scenario 1: Remote Access Security in Power Grid System

**Background**  
A power utility company is reevaluating its cybersecurity measures due to vulnerabilities found in  
remote access protocols used for system operations and monitoring. Unauthorized access through these  
channels could lead to control disruption or blackout.

### Question 1 (Q1)  
**Difficulty Level: Medium**  

> **What mitigation strategy is most suited to strengthen security for remote access tools used in  
> power systems operations and monitoring?**

1. **Identity-based authentication and critical public infrastructure (PKI) methods (4 Points)**  
2. Determination of specific roles on the system and grouping access privileges to each role (Role-Based Access) (3 Points)  
3. IP whitelisting of incoming connections for authorized clients (1 Point)  
4. Strict password policies for user authentication (2 Points)  
5. Others. (0 points)

**Logic for Highest Rated Answer**  
- The question with the highest marks provides the most robust real-time authentication mechanism.  
- Validation is not local and provided by an external entity.

#### Follow-up Question for Q1
> _Could you please explain your reasoning for selecting that particular response?_

1. It provides the most robust real-time authentication mechanism (4 Points).  
2. It effectively restricts access based on job roles (3 Points).  
3. It only allows access from pre-approved IP addresses (2 Points).  
4. It ensures that passwords are strong and regularly updated (1 Point).  
5. Others. (0 points)

### Sample Prompt Sequence (Q1)

- **Prompt #1**: "Identify the best way to secure remote access protocols in power grid operations."  
- **Prompt #2**: "Clarify why PKI-based authentication offers greater security than role-based or whitelisting."  
- **Prompt #3**: "Refine: what additional validation steps ensure real-time authentication?"  
- **Prompt #4**: "Assess if external certificate authorities improve trust and validation."

---

### Question 2 (Q2)  
**Difficulty Level: Difficult**  

> **Which technique is most effective in detecting false data injection attacks aimed at manipulating  
> operational data?**

1. **Anomaly detection methods (Identify suspicious patterns) (4 Points)**  
2. Secure control methodologies (3 Points)  
3. Encryption-based techniques (2 Points)  
4. Redundant data transmission (1 Point)  
5. Others. (0 points)

**Logic for Highest Rated Answer**  
The question with the highest marks provides the most effective detection methodology  
based on pre-defined signatures and heuristic analysis.

#### Follow-up Question for Q2
> _Could you please explain your reasoning for selecting that particular response?_

1. It detects unusual patterns that indicate tampering (4 Points).  
2. It secures commands and controls against unauthorized changes (3 Points).  
3. It ensures data integrity and confidentiality (2 Points).  
4. It provides multiple data sources for verification (1 Point).  
5. Others. (0 points)

### Sample Prompt Sequence (Q2)

- **Prompt #1**: "Which technique is best at catching tampered or injected data in a power grid's operational streams."  
- **Prompt #2**: "Investigate how anomaly detection compares with encryption for detecting real-time data manipulation."  
- **Prompt #3**: "Request examples of heuristic analyses that might indicate falsified data."  
- **Prompt #4**: "Evaluate the role of pre-defined signatures in identifying advanced persistent threats."

---

## Scenario 2: Cybersecurity of Distributed Energy Resources (DER)

**Background**  
As the adoption of distributed energy resources (DER) like solar panels and wind turbines grows, so does  
the complexity of the grid's cybersecurity landscape. A regional power company has identified potential  
vulnerabilities in the communication protocols used to manage these resources. There's a concern that  
attackers could manipulate the control signals, causing instability in the power grid.

### Question 1 (Q1)  
**Difficulty Level: Difficult**  

> **What protocol security enhancement is most critical to protect communications between DER management  
> systems and the central grid control?**

1. Implementation of TLS/SSL for data encryption in transit (2 Points)  
2. **Use of a protocol (IEC 60870-5, IEC 61850-7-420) with enhanced authentication (4 Points)**  
3. Deployment of secure VPN tunnels for remote connections (1 Point)  
4. Enforcing IEEE 1815 (DNP3) with secure authentication (3 Points)  
5. Others. (0 points)

**Logic for Highest Rated Answer**  
The question with the highest marks provides a preferred standard for power grid monitoring,  
control, and associated communication.

#### Follow-up Question for Q1
> _Could you please explain your reasoning for selecting that particular response?_

1. It provides end-to-end encryption. (3 Points)  
2. **It offers both encryption and reliable data flow. (4 Points)**  
3. It creates a secure channel for remote access. (1 Point)  
4. It is specifically designed for utility communications. (2 Points)  
5. Others. (0 points)

### Sample Prompt Sequence (Q1)

- **Prompt #1**: "Inquire about the most robust protocol for securely communicating with DER management systems."  
- **Prompt #2**: "Compare IEC 61850-7-420 with TLS/SSL in terms of authentication and data flow reliability."  
- **Prompt #3**: "Clarify how encryption, authentication, and standardization combine in a single protocol."  
- **Prompt #4**: "Confirm specialized protocols for utility operations that offer both security and reliability."

---

### Question 2 (Q2)  
**Difficulty Level: Medium**  

> **Which method is most effective to detect and mitigate potential cybersecurity threats to DER systems?**

1. Regular penetration testing of the network (3 Points)  
2. **Continuous monitoring with SIEM (Security Information & Event Management) systems (4 Points)**  
3. Periodic updates and patch management. (2 Points)  
4. Deployment of anomaly detection systems at each DER node. (1 Point)  
5. Others. (0 points)

**Logic for Highest Rated Answer**  
It provides real-time threat analysis and response.

#### Follow-up Question for Q2
> _Could you please explain your reasoning for selecting that particular response?_

1. It identifies vulnerabilities before exploitation. (3 Points)  
2. **It provides real-time threat analysis and response. (4 Points)**  
3. It ensures all components are up-to-date. (2 Points)  
4. It detects unusual patterns specific to each node. (1 Point)  
5. Others. (0 points)

### Sample Prompt Sequence (Q2)

- **Prompt #1**: "Ask how to best monitor DER systems in real time for cybersecurity anomalies."  
- **Prompt #2**: "Compare continuous monitoring (SIEM) with periodic penetration testing for quick threat response."  
- **Prompt #3**: "Request details on how SIEM aggregates logs and detects advanced threats."  
- **Prompt #4**: "Explore whether localized anomaly detectors suffice compared to a comprehensive SIEM solution."

---

## Scenario 3: Power System Wide Area Measurement System (WAMS)

**Background**  
Power system Wide Area Measurement System (WAMS) utilizes Phasor Measurement Unit (PMU) data for advanced  
energy management applications like stability monitoring, islanding, and disturbance management. PMU data is  
communicated from PMU to the Phasor Data Concentrator (PDC) via intermediate routers and communication links.  
An adversary can compromise one or multiple PMUs, links in between, or the internet-facing routers to manipulate  
PMU data. These attacks can remain undetected, causing extensive power disruptions.

### Question 1 (Q1)  
**Difficulty Level: Medium**  

> **Which attack on PMU data is most likely to have a greater impact on stability monitoring applications?**

1. Denial of Service (DoS) attack. (2 Points)  
2. Time Synchronization Attack. (1 Point)  
3. **Coordinated False Data Injection (FDI) Attack. (4 Points)**  
4. Man-in-the-Middle (MiTM) Attack. (3 Points)

**Logic for Highest Rated Answer**  
False data from multiple devices can cause incorrect inferences about system state.

#### Follow-up Question for Q1
> _Could you please explain your reasoning for selecting that particular response?_

1. DoS will prevent receiving real-time data at the control center. (2 Points)  
2. Time Synchronization is critical for all applications. (1 Point)  
3. **False data from multiple devices can cause incorrect inferences about system state. (4 Points)**  
4. MiTM can modify data in transit. (3 Points)  
5. Others.

### Sample Prompt Sequence (Q1)

- **Prompt #1**: "Ask about the most disruptive cyberattack type on PMU data for stability monitoring."  
- **Prompt #2**: "Clarify why coordinated FDI might be more harmful than simple DoS or MiTM attacks."  
- **Prompt #3**: "Investigate how compromised data from multiple devices leads to inaccurate state estimation."  
- **Prompt #4**: "Confirm if false data across many PMUs has a cascading effect on power system decisions."

---

### Question 2 (Q2)  
**Difficulty Level: Difficult**  

> **In the above scenario, what is the easiest way to perform the attack on power system C37.118-based WAMS?**

1. Compromise one or multiple PMUs (3 Points)  
2. Compromise wired links in between (2 Points)  
3. **Compromise the internet-facing Routers (4 Points)**  
4. Compromise PDC (1 Point)

**Logic for Highest Rated Answer**  
In this scenario, the router is a link between commercial and control systems, which is exposed to the internet.

#### Follow-up Question for Q2
> _Could you please explain your reasoning for selecting that particular response?_

1. Physical access to the link is easy to achieve. (2 Points)  
2. **A router is a link between commercial and control systems, exposed to the internet. (4 Points)**  
3. PDC physical access is easy as it is not protected by proper authorization. (1 Point)  
4. PMUs may have zero-day vulnerabilities that can be exploited easily. (3 Points)  
5. Others.

### Sample Prompt Sequence (Q2)

- **Prompt #1**: "Ask which entry point is the simplest for attackers aiming to hijack WAMS traffic."  
- **Prompt #2**: "Compare vulnerabilities in routers vs. PMUs or PDC systems."  
- **Prompt #3**: "Confirm how internet-facing routers bridge commercial and control networks."  
- **Prompt #4**: "Examine why router compromise offers broad access to WAMS data."

---

## Scenario 4: Compromising the IEC 61850 Network of a Substation

**Background**  
An attacker breached the IEC 61850 network of a substation. The attacker analyzed network packets and  
identified specific file types used to configure the Intelligent Electronic Devices (IEDs). They then  
tampered with an IED's configuration, changing values of protection function data attributes and causing  
a malfunction during a power system fault.

### Question 1 (Q1)  
**Difficulty Level: Medium**  

> **Which configuration file would the attacker modify and send back to the network for the highest impact  
> on the IED functionality?**

1. ICD (IED Capability Description) (2 Points)  
2. SCD (Station Configuration Description) (1 Point)  
3. **CID (Configured IED Description) (4 Points)**  
4. IID (Instantiated IED Description) (3 Points)

**Logic for Highest Rated Answer**  
CID file contains all necessary elements from SCD to configure an IED.

#### Follow-up Question for Q1
> _Could you please explain your reasoning for selecting that particular response?_

1. The ICD file defines the complete capability range of an IED. (2 Points)  
2. The SCD file describes the entire substation in detail. (1 Point)  
3. **The CID file contains everything that is needed from SCD to configure an IED. (4 Points)**  
4. The IID file defines the configuration of an IED for a specific project. (3 Points)  
5. Others.

### Sample Prompt Sequence (Q1)

- **Prompt #1**: "Ask which IEC 61850 configuration file impacts IED functionality most directly if modified."  
- **Prompt #2**: "Clarify how CID vs. SCD files differ in terms of direct IED configuration data."  
- **Prompt #3**: "Confirm that CID includes all relevant parameters needed for IED operations."  
- **Prompt #4**: "Inquire if modifying CID can override station-level settings."

---

### Question 2 (Q2)  
**Difficulty Level: Difficult**  

> **Which field within an IED, if maliciously configured, would have the maximum number of line disconnections  
> during a power system fault?**

1. PTRC.Tr.General (1 Point)  
2. **PBDF.DifAClc. rangeC.min.f (4 Points)**  
3. PLDF.DifAClc.LoSet (3 Points)  
4. RBRF.OpE (2 Points)

**Logic for Highest Rated Answer**  
Bus bar protection, if triggered incorrectly, removes multiple devices from the network.

#### Follow-up Question for Q2
> _Could you please explain your reasoning for selecting that particular response?_

1. PTRC is related to Protection Trip Conditioning. (1 Point)  
2. **PBDF is related to Bus bar protection. (4 Points)**  
3. PLDF is related to Line differential protection. (3 Points)  
4. RBRF is related to Breaker Failure protection. (2 Points)  
5. Others.

### Sample Prompt Sequence (Q2)

- **Prompt #1**: "Ask which IED field leads to the widest disruption if maliciously altered."  
- **Prompt #2**: "Compare bus bar protection with line differential or breaker failure triggers."  
- **Prompt #3**: "Confirm how bus bar protection can disconnect multiple lines simultaneously."  
- **Prompt #4**: "Assess the vulnerability of PBDF in substation control logic."

---

## Scenario 5: Defending Against ARP Spoofing in IEC 61850 Networks

**Background**  
A regional power distribution company's IT security team has found evidence of ARP spoofing attempts targeting  
the communication among Intelligent Electronic Devices (IEDs) within their IEC 61850 network.

### Question 1 (Q1)  
**Difficulty Level: Medium**  

> **What is the most effective method to detect ARP spoofing in IEC 61850 networks?**

1. **Anomaly and Intrusion detection systems (4 Points)**  
2. Algorithms to detect ARP Cache Poisoning (3 Points)  
3. IP whitelisting of incoming connections for authorized clients (2 Points)  
4. End-to-end encryption and passwords (1 Point)  
5. Others. (0 points)

**Logic for Highest Rated Answer**  
Uses pre-defined signatures, network-traffic baselines, and heuristic analysis to detect intrusions.

#### Follow-up Question for Q1
> _Could you please explain your reasoning for selecting that particular response?_

1. It directly monitors for signs of intrusion based on anomalies for the baseline (4 Points).  
2. It can specifically identify ARP-related anomalies (3 Points).  
3. It restricts network access to trusted devices (2 Points).  
4. It secures data transmission from end to end (1 Point).  
5. Others. (0 points)

### Sample Prompt Sequence (Q1)

- **Prompt #1**: "Ask how to best detect ARP spoofing in a 61850 substation network."  
- **Prompt #2**: "Compare general anomaly detection with targeted ARP cache-poisoning algorithms."  
- **Prompt #3**: "Clarify how intrusion detection baselines might identify abnormal ARP behaviors."  
- **Prompt #4**: "Evaluate the role of real-time monitoring vs. IP whitelisting for ARP attacks."

---

### Question 2 (Q2)  
**Difficulty Level: Difficult**  

> **What are the most direct damaging consequences of successful ARP spoofing on IED configuration files?**

1. Unwanted relay trip delays, causing cascading effects (3 Points)  
2. Alteration of voltage or current setpoints, risking equipment damage (2 Points)  
3. **Unexpected opening of circuit breakers, leading to instability (4 Points)**  
4. Altering of sensed voltage and current measurements by relays (1 Point)  
5. Others. (0 points)

**Logic for Highest Rated Answer**  
Sending an open command to the circuit breaker can directly remove devices from the network.

#### Follow-up Question for Q2
> _Could you please explain your reasoning for selecting that particular response?_

1. It represents the most immediate and dangerous impact. (4 Points)  
2. It could cause long-term damage to infrastructure. (2 Points)  
3. It poses a direct threat to system stability. (3 Points)  
4. It compromises the accuracy of critical monitoring data. (1 Point)  
5. Others. (0 points)

### Sample Prompt Sequence (Q2)

- **Prompt #1**: "Ask which direct impact of ARP spoofing is most severe in IED configurations."  
- **Prompt #2**: "Compare breaker-tripping with changes to voltage/current setpoints."  
- **Prompt #3**: "Evaluate how opening circuit breakers leads to wider network disruptions."  
- **Prompt #4**: "Confirm severity of immediate disconnections vs. longer-term damage."

---

## Scenario 6: Countering BlackEnergy3 in SCADA Systems

**Background**  
A national power grid operator has been warned about potential BlackEnergy3 malware attacks targeting their  
SCADA systems. This malware could overwrite firmware, disrupt operations, and use stolen credentials for  
further attacks.

### Question 1 (Q1)  
**Difficulty Level: Difficult**  

> **How can BlackEnergy3 best exploit its capabilities to overwrite firmware and disrupt IEDs during an  
> attack on power grid SCADA systems and create maximum damage?**

1. Stealing login credentials and other sensitive data (2 Points).  
2. Disrupting critical infrastructure operations through DDoS attacks (3 Points).  
3. Identifying and patching vulnerabilities within ICS systems (1 Point).  
4. **Creating botnets of compromised devices for further attacks (4 Points).**  
5. Others. (0 points).

**Logic for Highest Rated Answer**  
Creating botnets of compromised devices provides the best exploit capability, based on TTP from the Ukraine  
power-outage incident.

#### Follow-up Question for Q1
> _Could you please explain your reasoning for selecting that particular response?_

1. It creates the maximum damage by exploiting other vulnerable devices. (4 Points).  
2. It will launch a DDoS attack only (3 Points).  
3. It just rewrites the firmware without any further damages (1 Point).  
4. It will just steal login credentials (2 Points).  
5. Others. (0 points).

### Sample Prompt Sequence (Q1)

- **Prompt #1**: "Ask how BlackEnergy3 can cause widespread disruption in SCADA systems beyond credential theft."  
- **Prompt #2**: "Compare DDoS attacks vs. building a botnet of compromised IEDs or ICS devices."  
- **Prompt #3**: "Examine how multiple compromised devices amplify an attacker’s capabilities."  
- **Prompt #4**: "Confirm the link between botnet-based infiltration and large-scale grid outages."

---

### Question 2 (Q2)  
**Difficulty Level: Medium**  

> **Which initial attack method is most likely used by adversaries deploying BlackEnergy3 against power grid systems?**

1. Physical tampering with systems (1 Point).  
2. Phishing emails (3 Points).  
3. Direct network intrusion (2 Points).  
4. **Social engineering (4 Points).**  
5. Others. (0 points).

#### Follow-up Question for Q2
> _Could you please explain your reasoning for selecting that particular response?_

1. It is the most direct and forceful approach. (1 Point).  
2. It exploits human vulnerabilities effectively. (4 Points).  
3. It offers stealthy access to network systems. (2 Points).  
4. It bypasses most conventional security measures. (3 Points).  
5. Others. (0 points).

### Sample Prompt Sequence (Q2)

- **Prompt #1**: "Ask about the primary entry vector BlackEnergy3 attackers typically use in power grids."  
- **Prompt #2**: "Compare social engineering with physical tampering for initial compromise."  
- **Prompt #3**: "Discuss how phishing and social engineering overlap in leveraging human error."  
- **Prompt #4**: "Check whether infiltration is easier through user deception or direct network exploits."

---

## Scenario 7: Security of Smart Grid Communication Networks

**Background**  
A utility company is upgrading its grid to a smart grid system, which includes AMI (advanced metering  
infrastructure), intelligent appliances, and automated substations. However, this increased connectivity also  
introduces new vulnerabilities, particularly in the AMI.

### Question 1 (Q1)  
**Difficulty Level: Medium**  

> **What is the most effective security measure for protecting AMI communications from eavesdropping and data manipulation?**

1. **Encryption of data at transit using AES-256 (4 Points)**  
2. Implementing frequency hopping spread spectrum (FHSS) (1 Point)  
3. Utilization of public key infrastructure (PKI) for device authentication (3 Points)  
4. Application of whitelisting for all connecting devices (2 Points)  
5. Others. (0 points)

**Logic for Highest Rated Answer**  
It secures data from being intercepted during transmission.

#### Follow-up Question for Q1
> _Could you please explain your reasoning for selecting that particular response?_

1. **It secures data from being intercepted during transmission. (4 Points)**  
2. It prevents interception by rapidly changing transmission frequencies. (1 Point)  
3. It ensures that only verified devices can communicate. (3 Points)  
4. It restricts device connections to those explicitly allowed. (2 Points)  
5. Others. (0 points)

### Sample Prompt Sequence (Q1)

- **Prompt #1**: "Ask which security measure best protects AMI communications from interception."  
- **Prompt #2**: "Compare AES-256 encryption with PKI for device authentication."  
- **Prompt #3**: "Confirm how in-transit encryption mitigates eavesdropping or data tampering."  
- **Prompt #4**: "Evaluate whitelisting vs. encryption for preventing unauthorized access."

---

### Question 2 (Q2)  
**Difficulty Level: Difficult**  

> **How can the utility company ensure the highest data integrity and authenticity in smart grid operations?**

1. **Using HMAC (Hash-based Message Authentication Code) for data integrity checks (4 Points)**  
2. Regular checksum validations (1 Point)  
3. Role-based access controls (RBAC) on data endpoints (3 Points)  
4. Time-stamping all transmitted data (2 Points)  
5. Others. (0 points)

**Logic for Highest Rated Answer**  
It provides a secure method to verify data origin and integrity.

#### Follow-up Question for Q2
> _Could you please explain your reasoning for selecting that particular response?_

1. **It provides a secure method to verify data origin and integrity. (4 Points)**  
2. It checks for data corruption during transmission. (1 Point)  
3. It restricts access based on user roles. (3 Points)  
4. It associates a verifiable time with data creation. (2 Points)  
5. Others. (0 points)

### Sample Prompt Sequence (Q2)

- **Prompt #1**: "Ask how to ensure maximum data integrity and authenticity for smart grid operations."  
- **Prompt #2**: "Compare HMAC to checksum-based methods for verifying authenticity."  
- **Prompt #3**: "Investigate how HMAC establishes both origin and integrity of transmitted data."  
- **Prompt #4**: "Confirm if RBAC alone can maintain authenticity or if cryptographic checks are essential."

---

## Scenario 8: Security of SCADA Systems

**Background**  
A device log-analysis tool for a utility's smart grid, installed in substations with minimal initial security  
controls, exhibited suspicious behavior. A software update without proper change-control policies granted  
an attacker remote access via an exposed VPN, compromising SCADA system devices. The attacker removed  
critical power lines, causing a cascading blackout as operators lost control.

### Question 1 (Q1)  
**Difficulty Level: Difficult**  

> **What is the most precise safeguard/countermeasure missing in the above scenario that resulted in  
> the mentioned outcome?**

1. Lack of inventory management policy (2 Points)  
2. **Inadequate Operation Technology (OT) equipment security guidelines (4 Points)**  
3. Lack of configuration management policy (1 Point)  
4. Inadequate security policy for OT (3 Points)  
5. Others.

**Logic for Highest Rated Answer**  
OT equipment guidelines are an integral part of security procedures; they should be followed for OT equipment installation.

#### Follow-up Question for Q1
> _Could you please explain your reasoning for selecting that particular response?_

1. Inadequate policy can lead to such problems. (3 Points)  
2. **Inadequate guidelines can lead to such problems. (4 Points)**  
3. The operator did not know what tool could be downloaded or installed. (1 Point)  
4. The security team did not know what software was in their inventory. (2 Points)  
5. Others.

### Sample Prompt Sequence (Q1)

- **Prompt #1**: "Ask which missing security procedure most likely led to the device compromise in SCADA systems."  
- **Prompt #2**: "Clarify the difference between OT equipment security guidelines and a general security policy."  
- **Prompt #3**: "Confirm how inadequate guidelines contribute to unregulated software installations."  
- **Prompt #4**: "Evaluate if stricter OT guidelines might have prevented the compromise."

---

### Question 2 (Q2)  
**Difficulty Level: Medium**  

> **Which one of the following factors has the highest impact in facilitating an attacker’s access to the  
> grid network?**

1. Inadequate OT security training and awareness program (2 Points)  
2. No security perimeter defined (1 Point)  
3. Logs were not analyzed for anomalies (3 Points)  
4. **Inadequate authentication, privileges, and access control in the log-analysis tool (4 Points)**

**Logic for Highest Rated Answer**  
A user should only have the least privileges and permission.

#### Follow-up Question for Q2
> _Could you please explain your reasoning for selecting that particular response?_

1. OT security training educates authenticated users on cyber threats. (2 Points)  
2. Logs are essential to trace back past events. (3 Points)  
3. Security perimeter helps to protect the boundaries of a network. (1 Point)  
4. **A user should only have the least privileges and permission. (4 Points)**  
5. Others.

### Sample Prompt Sequence (Q2)

- **Prompt #1**: "Ask which factor most directly contributed to the attacker's access to the grid network."  
- **Prompt #2**: "Compare inadequate privileges vs. lack of perimeter or log analysis."  
- **Prompt #3**: "Investigate how least privilege principles would prevent unauthorized escalation."  
- **Prompt #4**: "Confirm the importance of granular access control in a SCADA environment."

---

_**End of Questionnaire**_

This document offers a structure for question-answer interactions within various power grid cybersecurity  
scenarios. Each question includes a sample prompt sequence, illustrating how participants might query  
a Generative AI system multiple times. The scoring framework correlates the number of prompts used to  
reach a correct conclusion with the final score, promoting efficient and strategic question formulation.
