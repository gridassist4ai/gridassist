* Encoding: UTF-8.


/* Research Title: Impact of Generative AI on Cybersecurity Posture of Critical Infrastructure 


/*Upload Data
    
GET DATA
  /TYPE=XLSX
  /FILE='c:\spss\responses.xlsx'
  /SHEET=name 'responses'
  /CELLRANGE=FULL
  /READNAMES=ON
  /DATATYPEMIN PERCENTAGE=95.0
  /HIDDEN IGNORE=YES.
EXECUTE.
DATASET NAME DataSet1 WINDOW=FRONT.
PreQ1FDIElabourate_num


/* ######################## Data Preperation #######################################

* Recode the string variable Age .
RECODE Age ("18-25 Yrs"=1) ("25 - 35 Yrs"=2) ("35 - 50 Yrs"=3) ("50 & above"=4)  INTO Age_num .
VARIABLE LABELS Age_num "Age (numeric)" .
FORMATS Age_num (F1.0) .
ADD VALUE LABELS Age_num
    1 "18-25 Yrs"
    2 "25 - 35 Yrs"
    3 "35 - 50 Yrs"
    4 "50 & above" .
EXECUTE.

* Recode the string variable Gender .
RECODE Gender ("Female"=1) ("Male"=2) ("Prefer not to answer"=3) INTO Gender_num .
VARIABLE LABELS Gender_num " Gender (numeric)" .
FORMATS Gender_num (F1.0) .
ADD VALUE LABELS Gender_num
    1 "Female"
    2 "Male" 
    3 "Prefer not to answer" .
EXECUTE.

* Recode the string variable WorkStatus .

RECODE WorkStatus ('Employed'=1) ('Studying'=2) ('Unemployed'=3) INTO WorkStatus_num.
VARIABLE LABELS  WorkStatus_num 'WorkStatus_num'.
FORMATS WorkStatus_num (F1.0) .
ADD VALUE LABELS WorkStatus_num
    1 "Employed"
    2 "Studying" 
    3 "Unemployed" .
EXECUTE.

* Recode the string variable Country .
RECODE Country ('Singapore'=1) ('India'=2) (ELSE=3) INTO Country_num.
VARIABLE LABELS  Country_Num 'Country (numeric)'.
FORMATS Country_Num (F1.0) .
ADD VALUE LABELS Country_Num
    1 "Singapore"
    2 "India" 
    3 "RoW" .
EXECUTE.

* Recode the string variable Education .
RECODE Education ('Graduate'=1) ('Post Graduate'=2) ('Diploma'=3) ('Doctorate '=2) ('Prefer not '+
    'to answer'=4) INTO Education_num.
FORMATS Education_num (F1.0) .
VARIABLE LABELS  Education_num 'Education (numeric)'.
ADD VALUE LABELS Education_Num
    1 "Graduate"
    2 "Post Graduate & Above" 
    3 "Diploma"
    4 "Prefer not to answer" .
EXECUTE.

* Recode the string variable Understanding of Powergrid .
RECODE UnderstandingOfPowerGrid (1=1) (0=0)  INTO UnderstandingOfPowerGrid_num.
FORMATS UnderstandingOfPowerGrid_num (F1.0) .
VARIABLE LABELS UnderstandingOfPowerGrid_num 'UnderstandingOfPowerGrid (numeric)'.
ADD VALUE LABELS UnderstandingOfPowerGrid_num
    1 "Yes"
    0 "No" .
EXECUTE.

* Recode the string variable Understanding of PowerGrid Security .
RECODE UnderstandingOfPowerGridSecurity (1=1) (0=0)  INTO UnderstandingOfPowerGridSecurity_num.
FORMATS UnderstandingOfPowerGridSecurity_num (F1.0) .
VARIABLE LABELS  UnderstandingOfPowerGridSecurity_num 'UnderstandingOfPowerGridSecurity (numeric)'.
ADD VALUE LABELS UnderstandingOfPowerGridSecurity_num
    1 "Yes"
    0 "No" .
EXECUTE.

* Recode the string variable SharedExperience .
RECODE SharedExperience (1=1) (ELSE=2) INTO SharedExperience_num.
VARIABLE LABELS  SharedExperience_num 'SharedExperience (numeric)'.
FORMATS SharedExperience_num (F1.0) .
ADD VALUE LABELS SharedExperience_num
    1 "Yes"
    2 "No" .
EXECUTE.


/* RECODING RESPONSE VALUES /*
    
* PreQ1-Q1

RECODE PreQ1RemoteAccess ('Determination of specific roles on the system and grouping access '+
    'privileges to each role (Role-Based Access)'=3) ('Identity-based authentication and critical '+
    'public infrastructure (PKI) methods'=4) ('IP whitelisting of incoming connections for '+
    'authorized clients'=1) ('Strict password policies for user authentication'=2) (''=0) INTO 
    PreQ1RemoteAccess_num.
VARIABLE LABELS  PreQ1RemoteAccess_num 'PreQ1RemoteAccess_num'.
FORMATS PreQ1RemoteAccess_num (F1.0) 
ADD VALUE LABELS PreQ1RemoteAccess_num
    1 "IP Whitelisting"
    2 "Strict Password Policy"
    3 "Role Based Access"
    4 "PKI Method"
    0 "Others" .
EXECUTE.

* PreQ1-Q1-FollowUp

RECODE PreQ1RemoteAccessElaborate ('It effectively restricts access based on job roles'=3) ('It '+
    'provides the most robust authentication mechanism'=4) ('It only allows access from '+
    'pre-approved IP addresses'=2) ('It ensures that passwords are strong and regularly updated '=1) (''=0) INTO PreQ1RemoteAccessElaborate_num.
VARIABLE LABELS  PreQ1RemoteAccessElaborate_num 'PreQ1RemoteAccessElaborate_num'.
VARIABLE LABELS  PreQ1RemoteAccess_num 'PreQ1RemoteAccess_num'.
FORMATS PreQ1RemoteAccessElaborate_num (F1.0) 
ADD VALUE LABELS PreQ1RemoteAccessElaborate_num
    1 "Strong Password"
    2 "IP whitelisting"
    3 "Role Based Access"
    4 "Real Time Authentication"
    0 "Others" .
EXECUTE.

* PreQ1-Q2
    
RECODE PreQ1FDI ('Secure control methodologies'=3) ('Anomaly detection methods (Identify '+
    'suspicious patterns)'=4) ('Encryption-based techniques'=2) ('Redundant data transmission'=1) 
    (MISSING=0) INTO PreQ1FDI_num.
VARIABLE LABELS  PreQ1FDI_num 'PreQ1FDI_num'.
FORMATS PreQ1FDI_num (F1.0) 
ADD VALUE LABELS PreQ1FDI_num
    1 "Redundant Data"
    2 "Encryption Based Method"
    3 "Secure Control Method"
    4 "Identify Suspicous Patern"
    0 "Others" .
EXECUTE.
 

* PreQ1-Q2-FollowUp

RECODE PreQ1FDIElabourate ('It secures commands and controls against unauthorized changes'=3) 
    ('It detects unusual patterns that indicate tampering'=4) ('It ensures data integrity and '+
    'confidentiality'=2) ('It provides multiple data sources for verification'=1) (MISSING=0) INTO 
    PreQ1FDIElabourate_num.
VARIABLE LABELS  PreQ1FDIElabourate_num 'PreQ1FDIElabourate_num'.
FORMATS PreQ1FDIElabourate_num (F1.0) 
ADD VALUE LABELS PreQ1FDIElabourate_num
    1 "Multi Data Source"
    2 "Data Integrity & confidentiality"
    3 "Secures Command & Control"
    4 "Detects unusual patterns"
    0 "Others" .
EXECUTE.


* PreQ2-Q1


RECODE PreQ2DER ('Implementation of TLS/SSL for data encryption in transit'=2) 
    ('Use of a protocol (IEC 60870-5, IEC 61850-7-420) with enhanced authentication'=4) 
    ('Deployment of secure VPN tunnels for remote connections'=1) 
    ('Enforcing IEEE 1815 (DNP3) with secure authentication'=3) 
    (''=0) INTO PreQ2DER_num.
VARIABLE LABELS PreQ2DER_num 'PreQ2DER_num'.
FORMATS PreQ2DER_num (F1.0) 
ADD VALUE LABELS PreQ2DER_num
    1 "Secure VPN Tunnels"
    2 "TLS/SSL Encryption"
    3 "IEEE 1815 (DNP3)"
    4 "Enhanced Authentication"
    0 "Others" .
EXECUTE.

* PreQ2-Q1-Followup 
 
RECODE PreQ2DERElabourate ('It provides end-to-end encryption'=3) 
    ('It offers both encryption and reliable data flow'=4) 
    ('It creates a secure channel for remote access'=1) 
    ('It is specifically designed for utility communications'=2) 
    (''=0) INTO PreQ2DERElabourate_num.
VARIABLE LABELS PreQ2DERElabourate_num 'PreQ2DERElabourate_num'.
FORMATS PreQ2DERElabourate_num (F1.0) 
ADD VALUE LABELS PreQ2DERElabourate_num
    1 "Secure Channel for Remote Access"
    2 "Utility Communications Design"
    3 "End-to-End Encryption"
    4 "Encryption and Reliable Data Flow"
    0 "Others" .
EXECUTE.   

* PreQ2-Q2

RECODE PreQ2DERThreat ('Regular penetration testing of the network'=3) 
    ('Continuous monitoring with SIEM (Security Information & Event Management) systems'=4) 
    ('Periodic updates and patch management.'=2) 
    ('Deployment of anomaly detection systems at each DER node'=1) 
    (''=0) INTO PreQ2DERThreat_num.
VARIABLE LABELS PreQ2DERThreat_num 'PreQ2DERThreat_num'.
FORMATS PreQ2DERThreat_num (F1.0) 
ADD VALUE LABELS PreQ2DERThreat_num
    1 "Anomaly Detection Systems"
    2 "Periodic Updates and Patch Management"
    3 "Penetration Testing"
    4 "Continuous Monitoring with SIEM"
    0 "Others" .
EXECUTE.

* PreQ2-Q2-Followup

RECODE PreQ2DERThreatElabourate ('It identifies vulnerabilities before exploitation.'=3) 
    ('It provides real-time threat analysis and response'=4) 
    ('It ensures all components are up-to-date'=2) 
    ('It detects unusual patterns specific to each node.'=1) 
    (''=0) INTO PreQ2DERThreatElabourate_num.
VARIABLE LABELS PreQ2DERThreatElabourate_num 'PreQ2DERThreatElabourate_num'.
FORMATS PreQ2DERThreatElabourate_num (F1.0) 
ADD VALUE LABELS PreQ2DERThreatElabourate_num
    1 "Detects Unusual Patterns"
    2 "Components Up-to-Date"
    3 "Identifies Vulnerabilities"
    4 "Real-Time Threat Analysis"
    0 "Others" .
EXECUTE.

* PreQ3-Q1

RECODE PreQ3WAMS ('Denial of Service (DoS) attack'=2) 
    ('Time Synchronization Attack'=1) 
    ('Coordinated False Data Injection (FDI) Attack'=4) 
    ('Man-in-the-Middle (MiTM) Attack'=3) 
    (''=0) INTO PreQ3WAMS_num.
VARIABLE LABELS PreQ3WAMS_num 'PreQ3WAMS_num'.
FORMATS PreQ3WAMS_num (F1.0) 
ADD VALUE LABELS PreQ3WAMS_num
    1 "Time Synchronization Attack"
    2 "Denial of Service (DoS) attack"
    3 "Man-in-the-Middle (MiTM) Attack"
    4 "Coordinated False Data Injection (FDI) Attack"
    0 "Others" .
EXECUTE.


* PreQ3-Q1-Followup 
    
RECODE PreQ3WAMSElabourate ('DoS will prevent receiving real time data at control center'=2) 
    ('Time Synchronization is critical for all applications'=1) 
    ('False data from multiple devices can cause wrong interference of system state'=4) 
    ('MiTM can modify data in between communication'=3) 
    (''=0) INTO PreQ3WAMSElabourate_num.
VARIABLE LABELS PreQ3WAMSElabourate_num 'PreQ3WAMSElabourate_num'.
FORMATS PreQ3WAMSElabourate_num (F1.0) 
ADD VALUE LABELS PreQ3WAMSElabourate_num
    1 "Time Synchronization Criticality"
    2 "DoS Prevention of Real-Time Data"
    3 "MiTM Data Modification"
    4 "False Data Injection Impact"
    0 "Others" .
EXECUTE.
    
* PreQ3-Q2

RECODE PreQ3Attack ('Compromise one or multiple PMUs'=3) 
    ('Compromise wired links in between'=2) 
    ('Compromise the internet facing Routers'=4) 
    ('Compromise PDC'=1) 
    (''=0) INTO PreQ3Attack_num.
VARIABLE LABELS PreQ3Attack_num 'PreQ3Attack_num'.
FORMATS PreQ3Attack_num (F1.0) 
ADD VALUE LABELS PreQ3Attack_num
    1 "Compromise PDC"
    2 "Compromise Wired Links"
    3 "Compromise PMUs"
    4 "Compromise Internet Facing Routers"
    0 "Others" .
EXECUTE.

* PreQ3-Q2-Followup

RECODE PreQ3AttackElabourate ('Physical access to the link is easy to achieve'=2) 
    ('A router is a link between commercial and control systems, exposed to the internet'=4) 
    ('PDC physical access is easy as it is not protected by proper authorization'=1) 
    ('PMUs may have zero-day vulnerabilities that can be exploited easily.'=3) 
    (''=0) INTO PreQ3AttackElabourate_num.
VARIABLE LABELS PreQ3AttackElabourate_num 'PreQ3AttackElabourate_num'.
FORMATS PreQ3AttackElabourate_num (F1.0) 
ADD VALUE LABELS PreQ3AttackElabourate_num
    1 "PDC Physical Access Ease"
    2 "Physical Access to Links"
    3 "PMUs Zero-Day Vulnerabilities"
    4 "Router Exposure"
    0 "Others" .
EXECUTE.




* PreQ4-Q1

RECODE PreQ4IEDAttack ('ICD (IED Capability Description)'=2) 
    ('SCD (Station Configuration Description)'=1) 
    ('CID (Configured IED Description)'=3) 
    ('IID (Instantiated IED Description)'=4) 
    (''=0) INTO PreQ4IEDAttack_num.
VARIABLE LABELS PreQ4IEDAttack_num 'PreQ4IEDAttack_num'.
FORMATS PreQ4IEDAttack_num (F1.0) 
ADD VALUE LABELS PreQ4IEDAttack_num
    1 "SCD (Station Configuration Description)"
    2 "ICD (IED Capability Description)"
    3 "CID (Configured IED Description)"
    4 "IID (Instantiated IED Description)"
    0 "Others" .
EXECUTE.


* PreQ4-Q1-Followup 
 
RECODE PreQ4IEDAttackElabourate ('ICD file defines the complete capability range of an IED'=2) 
    ('SCD file describes the entire substation in detail'=1) 
    ('CID file contains everything that is needed from SCD to configure an IED'=3) 
    ('IID file defines the configuration of an IED for a specific project.'=4) 
    (''=0) INTO PreQ4IEDAttackElabourate_num.
VARIABLE LABELS PreQ4IEDAttackElabourate_num 'PreQ4IEDAttackElabourate_num'.
FORMATS PreQ4IEDAttackElabourate_num (F1.0) 
ADD VALUE LABELS PreQ4IEDAttackElabourate_num
    1 "SCD File Description"
    2 "ICD File Capability"
    3 "CID File Configuration"
    4 "IID File Project Specific Configuration"
    0 "Others" .
EXECUTE.
    
* PreQ4-Q2

RECODE PreQ4IEDAttackLine ('PTRC.Tr.General'=1) 
    ('PBDF.DifAClc. rangeC.min.f'=4) 
    ('PLDF.DifAClc.LoSet'=3) 
    ('RBRF.OpE'=2) 
    (''=0) INTO PreQ4IEDAttackLine_num.
VARIABLE LABELS PreQ4IEDAttackLine_num 'PreQ4IEDAttackLine_num'.
FORMATS PreQ4IEDAttackLine_num (F1.0) 
ADD VALUE LABELS PreQ4IEDAttackLine_num
    1 "PTRC.Tr.General"
    2 "RBRF.OpE"
    3 "PLDF.DifAClc.LoSet"
    4 "PBDF.DifAClc. rangeC.min.f"
    0 "Others" .
EXECUTE.


* PreQ4-Q2-Followup

RECODE PreQ4IEDAttackLineElabourate ('PTRC is related to Protection Trip Conditioning'=1) 
    ('PBDF is related to Bus bar protection'=4) 
    ('PLDF is related to Line differential protection'=3) 
    ('RBRF is related to Breaker Failure protection'=2) 
    (''=0) INTO PreQ4IEDAttackLineElabourate_num.
VARIABLE LABELS PreQ4IEDAttackLineElabourate_num 'PreQ4IEDAttackLineElabourate_num'.
FORMATS PreQ4IEDAttackLineElabourate_num (F1.0) 
ADD VALUE LABELS PreQ4IEDAttackLineElabourate_num
    1 "Protection Trip Conditioning (PTRC)"
    2 "Breaker Failure Protection (RBRF)"
    3 "Line Differential Protection (PLDF)"
    4 "Bus Bar Protection (PBDF)"
    0 "Others" .
EXECUTE.


*##### Post Training Score Starts ########

* PostQ1-Q1

*  Most effective method to detect ARP spoofing in IEC 61850 networks (PostQ1ARPSpoofing).

RECODE PostQ1ARPSpoofing ('Anomaly and Intrusion detection systems'=4) 
    ('Algorithms to detect ARP Cache Poisoning'=3) 
    ('IP whitelisting of incoming connections for authorized clients'=2) 
    ('End-to-end encryption and passwords'=1) 
    (''=0) INTO PostQ1ARPSpoofing_num.
VARIABLE LABELS PostQ1ARPSpoofing_num 'PostQ1ARPSpoofing_num'.
FORMATS PostQ1ARPSpoofing_num (F1.0) 
ADD VALUE LABELS PostQ1ARPSpoofing_num
    1 "End-to-end encryption and passwords"
    2 "IP whitelisting of incoming connections"
    3 "Algorithms to detect ARP Cache Poisoning"
    4 "Anomaly and Intrusion detection systems"
    0 "Others" .
EXECUTE.

* PostQ1-Q1-Followup 

* Follow-up Question : Reason for selecting ARP spoofing detection method (PostQ1ARPSpoofingElabourate).

RECODE PostQ1ARPSpoofingElabourate ('It directly monitors for signs of intrusion based on anomaly for the baseline'=4) 
    ('It can specifically identify ARP-related anomalies'=3) 
    ('It restricts network access to trusted'=2) 
    ('It secures data transmission from end to end'=1) 
    (''=0) INTO PostQ1ARPSpoofingElabourate_num.
VARIABLE LABELS PostQ1ARPSpoofingElabourate_num 'PostQ1ARPSpoofingElabourate_num'.
FORMATS PostQ1ARPSpoofingElabourate_num (F1.0) 
ADD VALUE LABELS PostQ1ARPSpoofingElabourate_num
    1 "Secures data transmission from end to end"
    2 "Restricts network access to trusted devices"
    3 "Identifies ARP-related anomalies"
    4 "Monitors for signs of intrusion"
    0 "Others" .
EXECUTE.

* PostQ1-Q2

* Most direct damaging consequences of successful ARP spoofing on IED configuration files (PostQ1ARPImpact).

RECODE PostQ1ARPImpact ('Unwanted relay trip delays, causing cascading effects'=3) 
    ('Alteration of voltage or current setpoints, risking equipment damage'=2) 
    ('Unexpected opening of circuit breakers, leading to instability'=4) 
    ('Altering of sensed voltage and current measurements by relays'=1) 
    ('Others.'=0) INTO PostQ1ARPImpact_num.
VARIABLE LABELS PostQ1ARPImpact_num 'PostQ1ARPImpact_num'.
FORMATS PostQ1ARPImpact_num (F1.0) 
ADD VALUE LABELS PostQ1ARPImpact_num
    1 "Altering sensed voltage and current measurements"
    2 "Alteration of voltage or current setpoints"
    3 "Unwanted relay trip delays"
    4 "Unexpected opening of circuit breakers"
    0 "Others" .
EXECUTE.


* PostQ1-Q2-Followup


*  Reason for selecting the consequence of ARP spoofing (PostQ1ARPImpactElabourate).

RECODE PostQ1ARPImpactElabourate ('It represents the most immediate and dangerous impact'=4) 
    ('It could cause long-term damage to infrastructure'=2) 
    ('It poses a direct threat to system stability'=3) 
    ('It compromises the accuracy of critical monitoring data.('=1) 
    (''=0) INTO PostQ1ARPImpactElabourate_num.
VARIABLE LABELS PostQ1ARPImpactElabourate_num 'PostQ1ARPImpactElabourate_num'.
FORMATS PostQ1ARPImpactElabourate_num (F1.0) 
ADD VALUE LABELS PostQ1ARPImpactElabourate_num
    1 "Compromises accuracy of monitoring data"
    2 "Causes long-term damage to infrastructure"
    3 "Poses threat to system stability"
    4 "Most immediate and dangerous impact"
    0 "Others" .
EXECUTE.

    
* PostQ2-Q2

* Q: How can BlackEnergy3 best exploit its capabilities to overwrite firmware and disrupt IEDs during an attack on power grid SCADA systems & create maximum damage (PostQ2BlackEnergy).

RECODE PostQ2BlackEnergy ('Stealing login credentials and other sensitive data'=2) 
    ('Disrupting critical infrastructure operations through DDoS attacks'=3) 
    ('Identifying and patching vulnerabilities within ICS systems'=1) 
    ('Creating botnets of compromised devices for further attacks'=4) 
    (''=0) INTO PostQ2BlackEnergy_num.
VARIABLE LABELS PostQ2BlackEnergy_num 'PostQ2BlackEnergy_num'.
FORMATS PostQ2BlackEnergy_num (F1.0) 
ADD VALUE LABELS PostQ2BlackEnergy_num
    1 "Identifying and patching vulnerabilities"
    2 "Stealing login credentials"
    3 "Disrupting operations through DDoS attacks"
    4 "Creating botnets"
    0 "Others" .
EXECUTE.

* Follow-up Question for Q: Reason for selecting this method (PostQ2BlackEnergyElabourate).

RECODE PostQ2BlackEnergyElabourate ('It creates the maximum damage by exploiting other vulnerable devices'=4) 
    ('It will launch a DDoS attack only'=3) 
    ('It just rewrites the firmware without any further damages'=1) 
    ('It will just steal login credentials'=2) 
    (''=0) INTO PostQ2BlackEnergyElabourate_num.
VARIABLE LABELS PostQ2BlackEnergyElabourate_num 'PostQ2BlackEnergyElabourate_num'.
FORMATS PostQ2BlackEnergyElabourate_num (F1.0) 
ADD VALUE LABELS PostQ2BlackEnergyElabourate_num
    1 "Just rewrites firmware or steals credentials"
    3 "Launches DDoS attack only"
    4 "Creates maximum damage"
    0 "Others" .
EXECUTE.

* Q: Which initial attack method is most likely used by adversaries deploying BlackEnergy3 against power grid systems (PostQ2BlackEnergyAttackMethod).

RECODE PostQ2BlackEnergyAttackMethod ('Physical tampering with systems'=1) 
    ('Phishing emails'=3) 
    ('Direct network intrusion'=2) 
    ('Social engineering'=4) 
    (''=0) INTO PostQ2BlackEnergyAttackMethod_num.
VARIABLE LABELS PostQ2BlackEnergyAttackMethod_num 'PostQ2BlackEnergyAttackMethod_num'.
FORMATS PostQ2BlackEnergyAttackMethod_num (F1.0) 
ADD VALUE LABELS PostQ2BlackEnergyAttackMethod_num
    1 "Physical tampering"
    2 "Direct network intrusion"
    3 "Phishing emails"
    4 "Social engineering"
    0 "Others" .
EXECUTE.

* Follow-up Question for Q: Reason for selecting the initial attack method (PostQ2BlackEnergyAttackMethodElabourate).

RECODE PostQ2BlackEnergyAttackMethodElabourate ('It is the most direct and forceful approach'=1) 
    ('It exploits human vulnerabilities effectively'=4) 
    ('It offers stealthy access to network systems'=2) 
    ('It bypasses most conventional security measures'=3) 
    (''=0) INTO PostQ2BlackEnergyAttackMethodElabourate_num.
VARIABLE LABELS PostQ2BlackEnergyAttackMethodElabourate_num 'PostQ2BlackEnergyAttackMethodElabourate_num'.
FORMATS PostQ2BlackEnergyAttackMethodElabourate_num (F1.0) 
ADD VALUE LABELS PostQ2BlackEnergyAttackMethodElabourate_num
    1 "Direct and forceful approach"
    2 "Stealthy access"
    3 "Bypasses security measures"
    4 "Exploits human vulnerabilities"
    0 "Others" .
EXECUTE.



* PostQ3-Q1

* Q: Most effective security measure for protecting AMI communications from eavesdropping and data manipulation (PostQ3DataIntegrity).

RECODE PostQ3AMI ('Encryption of data at transit using AES-256'=4) 
    ('Implementing frequency hopping spread spectrum (FHSS)'=1) 
    ('Utilization of public key infrastructure (PKI) for device authentication'=3) 
    ('Application of whitelisting for all connecting devices'=2) 
    (''=0) INTO PostQ3AMI_num.
VARIABLE LABELS PostQ3DataIntegrity_num 'PostQ3AMI_num'.
FORMATS PostQ3AMI_num (F1.0) 
ADD VALUE LABELS PostQ3AMI_num
    1 "Frequency hopping spread spectrum (FHSS)"
    2 "White-listing for connecting devices"
    3 "Public key infrastructure (PKI)"
    4 "Encryption using AES-256"
    0 "Others" .
EXECUTE.

* Follow-up Question for Q: Reason for choosing this security measure for AMI communications (PostQ3DataIntegrityElabourate).

RECODE PostQ3AMIElabourate ('It secures data from being intercepted during transmission'=4) 
    ('It prevents interception by rapidly changing transmission frequencies'=1) 
    ('It ensures that only verified devices can communicate.'=3) 
    ('It restricts device connections to those explicitly allowed'=2) 
    (''=0) INTO PostQ3AMIElabourate_num.
VARIABLE LABELS PostQ3AMIElabourate_num 'PostQ3AMIElabourate_num'.
FORMATS PostQ3AMIElabourate_num (F1.0) 
ADD VALUE LABELS PostQ3AMIElabourate_num
    1 "Prevents interception by changing frequencies"
    2 "Restricts device connections"
    3 "Ensures only verified devices can communicate"
    4 "Secures data during transmission"
    0 "Others" .
EXECUTE.

* Q: How can the utility company ensure highest data integrity and authenticity in smart grid operations (PostQ3DataIntegrity).

RECODE PostQ3DataIntegrity ('Using HMAC (Hash-based Message Authentication Code) for data integrity checks'=4) 
    ('Regular checksum validations'=1) 
    ('Role-based access controls (RBAC) on data endpoints'=3) 
    ('Time-stamping all transmitted data'=2) 
    (''=0) INTO PostQ3DataIntegrity_num.
VARIABLE LABELS PostQ3DataIntegrity_num 'PostQ3DataIntegrity_num'.
FORMATS PostQ3DataIntegrity_num (F1.0) 
ADD VALUE LABELS PostQ3DataIntegrity_num
    1 "Regular checksum validations"
    2 "Time-stamping all data"
    3 "Role-based access controls (RBAC)"
    4 "Using HMAC for integrity checks"
    0 "Others" .
EXECUTE.

* Follow-up Question for Q:  Reason for selecting the method to ensure data integrity and authenticity (PostQ3DataIntegrityElabourate).

RECODE PostQ3DataIntegrityElabourate ('It provides a secure method to verify data origin and integrity.'=4) 
    ('It checks for data corruption during transmission'=1) 
    ('It restricts access based on user roles'=3) 
    ('It associates a verifiable time with data creation'=2) 
    (''=0) INTO PostQ3DataIntegrityElabourate_num.
VARIABLE LABELS PostQ3DataIntegrityElabourate_num 'PostQ3DataIntegrityElabourate_num'.
FORMATS PostQ3DataIntegrityElabourate_num (F1.0) 
ADD VALUE LABELS PostQ3DataIntegrityElabourate_num
    1 "Checks for data corruption"
    2 "Associates verifiable time with data"
    3 "Restricts access based on user roles"
    4 "Verifies data origin and integrity"
    0 "Others" .
EXECUTE.




* PostQ4-Q1

* Q: Vulnerabilities ignored while installing the tool into the control center (PostQ4ExposedVPN).

RECODE PostQ4ExposedVPN ('Lack of inventory management policy'=2) 
    ('Inadequate Operation Technology (OT) equipment security guidelines'=4) 
    ('Lack of configuration management policy'=1) 
    ('Inadequate security policy for OT'=3) 
    ('Others'=0) INTO PostQ4ExposedVPN_num.
VARIABLE LABELS PostQ4ExposedVPN_num 'PostQ4ExposedVPN_num'.
FORMATS PostQ4ExposedVPN_num (F1.0) 
ADD VALUE LABELS PostQ4ExposedVPN_num
    1 "Lack of configuration management policy"
    2 "Lack of inventory management policy"
    3 "Inadequate security policy for OT"
    4 "Inadequate OT equipment security guidelines"
    0 "Others" .
EXECUTE.

* Follow-up Question for Q: Reasoning for selecting the response (PostQ4ExposedVPNElabourate).

RECODE PostQ4ExposedVPNElabourate ('Inadequate policy can lead to such problems'=3) 
    ('Inadequate guidelines can lead to such problems'=4) 
    ('The operator did not know what tool could be downloaded or installed'=1) 
    ('The security team did not know what software was in their inventory'=2) 
    (''=0) INTO PostQ4ExposedVPNElabourate_num.
VARIABLE LABELS PostQ4ExposedVPNElabourate_num 'PostQ4ExposedVPNElabourate_num'.
FORMATS PostQ4ExposedVPNElabourate_num (F1.0) 
ADD VALUE LABELS PostQ4ExposedVPNElabourate_num
    1 "Operator lacked tool knowledge"
    2 "Security team lacked inventory knowledge"
    3 "Inadequate policy"
    4 "Inadequate guidelines"
    0 "Others" .
EXECUTE.

* Q: Inadequate measures relating to system security that contributed majorly to the attacker gaining access to grid networks (PostQ4ExposedVPNImpact).

RECODE PostQ4ExposedVPNImpact ('Inadequate OT security training and awareness program'=2) 
    ('No security perimeter defined'=1) 
    ('Logs were not analyzed for anomalies'=3) 
    ('Inadequate authentication, privileges, and access control in the log-analysis tool'=4) 
    (''=0) INTO PostQ4ExposedVPNImpact_num.
VARIABLE LABELS PostQ4ExposedVPNImpact_num 'PostQ4ExposedVPNImpact_num'.
FORMATS PostQ4ExposedVPNImpact_num (F1.0) 
ADD VALUE LABELS PostQ4ExposedVPNImpact_num
    1 "No security perimeter"
    2 "Inadequate OT security training"
    3 "Logs not maintained"
    4 "Inadequate authentication and access control"
    0 "Others" .
EXECUTE.

* Follow-up Question for Q: Reason for selecting the inadequate measure (PostQ4ExposedVPNImpactElabourate).

RECODE PostQ4ExposedVPNImpactElabourate ('OT security training educates authenticated users on cyber threats'=2) 
    ('Logs are essential to trace back past events'=3) 
    ('Security perimeter helps to protect boundaries of a network'=1) 
    ('A user should only have the least privileges and permission'=4) 
    (''=0) INTO PostQ4ExposedVPNImpactElabourate_num.
VARIABLE LABELS PostQ4ExposedVPNImpactElabourate_num 'PostQ4ExposedVPNImpactElabourate_num'.
FORMATS PostQ4ExposedVPNImpactElabourate_num (F1.0) 
ADD VALUE LABELS PostQ4ExposedVPNImpactElabourate_num
    1 "Security perimeter protection"
    2 "OT security training"
    3 "Logs for back tracing"
    4 "Least privileges and permissions"
    0 "Others" .
EXECUTE.


 

* Encoding: UTF-8.

/* PRE TRAINING SCORING /*

/* Q1  add first and final to all variables/*   
   

COMPUTE PREQ1Total=PreQ1RemoteAccess_num+PreQ1RemoteAccessElaborate_num+PreQ1FDI_num+PreQ1FDIElabourate_num.
EXECUTE.

    

/* Q2 /* 


COMPUTE PreQ2Total=PreQ2DER_num+PreQ2DERElabourate_num+PreQ2DERThreat_num+PreQ2DERThreatElabourate_num.	
EXECUTE.


/* Q3 /* 


COMPUTE PreQ3Total=PreQ3WAMS_num+PreQ3WAMSElabourate_num+PreQ3Attack_num+PreQ3AttackElabourate_num.	
EXECUTE.

/* Q4 /* 


COMPUTE PreQ4Total=PreQ4IEDAttack_num+PreQ4IEDAttackElabourate_num+PreQ4IEDAttackLine_num+PreQ4IEDAttackLineElabourate_num.	
EXECUTE.

/* Total Score Pre-test /* 
COMPUTE PreTrainingScore=PreQ1Total+PreQ2Total + PreQ3Total + PreQ4Total.
FORMATS PreTrainingScore (F1.0) .
EXECUTE.    


/* POST TRAINING SCORING /*
    
/* Q1 /* 

COMPUTE PostQ1Total=PostQ1ARPSpoofing_num+PostQ1ARPSpoofingElabourate_num+PostQ1ARPImpact_num+PostQ1ARPImpactElabourate_num.
EXECUTE.

/* Q2 /* 

COMPUTE PostQ2Total=PostQ2BlackEnergy_num+PostQ2BlackEnergyElabourate_num+PostQ2BlackEnergyAttackMethod_num+PostQ2BlackEnergyAttackMethodElabourate_num.
EXECUTE.


/* Q3 /* 

COMPUTE PostQ3Total=PostQ3AMI_num+PostQ3AMIElabourate_num+PostQ3DataIntegrity_num+PostQ3DataIntegrityElabourate_num.
EXECUTE.

/* Q4 /* 

COMPUTE PostQ4Total= PostQ4ExposedVPN_num+PostQ4ExposedVPNElabourate_num+PostQ4ExposedVPNImpact_num+PostQ4ExposedVPNImpactElabourate_num.
EXECUTE.

/* Total Score Post-test /* 
COMPUTE PostTrainingScore=PostQ1Total+PostQ2Total + PostQ3Total + PostQ4Total.
FORMATS PostTrainingScore (F1.0) .
EXECUTE.    


/* Time Taken 

COMPUTE  time_for_completion=(SubmitDateUTC - StartDateUTC) / 60.
VARIABLE LABELS  time_for_completion "Time For Completing Survey".
VARIABLE LEVEL  time_for_completion (SCALE).
FORMATS  time_for_completion (F8.2).
VARIABLE WIDTH  time_for_completion(8).
EXECUTE.

/* Score

COMPUTE PostMinusPre=PostTrainingScore - PreTrainingScore.
FORMATS PostMinusPre (F1.0) .
EXECUTE.

/* Tagging by participation controlgroups (RU3, RU1, EnergyProfessionals)
    
* First, ensure that the "SubmitDateUTC" variable is in a date-time format.
FORMATS SubmitDateUTC (DATETIME16).

* Create a new variable to hold the group tags.
STRING GroupTag (A30).

* Convert the datetime to a date-only variable for comparison.
COMPUTE SubmitDateOnly = XDATE.DATE(SubmitDateUTC).
FORMATS SubmitDateOnly (DATE11).

* Tagging the data based on the specified dates.
IF (SubmitDateOnly = DATE.DMY(19, 7, 2024)) GroupTag = "RU3ControlGroup".
IF (SubmitDateOnly = DATE.DMY(20, 7, 2024)) GroupTag = "RU1ControlGroup1".
IF (SubmitDateOnly = DATE.DMY(29, 7, 2024)) GroupTag = "RU1ControlGroup2".
IF (SubmitDateOnly = DATE.DMY(4, 8, 2024)) GroupTag = "EnergySectorProfessionals".
* Tagging remaining entries as "InternetParticipation".
IF (GroupTag = "") GroupTag = "InternetParticipation".
EXECUTE.

* Tagging remaining entries as "InternetParticipation".
IF (GroupTag = "") GroupTag = "InternetParticipation".
EXECUTE.

RECODE GroupTag ('RU3ControlGroup'=1) ('InternetParticipation'=2) ('RU1ControlGroup1'=3) 
    ('RU1ControlGroup2'=4) ('PowerGridProfessionals'=5) INTO GroupTag_num.
VARIABLE LABELS  GroupTag_num 'GroupTag_num'.
FORMATS GroupTag_num (F1.0) .
ADD VALUE LABELS Gender_num
    1 "RU3ControlGroup"
    2 "InternetParticipation" 
    3 "RU1ControlGroup1"
    4 "RU1ControlGroup2"
    5 "EnergySectorProfessionals".
EXECUTE.


* Display the frequency of each tag to check.
FREQUENCIES VARIABLES=GroupTag.


/* Analysis 
    
* Encoding: UTF-8.



/* for discarding time based outliers i.e. participants who took less than 5 minutes and greater than 30 minutes 

/*COMPUTE Is_selected = ( time_for_completion > 5.00 AND time_for_completion < 30.00) .
/*FREQUENCIES VARIABLES=Is_selected .
/*SELECT IF Is_selected .
/*EXECUTE. 

/* No Straightliners identification and elimination as the testing platform randomizes the options 


* Frequency Analysis 
 
FREQUENCIES VARIABLES= Age_num time_for_completion.
  /ORDER=ANALYSIS.

FREQUENCIES VARIABLES=PreQ1Total
  /ORDER=ANALYSIS.

FREQUENCIES VARIABLES=PreQ2Total
  /ORDER=ANALYSIS.

FREQUENCIES VARIABLES=PreQ3Total
  /ORDER=ANALYSIS.

FREQUENCIES VARIABLES=PreQ4Total
  /ORDER=ANALYSIS.

FREQUENCIES VARIABLES=PostQ1Total
  /ORDER=ANALYSIS.

FREQUENCIES VARIABLES=PostQ2Total
  /ORDER=ANALYSIS.

FREQUENCIES VARIABLES=PostQ3Total
  /ORDER=ANALYSIS.

FREQUENCIES VARIABLES=PostQ4Total
  /ORDER=ANALYSIS.

FREQUENCIES VARIABLES=PreTrainingScore
  /ORDER=ANALYSIS.

FREQUENCIES VARIABLES=PostTrainingScore
  /ORDER=ANALYSIS.


FREQUENCIES
    VARIABLES=PreTrainingScore
    /HIST=NORMAL .

FREQUENCIES
    VARIABLES=PostTrainingScore
    /HIST=NORMAL .

FREQUENCIES VARIABLES=Country_num
  /ORDER=ANALYSIS.

FREQUENCIES VARIABLES=Gender_num
  /ORDER=ANALYSIS.

FREQUENCIES VARIABLES=Education_num
  /ORDER=ANALYSIS.

FREQUENCIES VARIABLES=UnderstandingOfPowerGrid_num
  /ORDER=ANALYSIS.

FREQUENCIES VARIABLES=UnderstandingOfPowerGridSecurity_num
  /ORDER=ANALYSIS.

FREQUENCIES VARIABLES=time_for_completion
  /ORDER=ANALYSIS.

FREQUENCIES
    VARIABLES=time_for_completion
    /HIST=NORMAL .

FREQUENCIES VARIABLES=Age PostMinusPre
  /ORDER=ANALYSIS.


FREQUENCIES VARIABLES=time_for_completion PostMinusPre
  /ORDER=ANALYSIS.

FREQUENCIES
    VARIABLES=Gender
    /HIST=NORMAL .

FREQUENCIES VARIABLES=Age_num
  /ORDER=ANALYSIS.

FREQUENCIES VARIABLES=GroupTag
  /ORDER=ANALYSIS.



/* Particpants Education Level /*

GRAPH
  /BAR(SIMPLE)=COUNT BY Education_num

/* Particpants Gender /*

GRAPH
  /BAR(SIMPLE)=COUNT BY Gender_num.

/* Particpants Age /*

GRAPH
  /BAR(SIMPLE)=COUNT BY Age_num.


/* Particpants with understanding of Power Grid /*

GRAPH
  /BAR(SIMPLE)=COUNT BY UnderstandingOfPowerGrid_num.

/* Particpants with understanding of Power Grid Cybersecurity /*

GRAPH
  /BAR(SIMPLE)=COUNT BY UnderstandingOfPowerGridSecurity_num.


/* Particpants by Country /*

GRAPH
  /BAR(SIMPLE)=COUNT BY Country_Num.

/* Particpants by Gender and Education Stacked Graph /*

GRAPH
  /BAR(GROUPED)=COUNT BY Gender_num BY Education_num.

/* Particpants by Age and Education Stacked Graph /*

GRAPH
  /BAR(GROUPED)=COUNT BY Age_num BY Education_num.

/* Means Calcuation by Demographics */

MEANS TABLES=PostTrainingScore PreTrainingScore PostMinusPre BY Age_num
  /CELLS=MEAN COUNT STDDEV.

MEANS TABLES=PostTrainingScore PreTrainingScore PostMinusPre BY Country_num
  /CELLS=MEAN COUNT STDDEV.

MEANS TABLES=PostTrainingScore PreTrainingScore PostMinusPre BY Gender
  /CELLS=MEAN COUNT STDDEV.

MEANS TABLES=PostTrainingScore PreTrainingScore PostMinusPre BY Education_num
  /CELLS=MEAN COUNT STDDEV.

MEANS TABLES=PostTrainingScore PreTrainingScore PostMinusPre BY UnderstandingOfPowerGrid_num
  /CELLS=MEAN COUNT STDDEV.

MEANS TABLES=PostTrainingScore PreTrainingScore PostMinusPre BY  UnderstandingOfPowerGridSecurity_num
  /CELLS=MEAN COUNT STDDEV.

MEANS TABLES=PostTrainingScore PreTrainingScore PostMinusPre BY time_for_completion
  /CELLS=MEAN COUNT STDDEV.

/*Low Pretraining Better Improvement 
    


/*Time for Completion Histogram

FREQUENCIES
    VARIABLES=time_for_completion
    /HIST=NORMAL .


* Create a Graph  for "PostMinusPre" by GroupTag.


EXAMINE VARIABLES=PostMinusPre BY GroupTag_num
  /PLOT=BOXPLOT
  /STATISTICS=NONE
  /NOTOTAL
  /ID=GroupTag.


/* Paired T-test for null hyphothesis  /*
    

EXAMINE VARIABLES=PostMinusPre
  /PLOT BOXPLOT NPPLOT
  /COMPARE GROUPS
  /STATISTICS DESCRIPTIVES
  /CINTERVAL 95
  /MISSING LISTWISE
  /NOTOTAL.

T-TEST PAIRS=PostTrainingScore WITH PreTrainingScore (PAIRED)
  /ES DISPLAY(TRUE) STANDARDIZER(SD)
  /CRITERIA=CI(.9500)
  /MISSING=ANALYSIS.

/* Linear Correlation Test Time and Score Hypothesis - challenge due to nature of Typeform and onlie testtakers  /*
    

/* Low PreTraining Score  leads to higher overall score 
    
/* Step 1: Compute a new grouping variable based on Pre-Training Scores */
COMPUTE Group = (PreTrainingScore >= 40).
VARIABLE LABELS Group 'Group based on Pre-Training Scores (0 = < 40, 1 = >= 40)'.
VALUE LABELS Group 0 'Below 40' 1 '40 and above'.
EXECUTE.

/* Step 2: Perform Independent Samples t-Test to compare Score Differences between groups */
T-TEST GROUPS=Group(0 1)
  /VARIABLES=PostMinusPre
  /CRITERIA=CI(.95).


/* Particpants Performance between SG and IN - Independent Sample T-Test /*
  
T-TEST GROUPS=Country_num(1 2)
  /MISSING=ANALYSIS
  /VARIABLES=PostMinusPre
  /ES DISPLAY(TRUE)
  /CRITERIA=CI(.95).

/*An independent samples t-test was conducted to see if subjects from both India and Singapore performed well with no significant difference and both groups positively benefitted from the intervention.
/* Per the statistics below, the effect of training was more visible on Singapore participants and had less impact on India’s participant./*


/* Independent samples T-test by Gender, Score and TimeTaken
    
T-TEST GROUPS=Gender_num(1 2)
  /MISSING=ANALYSIS
  /VARIABLES= time_for_completion PostTrainingScore
  /ES DISPLAY(TRUE)
  /CRITERIA=CI(.95).

/*Inference:
/*Female participants spent more time to finish the survey,

/* Education vs Time Spent ( for non-linear ) : Scatter Plot 

GRAPH
  /SCATTERPLOT(BIVAR)=time_for_completion WITH Education_num
  /MISSING=LISTWISE.

/*Mean: Age-group and Score

MEANS TABLES=PostMinusPre BY Age_num
  /CELLS=MEAN COUNT STDDEV.

/* Inference:
/*Participants in the age group of 35-50 years had better scores after the training as compared to other participant age-groups

MEANS TABLES=PostMinusPre BY Gender_num
  /CELLS=MEAN COUNT STDDEV.

  /* the people with no prior understading of power grid  had better score as  compared to the participants who were aware of it. 
   
MEANS TABLES=PostMinusPre BY UnderstandingOfPowerGrid_num BY GroupTag
  /CELLS=MEAN COUNT STDDEV.

  /* the people with no prior understading of power grid security  had better score as  compared to the participants who were aware of it. 
   
MEANS TABLES=PostMinusPre BY UnderstandingOfPowerGridSecurity_num BY GroupTag
  /CELLS=MEAN COUNT STDDEV.


MEANS TABLES=PostMinusPre BY GroupTag
  /CELLS=MEAN COUNT STDDEV.


* Display the average "time_for_completion" by each tag.
MEANS TABLES=time_for_completion BY GroupTag
  /CELLS MEAN COUNT STDDEV.


* Display the average "PostMinusPre" by each tag.
MEANS TABLES=PostMinusPre BY GroupTag
  /CELLS MEAN COUNT STDDEV.


* Create a histogram for "time_for_completion" by tags.
GRAPH
  /BAR(SIMPLE)=COUNT BY time_for_completion BY GroupTag.
  /TITLE='Graph of Time for Completion by Tags'.


* Create a histogram for "PostMinusPre" by tags.

GRAPH
  /BAR(SIMPLE)=COUNT BY PostMinusPre BY GroupTag.
  /TITLE='Graph of PostMinusPre Tags'.


FREQUENCIES
    VARIABLES=time_for_completion BY GroupTag.
    /HIST=NORMAL .

/* Individual Gender T Test to calculate effect size 

T-TEST GROUPS=Gender_num(1 2)
  /MISSING=ANALYSIS
  /VARIABLES=PostTrainingScore PreTrainingScore
  /ES DISPLAY(TRUE)
  /CRITERIA=CI(.95).


/* Effect size on Countries 

T-TEST GROUPS=Country_num(1 2)
  /MISSING=ANALYSIS
  /VARIABLES=Post_Training Pre_Training
  /ES DISPLAY(TRUE)
  /CRITERIA=CI(.95).


/*Digital Divide Study 

MEANS TABLES=PostMinusPre BY Age_num
  /CELLS=MEAN COUNT STDDEV.

MEANS TABLES=Post_Training Pre_Training BY Age_num
  /CELLS=MEAN COUNT STDDEV.



/* Extra  Work for Future Research /* 

DATASET ACTIVATE DataSet1.
FREQUENCIES VARIABLES=Country_num
  /ORDER=ANALYSIS.

FREQUENCIES VARIABLES=Gender_num
  /ORDER=ANALYSIS.

FREQUENCIES VARIABLES=Education_num
  /ORDER=ANALYSIS.

FREQUENCIES VARIABLES=time_for_completion
  /ORDER=ANALYSIS.

FREQUENCIES
    VARIABLES=time_for_completion
    /HIST=NORMAL .

FREQUENCIES
    VARIABLES=time_for_completion
    /HIST=NORMAL .


FREQUENCIES VARIABLES=Age PostMinusPre
  /ORDER=ANALYSIS.


FREQUENCIES VARIABLES=time_for_completion PostMinusPre
  /ORDER=ANALYSIS.

/* Correlation: Education and TimeSpent
  
CORRELATIONS
  /VARIABLES=Education_num time_for_completion
  /PRINT=TWOTAIL NOSIG FULL
  /MISSING=PAIRWISE.

/*I observed strong correlation between Education and Time taken on the survey. The post grads and grads spent more time on survey.

/* Crosstab representing test scores of subjects by age-group - DIGITAL DIVIDE 

CROSSTABS
  /TABLES=Age BY PostMinusPre
  /FORMAT=AVALUE TABLES
  /CELLS=COUNT
  /COUNT ROUND CELL.

/*Inference:
/*18-25 Years , 66.67% of the total participants shows positive outcome to the training 
/*25-35 Years , 48.84% of the participants shows positive outcome to the training 
/*35-50 Years , 61.7 % of the participants shows positive outcome to the training
/*50 Years and above , 66.67 % of the participants shows positive outcome to the training 

/*Crosstab  scores
    
CROSSTABS
  /TABLES=UnderstandingOfPowerGridSecurity_num BY PostMinusPre
  /FORMAT=AVALUE TABLES
  /CELLS=COUNT
  /COUNT ROUND CELL.

