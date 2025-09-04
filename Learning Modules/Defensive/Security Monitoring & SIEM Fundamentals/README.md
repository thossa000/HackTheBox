# Security Monitoring & SIEM Fundamentals
Brief notes written to review the material in the HackTheBox Academy module, Security Monitoring & SIEM Fundamentals.

### What Is SIEM?
Security Information and Event Management (SIEM) facilitate real-time evaluations of alerts related to security, which are produced by network hardware and applications.

The first-generation SIM technology was developed upon conventional log collection management systems, allowing for extended storage, examination, and reporting of log data while incorporating logs with threat intelligence. Conversely, the second-generation SEM technology tackled security events by delivering consolidation, correlation, and notification of events from a range of security apparatuses, such as antivirus software, firewalls, Intrusion Detection Systems (IDS), in addition to events disclosed directly by authentication, SNMP traps, servers, and databases.

In the years that followed, vendors amalgamated the capabilities of SIM and SEM to devise the SIEM.

The capacity to accurately pinpoint high-risk events is what distinguishes SIEM from other network monitoring and detection tools, such as Intrusion Prevention Systems (IPS) or Intrusion Detection Systems (IDS). SIEM does not supplant the logging capabilities of these devices; rather, it operates in conjunction with them by processing and amalgamating their log data to recognize events that could potentially lead to system exploitation. By integrating data from numerous sources, SIEM solutions deliver a holistic strategy for threat detection and management.

### Data Flows Within A SIEM

1. SIEM solutions ingest logs from various data sources. Each SIEM tool possesses unique capabilities for collecting logs from different sources. This process is known as data ingestion or data collection.

2. The gathered data is processed and normalized to be understood by the SIEM correlation engine. The raw data must be written or read in a format that can be comprehended by the SIEM and converted into a common format from various types of datasets. This process is called data normalization and data aggregation.

3. Finally, the most crucial part of SIEM, where SOC teams utilize the normalized data collected by the SIEM to create various detection rules, dashboards, visualizations, alerts, and incidents. This enables the SOC team to identify potential security risks and respond swiftly to security incidents.

Numerous regulated organizations, such as those in Banking, Finance, Insurance, and Healthcare, are mandated to have a managed SIEM either on-premise or in the cloud. SIEM systems offer evidence that systems are being monitored and logged, reviewed, and adhere to log retention policies, fulfilling compliance standards like ISO and HIPAA.

# Introduction To The Elastic Stack
The Elastic stack, created by Elastic, is an open-source collection of mainly three applications (Elasticsearch, Logstash, and Kibana) that work in harmony to offer users comprehensive search and visualization capabilities for real-time analysis and exploration of log file sources.

The high-level architecture of the Elastic stack can be enhanced in resource-intensive environments with the addition of Kafka, RabbitMQ, and Redis for buffering and resiliency, and nginx for security.

<img width="1094" height="539" alt="image" src="https://github.com/user-attachments/assets/9e0f5330-d432-4a69-b2ec-b2577d885e63" />

Elasticsearch is a distributed and JSON-based search engine, designed with RESTful APIs. As the core component of the Elastic stack, it handles indexing, storing, and querying.

Logstash is responsible for collecting, transforming, and transporting log file records. Logstash operates in three main areas:

1. Process input: Logstash ingests log file records from remote locations, converting them into a format that machines can understand. It can receive records through different input methods, such as reading from a flat file, a TCP socket, or directly from syslog messages. After processing the input, Logstash proceeds to the next function.
2. Transform and enrich log records: Logstash offers numerous ways to modify a log record's format and even content. Specifically, filter plugins can perform intermediary processing on an event, often based on a predefined condition. Once a log record is transformed, Logstash processes it further.
3. Send log records to Elasticsearch: Logstash utilizes output plugins to transmit log records to Elasticsearch.

Kibana serves as the visualization tool for Elasticsearch documents. Users can view the data stored in Elasticsearch and execute queries through Kibana. 

Note: Beats is an additional component of the Elastic stack. These lightweight, single-purpose data shippers are designed to be installed on remote machines to forward logs and metrics to either Logstash or Elasticsearch directly.

### KQL
Kibana Query Language (KQL) is a powerful and user-friendly query language designed specifically for searching and analyzing data in Kibana. It simplifies the process of extracting insights from your indexed Elasticsearch data, offering a more intuitive approach than Elasticsearch's Query DSL.

Basic Structure: KQL queries are composed of field:value pairs, with the field representing the data's attribute and the value representing the data you're searching for. For example:
```
event.code:4625
# This Windows event code is associated with failed login attempts in a Windows operating system.
```

Free Text Search: KQL supports free text search, allowing you to search for a specific term across multiple fields without specifying a field name. For instance:
```
"svc-sql1"
```

Logical Operators: KQL supports logical operators AND, OR, and NOT for constructing more complex queries. Parentheses can be used to group expressions and control the order of evaluation. For example:
```
event.code:4625 AND winlog.event_data.SubStatus:0xC0000072
# In Windows, the SubStatus value indicates the reason for a login failure. A SubStatus value of 0xC0000072 indicates that the account is currently disabled.
```

Comparison Operators: KQL supports various comparison operators such as :, :>, :>=, :<, :<=, and :!. These operators enable you to define precise conditions for matching field values. For instance:
```
event.code:4625 AND winlog.event_data.SubStatus:0xC0000072 AND @timestamp >= "2023-03-03T00:00:00.000Z" AND @timestamp <= "2023-03-06T23:59:59.999Z"
# identify failed login attempts against disabled accounts that took place between March 3rd 2023 and March 6th 2023
```

Wildcards and Regular Expressions: KQL supports wildcards and regular expressions to search for patterns in field values. For example:
```
event.code:4625 AND user.name: admin*
```

### How To Identify The Available Data
Using the Discover feature, we can explore and sift through the available data, as well as gain insights into the architecture of the available fields, before we start constructing KQL queries.

- By using a search engine for the Windows event logs that are associated with failed login attempts, we will come across resources such as https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4625
- Using KQL's free text search we can search for "4625". In the returned records we notice event.code:4625, winlog.event_id:4625, and @timestamp
- event.code is related to the Elastic Common Schema (ECS)
- winlog.event_id is related to Winlogbeat
- If the organization we work for is using the Elastic stack across all offices and security departments, it is preferred that we use the ECS fields in our queries for reasons that we will cover at the end of this section.
- @timestamp typically contains the time extracted from the original event and it is different from event.created

### The Elastic Common Schema (ECS)

Elastic Common Schema (ECS) is a shared and extensible vocabulary for events and logs across the Elastic Stack, which ensures consistent field formats across different data sources. When it comes to Kibana Query Language (KQL) searches within the Elastic Stack, using ECS fields presents several advantages:

- Unified Data View: ECS enforces a structured and consistent approach to data, allowing for unified views across multiple data sources. For instance, data originating from Windows logs, network traffic, endpoint events, or cloud-based data sources can all be searched and correlated using the same field names.

- Improved Search Efficiency: By standardizing the field names across different data types, ECS simplifies the process of writing queries in KQL. This means that analysts can efficiently construct queries without needing to remember specific field names for each data source.

- Enhanced Correlation: ECS allows for easier correlation of events across different sources, which is pivotal in cybersecurity investigations. For example, you can correlate an IP address involved in a security incident with network traffic logs, firewall logs, and endpoint data to gain a more comprehensive understanding of the incident.

- Better Visualizations: Consistent field naming conventions improve the efficacy of visualizations in Kibana. As all data sources adhere to the same schema, creating dashboards and visualizations becomes easier and more intuitive. This can help in spotting trends, identifying anomalies, and visualizing security incidents.

- Interoperability with Elastic Solutions: Using ECS fields ensures full compatibility with advanced Elastic Stack features and solutions, such as Elastic Security, Elastic Observability, and Elastic Machine Learning. This allows for advanced threat hunting, anomaly detection, and performance monitoring.

- Future-proofing: As ECS is the foundational schema across the Elastic Stack, adopting ECS ensures future compatibility with enhancements and new features that are introduced into the Elastic ecosystem.


## MITRE ATT&CK
The MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) framework serves as an extensive, regularly updated resource outlining the tactics, techniques, and procedures (TTPs) employed by cyber threat actors. This structured methodology assists cybersecurity experts in comprehending, identifying, and reacting to threats more proactively and knowledgeably.

The ATT&CK framework comprises matrices tailored to various computing contexts, such as enterprise, mobile, or cloud systems. Each matrix links the tactics (the goals attackers aim to achieve) and techniques (the methods used to accomplish their objectives) to distinct TTPs. This linkage allows security teams to methodically examine and predict attacker activities.

The MITRE ATT&CK framework not only serves as a comprehensive resource for understanding adversarial tactics, techniques, and procedures (TTPs), but it also plays a crucial role in several aspects of Security Operations:

- Detection and Response: The framework supports SOCs in devising detection and response plans based on recognized attacker TTPs, empowering security teams to pinpoint potential dangers and develop proactive countermeasures.

- Security Evaluation and Gap Analysis: Organizations can leverage the ATT&CK framework to identify the strengths and weaknesses of their security posture, subsequently prioritizing security control investments to effectively defend against relevant threats.

- SOC Maturity Assessment: The ATT&CK framework enables organizations to assess their Security Operations Center (SOC) maturity by measuring their ability to detect, respond to, and mitigate various TTPs. This assessment assists in identifying areas for improvement and prioritizing resources to strengthen the overall security posture.

- Threat Intelligence: The framework offers a unified language and format to describe adversarial actions, enabling organizations to bolster their threat intelligence and improve collaboration among internal teams or with external stakeholders.

- Cyber Threat Intelligence Enrichment: Leveraging the ATT&CK framework can help organizations enrich their cyber threat intelligence by providing context on attacker TTPs, as well as insights into potential targets and indicators of compromise (IOCs). This enrichment allows for more informed decision-making and effective threat mitigation strategies.

Behavioral Analytics Development: By mapping the TTPs outlined in the ATT&CK framework to specific user and system behaviors, organizations can develop behavioral analytics models to identify anomalous activities indicative of potential threats. This approach enhances detection capabilities and helps security teams proactively mitigate risks.

Red Teaming and Penetration Testing: The ATT&CK framework presents a systematic way to replicate genuine attacker techniques during red teaming exercises and penetration tests, ultimately assessing an organization's defensive capabilities.

Training and Education: The comprehensive and well-organized nature of the ATT&CK framework makes it an exceptional resource for training and educating security professionals on the latest adversarial tactics and methods.

## SIEM Use Case Development
Utilizing SIEM use cases is a fundamental aspect of crafting a robust cybersecurity strategy, as they enable the effective identification and detection of potential security incidents.

The following critical stages must be considered when developing any use cases:

1. Requirements: Comprehend the purpose or necessity of the use case, pinpointing the specific scenario for which an alert or notification is needed. Requirements can be proposed by customers, analysts, or employees. For instance, the goal might be to design a detection use case for a brute force attack that triggers an alert after 10 consecutive login failures within 4 minutes.

2. Data Points: Identify all data points within the network where a user account can be used to log in. Gather information about the data sources that generate logs for unauthorized access attempts or login failures. For example, data might come from Windows machines, Linux machines, endpoints, servers, or applications. Ensure logs capture essential details like user, timestamp, source, destination, etc.

3. Log Validation: Verify and validate the logs, ensuring they contain all crucial information such as user, timestamp, source, destination, machine name, and application name. Confirm all logs are received during various user authentication events for critical data points, including local, web-based, application, VPN, and OWA (Outlook) authentication.

4. Design and Implementation: After identifying and verifying all logs with different data points and sources, begin designing the use case by defining the conditions under which an alert should be triggered. Consider three primary parameters: Condition, Aggregation, and Priority. For example, in a brute force attack use case, create an alert for 10 login failures in 4 minutes while considering aggregation to avoid false positives and setting alert priority based on the targeted user's privileges.

5. Documentation: Standard Operating Procedures (SOP) detail the standard processes analysts must follow when working on alerts. This includes conditions, aggregations, priorities, and information about other teams to which analysts need to report activities. The SOP also contains the escalation matrix.

6. Onboarding: Start with the development stage before moving the alert directly into the production environment. Identify and address any gaps to reduce false positives, then proceed to production.

Periodic Update/Fine-tuning: Obtain regular feedback from analysts and maintain up-to-date correlation rules by whitelisting. Continually refine and optimize the use case to ensure its effectiveness and accuracy.

### How To Build SIEM Use Cases
- Comprehend your needs, risks, and establish alerts for monitoring all necessary systems accordingly.
- Determine the priority and impact, then map the alert to the kill chain or MITRE framework.
- Establish the Time to Detection (TTD) and Time to Response (TTR) for the alert to assess the SIEM's effectiveness and analysts' performance.
- Create a Standard Operating Procedure (SOP) for managing alerts.
- Outline the process for refining alerts based on SIEM monitoring.
- Develop an Incident Response Plan (IRP) to address true positive incidents.
- Set Service Level Agreements (SLAs) and Operational Level Agreements (OLAs) between teams for handling alerts and following the IRP.
- Implement and maintain an audit process for managing alerts and incident reporting by analysts.
- Create documentation to review the logging status of machines or systems, the basis for creating alerts, and their triggering frequency.
- Establish a knowledge base document for essential information and updates to case management tools.

## The Triaging Process
Alert triaging, performed by a Security Operations Center (SOC) analyst, is the process of evaluating and prioritizing security alerts generated by various monitoring and detection systems to determine their level of threat and potential impact on an organization's systems and data. It involves systematically reviewing and categorizing alerts to effectively allocate resources and respond to security incidents.

Escalation is an important aspect of alert triaging in a SOC environment. The escalation process typically involves notifying supervisors, incident response teams, or designated individuals within the organization who have the authority to make decisions and coordinate the response effort. Escalation ensures that critical alerts receive prompt attention and facilitates effective coordination among different stakeholders, enabling a timely and efficient response to potential security incidents. It helps to leverage the expertise and decision-making capabilities of individuals who are responsible for managing and mitigating higher-level threats or incidents within the organization.

### What Is The Ideal Triaging Process?

1. Initial Alert Review:
- Thoroughly review the initial alert, including metadata, timestamp, source IP, destination IP, affected systems, and triggering rule/signature.
- Analyze associated logs (network traffic, system, application) to understand the alert's context.

2. Alert Classification:
- Classify the alert based on severity, impact, and urgency using the organization's predefined classification system.

3. Alert Correlation:
- Cross-reference the alert with related alerts, events, or incidents to identify patterns, similarities, or potential indicators of compromise (IOCs).
- Query the SIEM or log management system to gather relevant log data.
- Leverage threat intelligence feeds to check for known attack patterns or malware signatures.

4. Enrichment of Alert Data:
- Collect network packet captures, memory dumps, or file samples associated with the alert.
- Utilize external threat intelligence sources, open-source tools, or sandboxes to analyze suspicious files, URLs, or IP addresses.
- Conduct reconnaissance of affected systems for anomalies (network connections, processes, file modifications).

5. Risk Assessment:
- Consider the value of affected systems, sensitivity of data, compliance requirements, and regulatory implications.
- Determine likelihood of a successful attack or potential lateral movement.

6. Contextual Analysis:
- The analyst considers the context surrounding the alert, including the affected assets, their criticality, and the sensitivity of the data they handle.
- They evaluate the security controls in place, such as firewalls, intrusion detection/prevention systems, and endpoint protection solutions, to determine if the alert indicates a potential control failure or evasion technique.
- The analyst assesses the relevant compliance requirements, industry regulations, and contractual obligations to understand the implications of the alert on the organization's legal and regulatory compliance posture.

7. Incident Response Planning:
- Document alert details, affected systems, observed behaviors, potential IOCs, and enrichment data.
- Assign incident response team members with defined roles and responsibilities.
- Coordinate with other teams (network operations, system administrators, vendors) as necessary.

8. Consultation with IT Operations:
- Assess the need for additional context or missing information by consulting with IT operations or relevant departments.
- Engage in discussions or meetings to gather insights on the affected systems, recent changes, or ongoing maintenance activities.
- Collaborate to understand any known issues, misconfigurations, or network changes that could potentially generate false-positive alerts.
- Gain a holistic understanding of the environment and any non-malicious activities that might have triggered the alert.
- Document the insights and information obtained during the consultation.

9. Response Execution:
- Based on the alert review, risk assessment, and consultation, determine the appropriate response actions.
- If the additional context resolves the alert or identifies it as a non-malicious event, take necessary actions without escalation.
- If the alert still indicates potential security concerns or requires further investigation, proceed with the incident response actions.

10. Escalation:
- Assess the alert against escalation triggers, considering potential consequences if not escalated.
- Triggers may include compromise of critical systems/assets, ongoing attacks, unfamiliar/sophisticated techniques, widespread impact, or insider threats.
- Follow internal escalation process, notifying higher-level teams/management responsible for incident response.
- Provide comprehensive alert summary, severity, potential impact, enrichment data, and risk assessment.
- Document all communication related to escalation.
- In some cases, escalate to external entities (law enforcement, incident response providers, CERTs) based on legal/regulatory requirements.

11. Continuous Monitoring:
- Maintain open communication with escalated teams, providing updates on developments, findings, or changes in severity/impact.
- Collaborate closely with escalated teams for a coordinated response.

12. De-escalation:
- Evaluate the need for de-escalation as the incident response progresses and the situation is under control.
- De-escalate when the risk is mitigated, incident is contained, and further escalation is unnecessary.
- Notify relevant parties, providing a summary of actions taken, outcomes, and lessons learned.

Regularly review and update the process, aligning it with organizational policies, procedures, and guidelines. Adapt the process to address emerging threats.
