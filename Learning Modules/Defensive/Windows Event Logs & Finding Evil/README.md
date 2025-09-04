# Windows Event Logs & Finding Evil
Brief notes on the HackTheBox Academy module, Windows Event Logs & Finding Evil, under the SOC Analyst learning path.

## Windows Event Logging Basics
The logs are categorized into different event logs, such as "Application", "System", "Security", and others, to organize events based on their source or purpose.

Event logs can be accessed using the Event Viewer application or programmatically using APIs such as the Windows Event Log API.

Accessing the Windows Event Viewer as an administrative user allows us to explore the various logs available.

The default Windows event logs consist of Application, Security, Setup, System, and Forwarded Events. The "Forwarded Events" section is unique, showcasing event log data forwarded from other machines. This central logging feature proves valuable for system administrators who desire a consolidated view.

### The Anatomy of an Event Log
When examining Application logs, we encounter two distinct levels of events: information and error.

Information events provide general usage details about the application, such as its start or stop events. Conversely, error events highlight specific errors and often offer detailed insights into the encountered issues.

Each entry in the Windows Event Log is an "Event" and contains the following primary components:

- Log Name: The name of the event log (e.g., Application, System, Security, etc.).
- Source: The software that logged the event.
- Event ID: A unique identifier for the event.
- Task Category: This often contains a value or name that can help us understand the purpose or use of the event.
- Level: The severity of the event (Information, Warning, Error, Critical, and Verbose).
- Keywords: Keywords are flags that allow us to categorize events in ways beyond the other classification options. These are generally broad categories, such as "Audit Success" or "Audit Failure" in the Security log.
- User: The user account that was logged on when the event occurred.
- OpCode: This field can identify the specific operation that the event reports.
- Logged: The date and time when the event was logged.
- Computer: The name of the computer where the event occurred.
- XML Data: All the above information is also included in an XML format along with additional event data.

The Keywords field is particularly useful when filtering event logs for specific types of events. It can significantly enhance search queries by allowing us to specify events of interest.

### Leveraging Custom XML Queries
To streamline analysis, we can create custom XML queries to identify related events using the "Logon ID" as a starting point. By navigating to "Filter Current Log" -> "XML" -> "Edit Query Manually," we gain access to a custom XML query language that enables more granular log searches.
