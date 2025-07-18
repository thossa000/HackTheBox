# Introduction to Web Applications
Brief notes written to review the material in the HackTheBox module, Introduction to Web Applications.

Web applications are interactive applications that run on web browsers. Web applications usually adopt a client-server architecture to run and handle interactions. They typically have front end components (i.e., the website interface, or "what the user sees") that run on the client-side (browser) and other back end components (web application source code) that run on the server-side (back end server/databases). Some examples of typical web applications include online email services like Gmail, online retailers like Amazon, and online word processors like Google Docs.

### Web Applications vs. Websites
In the past, we interacted with websites that are static and cannot be changed in real-time. This means that traditional websites were statically created to represent specific information, and this information would not change with our interaction. To change the website's content, the corresponding page has to be edited by the developers manually. These types of static pages do not contain functions and, therefore, do not produce real-time changes. That type of website is also known as Web 1.0. On the other hand, most websites run web applications, or Web 2.0 presenting dynamic content based on user interaction. Another significant difference is that web applications are fully functional and can perform various functionalities for the end-user, while web sites lack this type of functionality. Other key differences between traditional websites and web applications include:

- Being modular
- Running on any display size
- Running on any platform without being optimized

### Web Applications vs. Native Operating System Applications
Unlike native operating system (native OS) applications, web applications are platform-independent and can run in a browser on any operating system. These web applications do not have to be installed on a user's system because these web applications and their functionality are executed remotely on the remote server and hence do not consume any space on the end user's hard drive. Another advantage of web applications over native OS applications is version unity. All users accessing a web application use the same version and the same web application, which can be continuously updated and modified without pushing updates to each user.

On the other hand, native OS applications have certain advantages over web applications, mainly their operation speed and the ability to utilize native operating system libraries and local hardware. As native applications are built to utilize native OS libraries, they are much faster to load and interact with.

### Web Application Distribution
- WordPress (Open Source)
- OpenCart (Open Source)
- Joomla (Open Source)
- Wix (Closed Source)
- Shopify (Closed Source)
- DotNetNuke (Closed Source)

### Attacking Web Apps

|Flaw|	Real-world Scenario|
|:-:|:-:|
|SQL injection|	Obtaining Active Directory usernames and performing a password spraying attack against a VPN or email portal.
|File Inclusion|	Reading source code to find a hidden page or directory which exposes additional functionality that can be used to gain remote code execution.
|Unrestricted File Upload|	A web application that allows a user to upload a profile picture that allows any file type to be uploaded (not just images). This can be leveraged to gain full control of the web application server by uploading malicious code.
|Insecure Direct Object Referencing (IDOR)|	When combined with a flaw such as broken access control, this can often be used to access another user's files or functionality. An example would be editing your user profile browsing to a page such as /user/701/edit-profile. If we can change the 701 to 702, we may edit another user's profile!
|Broken Access Control|	Another example is an application that allows a user to register a new account. If the account registration functionality is designed poorly, a user may perform privilege escalation when registering. Consider the POST request when registering a new user, which submits the data username=bjones&password=Welcome1&email=bjones@inlanefreight.local&roleid=3. What if we can manipulate the roleid parameter and change it to 0 or 1. We have seen real-world applications where this was the case, and it was possible to quickly register an admin user and access many unintended features of the web application.

# Web Application Layout
Web application layouts consist of many different layers that can be summarized with the following three main categories:

|Category|	Description|
|:-:|:-:|
|Web Application Infrastructure|	Describes the structure of required components, such as the database, needed for the web application to function as intended. Since the web application can be set up to run on a separate server, it is essential to know which database server it needs to access.
|Web Application Components|	The components that make up a web application represent all the components that the web application interacts with. These are divided into the following three areas: UI/UX, Client, and Server components.
|Web Application Architecture|	Architecture comprises all the relationships between the various web application components.

## Web Application Infrastructure
Web applications can use many different infrastructure setups. These are also called models. The most common ones can be grouped into the following four types:

- Client-Server
- One Server
- Many Servers - One Database
- Many Servers - Many Databases

### Client Server
A server hosts the web application in a client-server model and distributes it to any clients trying to access it. In this model, web applications have two types of components, those in the front end, which are usually interpreted and executed on the client-side (browser), and components in the back end, usually compiled, interpreted, and executed by the hosting server. Once the user clicks on a button or requests a specific function, the browser sends an HTTP web request to the server, which interprets this request and performs the necessary task(s) to complete the request (i.e., logging the user in, adding an item to the shopping cart, browsing to another page, etc.). Once the server has the required data, it sends the result back to the client's browser, displaying the result in a human-readable way.

### One Server
The entire web application or even several web applications and their components, including the database, are hosted on a single server. Though this design is straightforward and easy to implement, it is also the riskiest design. Furthermore, if the webserver goes down for any reason, all hosted web applications become entirely inaccessible until the issue is resolved.

### Many Servers - One Database
This model separates the database onto its own database server and allows the web applications' hosting server to access the database server to store and retrieve data. It can be seen as many-servers to one-database and one-server to one-database, as long as the database is separated on its own database server. The web applications can be replications of one main application (i.e., primary/backup), or they can be separate web applications that share common data. This model's main advantage (from a security point of view) is segmentation.

### Many Servers - Many Databases
This model builds upon the Many Servers, One Database model. However, within the database server, each web application's data is hosted in a separate database. The web application can only access private data and only common data that is shared across web applications. This design is also widely used for redundancy purposes, so if any web server or database goes offline, a backup will run in its place to reduce downtime as much as possible. Although this may be more difficult to implement and may require tools like load balancers to function appropriately, this architecture is one of the best choices in terms of security due to its proper access control measures and proper asset segmentation.

Aside from these models, there are other web application models available such as serverless web applications or web applications that utilize microservices.

## Web Application Components
1. Client
2. Server
- Webserver
- Web Application Logic
- Database
3. Services (Microservices)
- 3rd Party Integrations
- Web Application Integrations
5. Functions (Serverless)

## Web Application Architecture
Three Tier Architecture:

|Layer	|Description|
|:-:|:-:|
|Presentation Layer|	Consists of UI process components that enable communication with the application and the system. These can be accessed by the client via the web browser and are returned in the form of HTML, JavaScript, and CSS.
|Application Layer|	This layer ensures that all client requests (web requests) are correctly processed. Various criteria are checked, such as authorization, privileges, and data passed on to the client.
|Data Layer|	The data layer works closely with the application layer to determine exactly where the required data is stored and can be accessed.

An example of a web application architecture could look something like this:
<img width="1378" height="749" alt="image" src="https://github.com/user-attachments/assets/2b1a57cb-16f5-4653-ba0b-4f3bd59f4703" />

### Microservices
We can think of microservices as independent components of the web application, which in most cases are programmed for one task only. For example, for an online store, we can decompose core tasks into the following components:

- Registration
- Search
- Payments
- Ratings
- Reviews

The communication between these microservices is stateless, which means that the request and response are independent. This is because the stored data is stored separately from the respective microservices. The use of microservices is considered service-oriented architecture (SOA), built as a collection of different automated functions focused on a single business goal.

### Serverless
Cloud providers such as AWS, GCP, Azure, among others, offer serverless architectures. These platforms provide application frameworks to build such web applications without having to worry about the servers themselves. These web applications then run in stateless computing containers (Docker, for example). This type of architecture gives a company the flexibility to build and deploy applications and services without having to manage infrastructure; all server management is done by the cloud provider.

# Front End vs. Back End
## Front End
The front end of a web application contains the user's components directly through their web browser (client-side). These components make up the source code of the web page we view when visiting a web application and usually include HTML, CSS, and JavaScript. In modern web applications, front end components should adapt to any screen size and work within any browser on any device. This contrasts with back end components, which are usually written for a specific platform or operating system. If the front end of a web application is not well optimized, it may make the entire web application slow and unresponsive.

Aside from frontend code development, the following are some of the other tasks related to front end web application development:

- Visual Concept Web Design
- User Interface (UI) design
- User Experience (UX) design

## Back End
The back end of a web application drives all of the core web application functionalities, all of which is executed at the back end server, which processes everything required for the web application to run correctly. It is the part we may never see or directly interact with.

There are four main back end components for web applications:
|Component	|Description|
|:-:|:-:|
|Back end Servers|	The hardware and operating system that hosts all other components and are usually run on operating systems like Linux, Windows, or using Containers.
|Web Servers|	Web servers handle HTTP requests and connections. Some examples are Apache, NGINX, and IIS.
|Databases|	Databases (DBs) store and retrieve the web application data. Some examples of relational databases are MySQL, MSSQL, Oracle, PostgreSQL, while examples of non-relational databases include NoSQL and MongoDB.
|Development Frameworks|	Development Frameworks are used to develop the core Web Application. Some well-known frameworks include Laravel (PHP), ASP.NET (C#), Spring (Java), Django (Python), and Express (NodeJS JavaScript).

It is also possible to host each component of the back end on its own isolated server, or in isolated containers, by utilizing services such as Docker. To maintain logical separation and mitigate the impact of vulnerabilities, different components of the web application, such as the database, can be installed in one Docker container, while the main web application is installed in another, thereby isolating each part from potential vulnerabilities that may affect the other container(s).

Some of the main jobs performed by back end components include:

- Develop the main logic and services of the back end of the web application
- Develop the main code and functionalities of the web application
- Develop and maintain the back end database
- Develop and implement libraries to be used by the web application
- Implement technical/business needs for the web application
- Implement the main APIs for front end component communications
- Integrate remote servers and cloud services into the web application

# Front-End Components
# HTML
