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
