# Web Requests
Brief notes written to review the material in the HackTheBox Academy module, Web Requests.

## HyperText Transfer Protocol (HTTP)
HTTP is an application-level protocol used to access the World Wide Web resources. The term hypertext stands for text containing links to other resources and text that the readers can easily interpret. HTTP communication consists of a client and a server, where the client requests the server for a resource. The server processes the requests and returns the requested resource.

Default Port: 80 (can be changed to a custom port through configuration files/settings)

Resources over HTTP are accessed via a URL, which offers many more specifications than simply specifying a website we want to visit. Let's look at the structure of a URL:
![image](https://github.com/user-attachments/assets/dc3d326d-4406-47bd-b188-e88b4c274ac0)

Once your browser gets the IP address linked to the requested domain, it sends a GET request to the default HTTP port asking for the root path.  By default, servers are configured to return an index file when a request for root path (/) is received. Your host then reads the index file responds with the status code (e.g. 200 OK), indicating a successful request. The web browser then renders the index.html contents and presents it to the you.

HTTP has a severe vulnerability of transferring all data in clear-text format, to solve this, the HTTPS (HTTP Secure) protocol was created which transfers all data in an encrypted format. For this reason, HTTPS has become the mainstream scheme for websites on the internet, and HTTP is being phased out. Websites that enforce HTTPS can be identified through https:// in their URL and display a lock icon in the browser:
![image](https://github.com/user-attachments/assets/417dafe6-4308-4203-a046-943f20135ca6)

If we type http:// instead of https:// to visit a website that enforces HTTPS, the browser resolves the domain and redirects the user to the webserver hosting the target website. A request is sent to port 80 first, the server detects this and redirects the client to secure HTTPS port 443 instead. This is done via the 301 Moved Permanently response code.

## HTTP Requests, Responses, and Headers

An HTTP request is made by the client and is processed by the server. The requests contain all of the details we require from the server, including the resource, any request data, headers or options we specify, and many other options.

Once the server receives the HTTP request, it processes it and responds by sending the HTTP response. An HTTP response contains two fields separated by spaces. The first being the HTTP version (e.g. HTTP/1.1), and the second denotes the HTTP response code (e.g. 200 OK).

Most modern web browsers come with built-in developer tools (DevTools), which are mainly intended for developers to test their web applications. However, as web penetration testers, these tools can be a vital asset in any web assessment we perform. To open the browser devtools in either Chrome or Firefox, we can click [CTRL+SHIFT+I] or simply click [F12].

HTTP headers pass information between the client and the server. Some headers are only used with either requests or responses, while some other general headers are common to both. Headers can be divided into the following categories:

- General Headers - used in both HTTP requests and responses. They are contextual and are used to describe the message rather than its contents.
- Entity Headers - common to both the request and response. These headers are used to describe the content (entity) transferred by a message. They are usually found in responses and POST or PUT requests.
- Request Headers - used in an HTTP request and do not relate to the content of the message.
- Response Headers - used in an HTTP response and do not relate to the content. Certain response headers such as Age, Location, and Server are used to provide more context about the response. 
- Security Headers - a class of response headers used to specify certain rules and policies to be followed by the browser while accessing the website.

## HTTP Methods and Codes

Request Methods

|Method|	Description|
|:-:|:-:|
|GET|	Requests a specific resource. Additional data can be passed to the server via query strings in the URL (e.g. ?param=value).|
|POST|	Sends data to the server. It can handle multiple types of input, such as text, PDFs, and other forms of binary data. This data is appended in the request body present after the headers. The POST method is commonly used when sending information (e.g. forms/logins) or uploading data to a website, such as images or documents.|
|HEAD|	Requests the headers that would be returned if a GET request was made to the server. It doesn't return the request body and is usually made to check the response length before downloading resources.|
|PUT|	Creates new resources on the server. Allowing this method without proper controls can lead to uploading malicious resources.|
|DELETE|	Deletes an existing resource on the webserver. If not properly secured, can lead to Denial of Service (DoS) by deleting critical files on the web server.|
|OPTIONS|	Returns information about the server, such as the methods accepted by it.|
|PATCH|	Applies partial modifications to the resource at the specified location.|

Note: Most modern web applications mainly rely on the GET and POST methods. However, any web application that utilizes REST APIs also rely on PUT and DELETE, which are used to update and delete data on the API endpoint, respectively. 

Response Codes

|Type|	Description|
|:-:|:-:|
|1xx|	Provides information and does not affect the processing of the request.|
|2xx|	Returned when a request succeeds.|
|3xx|	Returned when the server redirects the client.|
|4xx|	Signifies improper requests from the client. For example, requesting a resource that doesn't exist or requesting a bad format.|
|5xx|	Returned when there is some problem with the HTTP server itself.|

The following are some of the commonly seen examples from each of the above HTTP method types:

|Code|	Description|
|:-:|:-:|
|200 OK|	Returned on a successful request, and the response body usually contains the requested resource.|
|302 Found|	Redirects the client to another URL. For example, redirecting the user to their dashboard after a successful login.|
|400 Bad Request|	Returned on encountering malformed requests such as requests with missing line terminators.|
|403 Forbidden|	Signifies that the client doesn't have appropriate access to the resource. It can also be returned when the server detects malicious input from the user.|
|404 Not Found|	Returned when the client requests a resource that doesn't exist on the server.|
|500 Internal Server Error|	Returned when the server cannot process the request.|

## CRUD
In general, APIs perform 4 main operations on the requested database entity:

|Operation|	HTTP Method|	Description|
|:-:|:-:|:-:|
|Create|	POST|	Adds the specified data to the database table.|
|Read|	GET|	Reads the specified entity from the database table.|
|Update|	PUT|	Updates the data of the specified database table.|
|Delete|	DELETE|	Removes the specified row from the database table.|

These four operations are mainly linked to the commonly known CRUD APIs, but the same principle is also used in REST APIs.

PUT example - thossa00@htb[/htb]$ curl -X PUT http://<SERVER_IP>:<PORT>/api.php/city/london -d '{"city_name":"New_HTB_City", "country_name":"HTB"}' -H 'Content-Type: application/json'

DELETE example - thossa00@htb[/htb]$ curl -X DELETE http://<SERVER_IP>:<PORT>/api.php/city/london

## cURL
cURL (client URL) is a command-line tool and library that primarily supports HTTP along with many other protocols. It is capable of sending various types of web requests from the command line, which makes it very useful in web penetration tests.

Basic cURL request:  #curl website.com

We may also use cURL to download a page or a file and output the content into a file using the -O flag. This will provide a status output but this can be silenced with the -s flag.

-I flag to send a HEAD request and only display the response headers. We can use the -i flag to display both the headers and the response body.
-v flag for verbose details. -X flag to set an HTTP method other than GET (ie. POST, PUT, DELETE). -b flag to set your own cookie. -H flag to set a header value. -d flag sends data in a POST request.

NOTE: The -h (help) flag or #man curl can be used to explore other cURL options.
