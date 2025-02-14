# Web Requests
Brief notes written to review the material in the HackTheBox Academy module, Web Requests.

## HyperText Transfer Protocol (HTTP)
HTTP is an application-level protocol used to access the World Wide Web resources. The term hypertext stands for text containing links to other resources and text that the readers can easily interpret. HTTP communication consists of a client and a server, where the client requests the server for a resource. The server processes the requests and returns the requested resource.

Default Port: 80 (can be changed to a custom port through configuration files/settings)

Resources over HTTP are accessed via a URL, which offers many more specifications than simply specifying a website we want to visit. Let's look at the structure of a URL:
![image](https://github.com/user-attachments/assets/dc3d326d-4406-47bd-b188-e88b4c274ac0)

Once your browser gets the IP address linked to the requested domain, it sends a GET request to the default HTTP port asking for the root path.  By default, servers are configured to return an index file when a request for root path (/) is received. Your host then reads the index file responds with the status code (e.g. 200 OK), indicating a successful request. The web browser then renders the index.html contents and presents it to the you.

## cURL
cURL (client URL) is a command-line tool and library that primarily supports HTTP along with many other protocols. It is capable of sending various types of web requests from the command line, which makes it very useful in web penetration tests.

Basic cURL request:  #curl website.com

We may also use cURL to download a page or a file and output the content into a file using the -O flag. This will provide a status output but this can be silenced with the -s flag.

NOTE: The -h (help) flag or #man curl can be used to explore other cURL options.
