# SQL Injection Fundamentals
Notes for the HackTheBox learning module, SQL Injection Fundamentals.

## SQL Injection (SQLi)
A SQL injection occurs when a malicious user attempts to pass input that changes the final SQL query sent by the web application to the database, enabling the user to perform other unintended SQL queries directly against the database. In the most basic case, this is done by injecting a single quote (') or a double quote (") to escape the limits of user input and inject data directly into the SQL query. To retrieve our new query's output, we have to interpret it or capture it on the web application's front end.

# Intro to Databases
## Database Management Systems
A Database Management System (DBMS) helps create, define, host, and manage databases. Various kinds of DBMS were designed over time, such as file-based, Relational DBMS (RDBMS), NoSQL, Graph based, and Key/Value stores.

Some of the essential features of a DBMS include:
|Feature|	Description|
|:-:|:-:|
|Concurrency|	A real-world application might have multiple users interacting with it simultaneously. A DBMS makes sure that these concurrent interactions succeed without corrupting or losing any data.
|Consistency|	With so many concurrent interactions, the DBMS needs to ensure that the data remains consistent and valid throughout the database.
|Security|	DBMS provides fine-grained security controls through user authentication and permissions. This will prevent unauthorized viewing or editing of sensitive data.
|Reliability|	It is easy to backup databases and rolls them back to a previous state in case of data loss or a breach.
|Structured Query Language|	SQL simplifies user interaction with the database with an intuitive syntax supporting various operations.

DBMS often follow a 2 tier architecture.

Tier I usually consists of client-side applications such as websites or GUI programs.

Tier II is the middleware, which interprets these events and puts them in a form required by the DBMS. The DBMS receives queries from the second tier and performs the requested operations. These operations could include insertion, retrieval, deletion, or updating of data.

After processing, the DBMS returns any requested data or error codes in the event of invalid queries.

# Types of Databases
Databases, in general, are categorized into Relational Databases and Non-Relational Databases. Only Relational Databases utilize SQL, while Non-Relational databases utilize a variety of methods for communications.

## Relational Databases
A relational database is the most common type of database. It uses a schema, a template, to dictate the data structure stored in the database. Tables in a relational database are associated with keys that provide a quick database summary or access to the specific row or column when specific data needs to be reviewed. These tables, also called entities, are all related to each other.

## Non-relational Databases
A non-relational database (also called a NoSQL database) does not use tables, rows, and columns or prime keys, relationships, or schemas. Instead, a NoSQL database stores data using various storage models, depending on the type of data stored. Due to the lack of a defined structure for the database, NoSQL databases are very scalable and flexible.

When dealing with datasets that are not very well defined and structured, a NoSQL database would be the best choice for storing such data. There are four common storage models for NoSQL databases:

- Key-Value
- Document-Based
- Wide-Column
- Graph

Each of the above models has a different way of storing data. For example, the Key-Value model usually stores data in JSON or XML, and have a key for each pair, and stores all of its data as its value.

The most common example of a NoSQL database is MongoDB.
