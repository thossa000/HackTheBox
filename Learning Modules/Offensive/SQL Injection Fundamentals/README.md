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



