# Introduction to Bash Scripting
Brief notes written to review the material in the HackTheBox Academy module, Intro to Bash Scripting.

## Bourne Again Shell
Bash is the scripting language we use to communicate with Unix-based OS and give commands to the system. Since May 2019, Windows provides a Windows Subsystem for Linux that allows us to use Bash in a Windows environment.The main difference between scripting and programming is that we don't need to compile the code to execute the scripting language, as opposed to programming languages. In general, a script does not create a process, but it is executed by the interpreter that executes the script, in this case, the Bash.

Like programming a scripting language can be divided into the following categories:

- Input & Output
- Arguments, Variables & Arrays
- Conditional execution
- Arithmetic
- Loops
- Comparison operators
- Functions

## Conditional Execution
### Shebang
The shebang line is always at the top of each script and always starts with "#!". This line contains the path to the specified interpreter (/bin/bash) with which the script is executed. We can also use Shebang to define other interpreters like Python, Perl, and others.

#!/bin/bash - Shebang.

### If-Else-Fi
One of the most fundamental programming tasks is to check different conditions. Usually has two different forms in programming and scripting languages, the if-else condition and case statements. By default, an If-Else condition can contain only a single "If". When adding Elif or Else, we add alternatives to treat specific values or statuses. If a particular value does not apply to the first case, it will be caught by others.
```
#!/bin/bash

value=$1

if [ $value -gt "10" ]
then
	echo "Given argument is greater than 10."
elif [ $value -lt "10" ]
then
	echo "Given argument is less than 10."
else
	echo "Given argument is not a number."
fi
```

## Arguments, Variables, and Arrays
### Arguments
The advantage of bash scripts is that we can always pass up to 9 arguments ($0-$9) to the script without assigning them to variables or setting the corresponding requirements for these. 9 arguments because the first argument $0 is reserved for the script. As we can see here, we need the dollar sign ($) before the name of the variable to use it at the specified position. 
```
thossa00@htb[/htb]$ ./script.sh ARG1 ARG2 ARG3 ... ARG9
       ASSIGNMENTS:       $0      $1   $2   $3 ...   $9
```

### Special Variables
Special variables use the Internal Field Separator (IFS) to identify when an argument ends and the next begins. Bash provides various special variables that assist while scripting.

|IFS|	Description|
|:-:|:-:|
|$#|	This variable holds the number of arguments passed to the script.|
|$@|	This variable can be used to retrieve the list of command-line arguments.|
|$n|	Each command-line argument can be selectively retrieved using its position. For example, the first argument is found at $1.|
|$$|	The process ID of the currently executing process.|
|$?|	The exit status of the script. This variable is useful to determine a command's success. The value 0 represents successful execution, while 1 is a result of a failure.|

Of the ones shown above, we have 3 such special variables for if-else conditions.

|IFS|	Description|
|:-:|:-:|
|$#|	In this case, we need just one variable that needs to be assigned to the domain variable. This variable is used to specify the target we want to work with. If we provide just an FQDN as the argument, the $# variable will have a value of 1.|
|$0|	This special variable is assigned the name of the executed script, which is then shown in the "Usage:" example.|
|$1|	Separated by a space, the first argument is assigned to that special variable.|

### Variables
The assignment of variables takes place without the dollar sign ($). The dollar sign is only intended to allow this variable's corresponding value to be used in other code sections. When assigning variables, there must be no spaces between the names and values.
```
domain=$1
echo $domain
```
In contrast to other programming languages, there is no direct differentiation and recognition between the types of variables in Bash like "strings," "integers," and "boolean." All contents of the variables are treated as string characters. 

### Arrays
Several values can be assigned to a variable in Bash. These variables are called arrays, they are used to store and process an ordered sequence of specific type values. Arrays identify each stored entry with an index starting with 0. When we want to assign a value to an array component, we do so in the same way as with standard shell variables. All we do is specify the field index enclosed in square brackets. 
```
#!/bin/bash

domains=(www.inlanefreight.com ftp.inlanefreight.com vpn.inlanefreight.com www2.inlanefreight.com)

echo ${domains[0]}
```

## Comparison Operators
