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
Comparison operators are used to determine how the defined values will be compared. Operators are differentiated between:

- string operators
- integer operators
- file operators
- boolean operators

### String Operators
|Operator|Description|
|:-:|:-:|
|==|	is equal to|
|!=|	is not equal to|
|<|	is less than in ASCII alphabetical order|
|>|	is greater than in ASCII alphabetical order|
|-z|	if the string is empty (null)|
|-n|	if the string is not null|

String comparison operators "< / >" works only within the double square brackets [[ <condition> ]]. 

Variables must also be put in quotes (" "). This tells Bash that the content of the variable should be handled as a string. Otherwise, we would get an error.

### Integer Operators
|Operator|Description|
|:-:|:-:|
|-eq|	is equal to|
|-ne|	is not equal to|
|-lt|	is less than|
|-le|	is less than or equal to|
|-gt|	is greater than|
|-ge|	is greater than or equal to|

### File Operators
The file operators are useful if we want to find out specific permissions or if they exist.
|Operator|Description|
|:-:|:-:|
|-e|	if the file exist|
|-f|	tests if it is a file|
|-d|	tests if it is a directory|
|-L|	tests if it is if a symbolic link|
|-N|	checks if the file was modified after it was last read|
|-O|	if the current user owns the file|
|-G|	if the file’s group id matches the current user’s|
|-s|	tests if the file has a size greater than 0|
|-r|	tests if the file has read permission|
|-w|	tests if the file has write permission|
|-x|	tests if the file has execute permission|

### Logical Operators
|Operator|Description|
|:-:|:-:|
|!|	logical negotation NOT|
|&&|	logical AND|
|\|\||	logical OR|

To request user input during a script the Read command can be used. 

```
read -p "Select your option: " opt
```
The -p option ensures the user input is on the same line as the prompt.

The tee utility can be used to provide outputs as the script is processing, instead of only showing after the script portion is complete:
```
whois $ip | grep "NetRange\|CIDR" | tee -a CIDR.txt
```
In this example tee -a will append the outputs from whois $ip to the CIDR.txt file while also displaying to the user's screen.

## Flow Control - Loops
Each control structure is either a branch or a loop. Logical expressions of boolean values usually control the execution of a control structure. Loop control structures include:

Loops:

- For Loops - executed on each pass for precisely one parameter.
- While Loops - A statement is executed as long as a condition is fulfilled (true). The while loops also work with conditions like if-else.
- Until Loops - The code inside a until loop is executed as long as the particular condition is false. The other way is to let the loop run until the desired value is reached.

## Flow Control - Branches
Branches:

- If-Else Conditions
- Case Statements

Case statements are also known as switch-case statements in other languages, such as C/C++ and C#. The main difference between if-else and switch-case is that if-else constructs allow us to check any boolean expression, while switch-case always compares only the variable with the exact value. Therefore, the same conditions as for if-else, such as "greater-than," are not allowed for switch-case. 
```
case <expression> in
	pattern_1 ) statements ;;
	pattern_2 ) statements ;;
	pattern_3 ) statements ;;
esac
```

## Functions
If we use the same routines several times in the script, the script's size will increase accordingly. In such cases, functions are the solution that improves both the size and the clarity of the script. Functions are an essential part of scripts and programs, as they are used to execute recurring commands for different values and phases of the script or program. Therefore, we do not have to repeat the whole section of code repeatedly but can create a single function that executes the specific commands. This helps to make the code easier to read and to keep the code as short as possible.

Functions must be coded at the beginning of a script since the code is read from top-down the functions must be defined before it is called.
```
#!/bin/bash

function print_pars {
	echo $1 $2 $3
}

one="First parameter"
two="Second parameter"
three="Third parameter"

print_pars "$one" "$two" "$three"
```

### Return Values
When we start a new process, each child process (for example, a function in the executed script) returns a return code to the parent process (bash shell through which we executed the script) at its termination, informing it of the status of the execution. This information is used to determine whether the process ran successfully or whether specific errors occurred. Based on this information, the parent process can decide on further program flow.

|Return Code|	Description|
|:-:|:-:|
|1|	General errors|
|2|	Misuse of shell builtins|
|126|	Command invoked cannot execute|
|127|	Command not found|
|128|	Invalid argument to exit|
|128+n|	Fatal error signal "n"|
|130|	Script terminated by Control-C|
|255\*|	Exit status out of range|

To get the value of a function back, we can use several methods like return, echo, or a variable.

## Debugging
Bash allows us to debug our code by using the "-x" (xtrace) and "-v" (verbose) options. 
```
thossa00@htb[/htb]$ bash -x -v CIDR.sh

#!/bin/bash

# Check for given argument
if [ $# -eq 0 ]
then
	echo -e "You need to specify the target domain.\n"
	echo -e "Usage:"
	echo -e "\t$0 <domain>"
	exit 1
else
	domain=$1
fi
+ '[' 0 -eq 0 ']'
+ echo -e 'You need to specify the target domain.\n'
You need to specify the target domain.

+ echo -e Usage:
Usage:
+ echo -e '\tCIDR.sh <domain>'
	CIDR.sh <domain>
+ exit 1
```

Bash shows us precisely which function or command was executed with which values. This is indicated by the plus sign (+) at the beginning of the line. Using only the "-x" option will show precisely which function or command was executed with which values instead of the whole script. 
```
+ '[' 0 -eq 0 ']'
+ echo -e 'You need to specify the target domain.\n'
You need to specify the target domain.

+ echo -e Usage:
Usage:
+ echo -e '\tCIDR.sh <domain>'
	CIDR.sh <domain>
+ exit 1
```
