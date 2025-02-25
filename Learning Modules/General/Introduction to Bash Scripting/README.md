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
