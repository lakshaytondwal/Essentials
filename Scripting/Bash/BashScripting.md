# Bash

## 1. Introduction

Bash (Bourne Again Shell) is a command-line interpreter and scripting language used to interact with the operating system.

A shell is a program that acts as an interface between the user and the operating system kernel. It allows users to execute commands, automate tasks, and manage files and processes by taking user input, interpreting it, and executing it. Bash is widely used for task automation, system administration, running programs, file management, and cybersecurity or server operations. It is commonly used on Linux systems, macOS, servers, cloud environments, and Windows Subsystem for Linux (WSL).

```bash
## Check Current Shell
echo $SHELL 
Output example: /bin/bash

## Check Bash Version
bash --version

## echo
echo Hello World

Output:
Hello World
```

---

## 2. Basic Script Creation

A Bash script is a file containing a sequence of commands executed automatically by the Bash interpreter. Instead of typing commands manually in the terminal, you store them in a file (commonly named with a `.sh` extension for clarity, though it’s not required) and run them whenever needed. The first line should be the shebang `#!/bin/bash`, which specifies the interpreter, ensures the script runs with Bash, and avoids issues if another shell is set as default.

A simple script might include:

```bash
#!/bin/bash

# This is a single-line comment

: '
This is a multi-line comment
using the null command method
It is ignored during execution
'

<<COMMENT
This is another multi-line comment
using the here-document method
It is also ignored
COMMENT

echo "This is my first Bash script"
echo "Bash scripting is useful for automation"
```

Commands execute from top to bottom, and the output is displayed in the terminal. By default, scripts do not have execute permission, so you must run `chmod +x script.sh` to make them executable. You can then run the script either directly with `./script.sh` or by invoking the interpreter using `bash script.sh`. When executed, the system reads the shebang, loads the script into Bash, runs each command sequentially, and displays the results.

---

## 3. Variables

### Creating Variables

In Bash, variables are created without using a data type.

Syntax:

```bash
variable_name=value
```

Important:

* No spaces around `=`
* Variable names are case-sensitive

Example:

```bash
name="Tom"
age=19
```

### Accessing Variables

Use `$` to access the value of a variable.

```bash
echo $name
echo $age
```

Output:

```bash
Tom
19
```

You can also use braces (recommended for clarity):

```bash
echo ${name}
```

### Rules for Naming Variables

* Must start with a letter or underscore
* Cannot start with a number
* Can contain letters, numbers, and underscores
* No spaces allowed
* Case-sensitive (`age` and `Age` are different)

Valid:

```bash
user_name="admin"
_count=10
```

Invalid:

```bash
2name="test"
user-name="test"
```

### Read-Only Variables

A variable can be made constant using `readonly`.

```bash
readonly pi=3.14
```

Attempting to modify it will cause an error.

### Command Substitution

Command substitution is used to store the output of a command in a variable.

Syntax:

```bash
variable=$(command)
````

Example:

```bash
current_user=$(whoami)
echo $current_user
```

```bash
# Old syntax (not recommended):
variable=`command`

# Recommended syntax:
variable=$(command)
```

### Environment Variables

Environment variables are system-wide variables accessible to scripts and processes. They store important system information that programs use during execution. Common examples include:

```bash
echo $HOME
echo $USER
echo $PATH
```

You can create a temporary environment variable using:

```bash
export project="bash_notes"
```

This makes `project` available in the current session and to any child processes started from it. However, it will disappear once the terminal session ends.

To make the variable permanent, you need to add it to the `~/.bashrc` file, which runs automatically whenever a new Bash session starts.

### Special Variable: `$RANDOM`

Bash also provides built-in special variables such as `$RANDOM`, which generates a random integer between 0 and 32767 each time it is accessed:

```bash
echo $RANDOM
```

This is commonly used in scripts for generating random numbers, simple simulations, or automation tasks.

---

## 4. User Input

### read Command

The `read` command is used to take input from the user.

```bash
read variable_name
```

Example:

```bash
echo "Enter your name:"
read name
echo "Hello $name"
```

### Prompt Input

You can provide a prompt directly:

```bash
read -p "Enter your age: " age
echo "You are $age years old"
```

### Silent Input (Password)

Use `-s` to hide input (useful for passwords):

```bash
read -s -p "Enter password: " password
echo
echo "Password received"
```

---

## 5. Conditional Statements

### if Statement

Syntax:

```bash
if [ condition ]
then
    commands
fi
```

Example:

```bash
if [ $age -gt 18 ]
then
    echo "Adult"
fi
```

### if-else

```bash
if [ $age -ge 18 ]
then
    echo "Adult"
else
    echo "Minor"
fi
```

### if-elif-else

```bash
if [ $marks -ge 90 ]
then
    echo "Grade A"
elif [ $marks -ge 75 ]
then
    echo "Grade B"
else
    echo "Grade C"
fi
```

### Nested Conditions

```bash
if [ $age -ge 18 ]
then
    if [ $age -lt 60 ]
    then
        echo "Working age"
    fi
fi
```

### case Statement (Switch Equivalent)

The `case` statement is used to match a variable against multiple values. It is cleaner than using many `if-elif` conditions.

Syntax:

```bash
case variable in
    value1)
        commands
        ;;
    value2)
        commands
        ;;
    *)
        default commands
        ;;
esac
```

Example:

```bash
read -p "Enter option (start/stop): " option

case $option in
    start)
        echo "Starting service"
        ;;
    stop)
        echo "Stopping service"
        ;;
    *)
        echo "Invalid option"
        ;;
esac
```

---

## 6. Operators

### Arithmetic Operators

Used inside double parentheses `(( ))`:

```bash
a=10
b=5

echo $((a + b))
echo $((a - b))
echo $((a * b))
echo $((a / b))
echo $((a % b))
```

Operators:

* `+` Addition
* `-` Subtraction
* `*` Multiplication
* `/` Division
* `%` Modulus

### Relational Operators

Used inside `[ ]`:

* `-eq` Equal
* `-ne` Not equal
* `-gt` Greater than
* `-lt` Less than
* `-ge` Greater or equal
* `-le` Less or equal

Example:

```bash
if [ $a -gt $b ]
then
    echo "a is greater"
fi
```

### Logical Operators

* `&&` AND
* `||` OR
* `!` NOT

Example:

```bash
if [ $age -gt 18 ] && [ $age -lt 60 ]
then
    echo "Valid age range"
fi
```

### String Operators

* `=` Equal
* `!=` Not equal
* `-z` String is empty
* `-n` String is not empty

Example:

```bash
if [ "$name" = "admin" ]
then
    echo "Access granted"
fi
```

### File Test Operators

* `-f` Regular file exists
* `-d` Directory exists
* `-r` Read permission
* `-w` Write permission
* `-x` Execute permission

Example:

```bash
if [ -f "file.txt" ]
then
    echo "File exists"
fi
```

---

## 7. Loops

### for Loop

```bash
for i in 1 2 3 4 5
do
    echo $i
done
```

Range syntax:

```bash
for i in {1..5}
do
    echo $i
done
```

### while Loop

```bash
count=1

while [ $count -le 5 ]
do
    echo $count
    ((count++))
done
```

### until Loop

Runs until condition becomes true.

```bash
count=1

until [ $count -gt 5 ]
do
    echo $count
    ((count++))
done
```

### break and continue

`break` stops the loop.

`continue` skips current iteration.

Example:

```bash
for i in {1..5}
do
    if [ $i -eq 3 ]
    then
        continue
    fi
    echo $i
done
```

---

## 8. Functions

### Creating Functions

Syntax:

```bash
function_name() {
    commands
}
```

Example:

```bash
greet() {
    echo "Hello"
}
```

### Calling Functions

```bash
greet
```

### Passing Arguments

Arguments are accessed using `$1`, `$2`, etc.

```bash
add() {
    echo $(($1 + $2))
}

add 5 3
```

### Returning Values

Functions return exit status (0–255).

```bash
check() {
    return 0
}

check
echo $?
```

`$?` stores the last command's exit status.

---

## 9. Command Line Arguments

When running a script:

```bash
./script.sh arg1 arg2
```

### Special Variables

* `$0` Script name
* `$1` First argument
* `$2` Second argument
* `$#` Number of arguments
* `$@` All arguments (separate)
* `$*` All arguments (single string)

Example:

```bash
echo "Script name: $0"
echo "First arg: $1"
echo "Total args: $#"
```

---

## 10. Arrays

### Creating Arrays

```bash
fruits=("apple" "banana" "mango")
```

### Accessing Elements

Index starts from 0.

```bash
echo ${fruits[0]}
echo ${fruits[1]}
```

Access all elements:

```bash
echo ${fruits[@]}
```

### Array Length

```bash
echo ${#fruits[@]}
```

### Looping Through Arrays

```bash
for fruit in ${fruits[@]}
do
    echo $fruit
done
```

---

## 11. File Handling

### Storing File Content in Variables (Command Substitution)

Command substitution is used to store the output of a command in a variable.

Syntax:

```bash
variable=$(command)
````

Example:

```bash
content=$(cat hello.txt)
echo $content
```

The variable `content` now contains the contents of `hello.txt`.

Example:

```bash
filename="hello.txt"
data=$(cat "$filename")
echo $data
```

### Reading File Line by Line

Used when processing files inside scripts.

```bash
while read line
do
    echo "Line: $line"
done < hello.txt
```

Each line is stored in the variable `line`.

### Counting Lines in File

```bash
count=$(wc -l < hello.txt)
echo "Total lines: $count"
```

### Writing to Files from Script

Overwrite file:

```bash
echo "Hello World" > file.txt
```

Append to file:

```bash
echo "New line" >> file.txt
```

Using variable:

```bash
message="Hello"
echo "$message" > file.txt
```

### Checking if File Exists

```bash
filename="hello.txt"

if [ -f "$filename" ]
then
    echo "File exists"
else
    echo "File does not exist"
fi
```

### Checking Directory Exists

```bash
dirname="myfolder"

if [ -d "$dirname" ]
then
    echo "Directory exists"
fi
```

### Reading File into Array

```bash
lines=($(cat hello.txt))

echo ${lines[0]}
echo ${lines[1]}
```

### Processing File with Loop

Example:

```bash
while read user
do
    echo "User: $user"
done < users.txt
```

---
