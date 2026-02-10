# Subnetter Tool
## Description :
This is a simple tool to find details about a network if you have the cidr and ip values. 

'subnetter.c' is the file with all the actual code.

The file has so much comments ,so you might not have trouble understanding the code 😅

I am also happy to hear from any of you about anything because I am new to post publicly on Github 😁. 
In fact I am looking forward to any feedback...

If you are using for the first time, try using the `--help` argument.

Also thank you for using or reading this program 😇 

## How to use (Linux) : 
First clone this repo by typing `git clone https://github.com/Oliver-Proto/subnetter.git` on your terminal.

Use `cd subnetter` to get into the cloned folder.

I don't have any makefiles or so. You will have to compile it with gcc or any compiler of your preference

I also have a gcc compiled executable for linux in the 'compiled' folder if you wanna use that instead of compiling

On linux, use the follwing command in terminal to compile with gcc:

`gcc -o subnetter subnetter.c -lm`

**NOTE:** -lm flag must be used to link the math module as I use `pow()` in this program. 

## How to use (Windows/ Mac) :
Sorry guys. I don't have instructions for you on how to compile because I haven't used windows or mac that much.

You can simply compile this with any compiler for your platforms or even open it in you favourite editor (eg: VS Code)
and compile and run the program from there.

I don't use VS Code btw...

## Example use:

<img src="example.png" alt="example.png">
