last updated january 11, 2025

welcome to my fileserver!
this is a simple place to upload and host static files for whatever purposes you need

if you need a registration key or experience any issues or unintended behaviors, do not hesitate to get in contact!
my contact information can be found on https://elisttm.space/

if you wish to support me, i take kofi at https://ko-fi.com/elisttm

---------- USER INFORMATION ----------

as a user, you have near full control over your personal directory

file management mode can be entered by clicking "manage files" under the file list
in file management mode you can...
    - create folders
    - rename files
    - delete selected files
    - move selected files in/out of a folder

you can also upload things straight from your personal directory, including multiple files at once
uploads have a maximum size limit of 64mb at a time. this includes the sum of every selected file
filenames have a max length of 32 characters and can only contain letters, numbers, and some symbols

it is recommended that you NEVER upload anything personally sensitive or illegal
nsfw and piracy are fine, but please dont add anything that will get me in trouble

---------- SPECIAL FILES ----------

you can create special "linkto" files that can link to external urls or to other files/folders on this server

to make one, create a plain file that starts with "LINKTO" plus an identifier. for example, "LINKTO-elisttm"
this identifier doesnt do anything functionally, it just differentiates it from any other link files you may make

now, edit the file and add your link to line 1. you can also add a vanity label on line 2.
the link on the first line can be any url OR a file/folder path formatted like so: "/eli/example.png"

---------- SHAREX UPLOADING ----------

if you use sharex, you can add this website as a custom upload destination!
be warned that this will stop working if you ever log out in your browser

    1. in sharex, navigate to destinations -> custom uploader settings
    2. download "sharex-uploader.sxcu" from the public directory and import it
    3. in your browser, ensure you are logged in with "remember me" checked
    4. open devtools; in chrome you can do this by pressing f12
    5. navigate to the application tab and open the cookies section in the sidebar
    6. copy the value of "AUTH" into the "Cookie" header in place of "abc123"
    7. on the bottom left in sharex, select elisttm for image/file uploader and test it!

you can also change the subdirectory that sharex uploads to by adding a folder to the "folder" url parameter

---------- CHANGELOG ----------

    1/11/24
cleaned up files and code, finished writing public README.txt (this file!)
added vanity name support to "linkto" files

    12/22/24
implemented special "linkto" files that can crosslink files or link to other websites

    12/15/24
added "remember me" checkbox in login page
reworked file and username sanitization to allow more user freedom

    12/12/24
added rudimentary api support for uploads (sharex)

    12/11/24
minor fixes to support url changes

    12/10/24
removed upload button on header in favor of the button in user folders
changed urls: files are now served under /f/ and directories are now under /u/

    12/9/24
added folders
added file management mode
