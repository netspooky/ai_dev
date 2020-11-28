# Ai Amano

YO - If you are reading this, this is only being shared because I am trying to do some beta testing and dev with people. It's not for public use yet, so if you decide to start playing with it and it doesn't work, sit tight until we figured it out hehe.

Ai Amano is a matrix bot that has been running on various Matrix servers since about April 2019. It's been heavily battle tested and hacked on, until Fall 2020 when we decided to finally port it to the new matrix-nio python library. This library is a far more robust than the library we used before, and it supports encryption and other nifty features. All that being said, there is still a bunch of things we need to add before this can be officially rolled out. If you'd like to help dev, please contact me (@netspooky) on Twitter.

## Setup

Install requirements.txt, then decide if you want to use matrix-nio with end to end encryption support (for DMs) or not. Install matrix-nio according to the instructions [here](https://github.com/poljar/matrix-nio). There have historically been issues with libolm, but it might be better now? Idk I literally compiled the shared object from scratch and have been using it on vms I deploy because it was ridiculous at first :D

For now, run tokenstore.py to generate your credentials.json file. This is what is used for authentication across sessions and allows your bot to start up faster.

### API Keys

There are API keys for a number of services in secrets.yml. If you want to use these services, get a key or creds and set up within secrets.yml. If a key does not exist, the bot will let you know.

### Server Output

Some command output may be really large, so we've setup a way to post the output of a file to a web directory on the server that the bot is running on. If you want to set up a directory for large command output, configure the config["output_dir"] and config["domain"] key in secrets.yml.

### Other Config

You don't need to set up the server/username/password secrets in secrets.yml, as we are using tokenstore.py for auth until a nicer scheme is developed :)

### Running Ai

Once everything is set up, simply run:

    python3 ai.py

## Dev

Here are some quick notes for those who would like to develop new commands for their bot!

### core/helper.py

Helper functions
- getDigits(someText) returns only digits from text.
- valid_ip(address) returns True if an IP is valid
- getTime() returns the current time
- loadYML(infile) returns data from a yaml file as a dict
- aiLog(event) does whatever logging you need
- readFile(file) returns the contents of a file
- getLine(file) returns a random line from a file
- getFace(mood) returns a random kaomoji face, mood args are "yay" and "nay"

Variables
- SECRETS is the secrets.yml file as a dict
- startTime is when the bot started
- fmt1 and fmt2 can be used to wrap preformatted text

### Designing a new command

Commands are just python functions that return _something_. It's the functions responsibility to prepare all of the text that is to be sent, from parsing event info to formatting. You can also use some of the things in core/helper.py to assist with these tasks.

Adding a new command is rather simple. First, pick a file you want to add too. If you want to create a new file to store commands, make sure you add the file name to core/__init__.py.

Depending on how you run / test these files, the import scheme can be weird, so we've just done this to make sure that it works no matter what.

    try:
        from core.helper import *
    except ImportError:
        from helper import *

Now you can create your command. Every command should have the args [room](https://matrix-nio.readthedocs.io/en/latest/nio.html#module-nio.rooms) and [event](https://matrix-nio.readthedocs.io/en/latest/nio.html#module-nio.events.room_events) objects passed to them, as that is the information given by the command parser. 

A simple command could be as follows:

    def sayHello(room,event):
        aiLog(event)
        s = event.sender
        return "Hello {}".format(s)

The aiLog(event) function from core/helper.py is used to log an event. The s variable represents that username of the person who ran the command. All commands should return the output of the command, so here the data returned is "Hello" + the name of the sender.

Now that this is set up, the last step is to add it to the command dict in ai.py.

cmdDict is a dictionary containing the command syntax for your bot, and a function to run when the command is called. You can pick any syntax you like, but we have historically used an exclamation point followed by a keyword to run the command. The command must appear at the start of the message, or it won't be called.

You can add your command like this:

    "!hello": core.mymodule.sayHello,

## Needs Work

This bot was ported from an old Matrix bot library, and some of the things that were redesigned have broken a small amount of functionality which is logged here.

- Auth - Using tokenstore.py now, but this login functionality and key checking can be implemented easily within ai.py or something...
- Logging. In core/helper.py, all it does right now is print something, could possibly use a small sqlite db or something to have logs, but couldn't decide.
- XSS and fuzz commands - They keep being interpreted due to how we send output now (custom_html). The solution might be to just have supplementary data from a command that marks how it's output should be formatted, or just not have xss and fuzz commands.
- File Uploads - This changed in the new library, and hasn't yet been implemented.
- Other CI/CD - This was part of the original Ai bot, but it hasn't been put into this version yet.
