# hydan

Hydan steganographically conceals a message into an application.

> See current status for info below

## Name meaning

Hydan [hI-dn]: Old english to hide or conceal.

## Fix and Rework

While doing the class Digital Forensics, the professor talked about this
program. I found it very difficult to compile and run the program. Because
of this and the fact that the program is not maintained anymore, I created
this repo to update the program.

## Goal

My goal is to make it run in 32 bit and then make it run in 64 bit eventually.

Of course any help is appreciated.

## Info

It took me a couple of hours `around 8` to make it at least hide some text
in a file. This is after using debugging, troubleshooting and using AI to
assist with newer implementations of OpenSSL libraries.

## Requirements

* libc6-dev-i386
* libelf-dev:i386
* libssl-dev:i386
* libssl-dev
* libelf-dev
* lib32z1
* gcc-multilib
* g++-multilib

You also need `libdisasm` but this is already included in the repo as the
32 bit version.

## Compiling

* make clean && make

## Running

### Embed

* `./hydan dist/target_exe_32bit dist/text.txt`

### Retrieve message

* `./hydan-decode dist/target_exe_32bit`

### Retrieve status of an executable

* `./hydan-stats dist/target_exe_32bit`

## Debugging

I had to use a nice program called `gdbgui` which allows you to run GDB but
in your browser. The advantage with this program is that the display does
not break like it does with `gdb -tui ./hydan`.

You need to install it using Python `pip3 install gdbgui`

* `python3 -m gdbgui --args ./hydan dist/target_exe_32bit dist/text.txt`

## Current status

1. I was able to embed data into an executable, run hydra-stats on it but was
   not able to retrieve the message with hydra-decode.
2. I had to disable the encryption and decryption of the password because no
   matter what I tried, it kept failing when trying to call `EVP_CIPHER_CTX_block_size`.
3. 

## Resources

* [Hydan wiki](http://justsolve.archiveteam.org/wiki/Hydan)
* [Original Hydan website in Archives](https://web.archive.org/web/20200108015102/http://crazyboy.com/hydan/)
* [Original source download](https://web.archive.org/web/20170827231142/http://www.crazyboy.com/hydan/hydan-0.13.tar.gz)
* [GDBGUI Github](https://github.com/cs01/gdbgui)
* [GDBGUI website](https://www.gdbgui.com/)

