SRARPD
======

Description
-----------

`srarpd` is a simplified implementation of the RARP protocol 
[RFC 903](https://tools.ietf.org/html/rfc903) in C.

Simplified refers to the fact that it only handles requests to lookup IPv4 
addresses based on Ethernet (type 0x0001) link layer (MAC) addresses.

`srarpd` uses `sqlite3 3.20.1 (3200100)` as the underlying database for the
storage/lookup of addresses.

Motivation
----------

Just for the fun of it!

Build dependencies
------------------
Linux system with
* ANSI C compiler
* RAW sockets support
* libpthread
* libdl

SQLite3 database schema
-----------------------

Currently there is only one table named `ADDRESSES` with the following columns:

* `MAC_ADDRESS (TEXT)` - stores the MAC address in lowercase hexadecimal notation, with the bytes delimeted by `:`, e.g. `a8:33:43:0b:42:1a`
* `IPV4_ADDRESS (TEXT)` - stores the IPv4 address in decimal notation with the bytes delimeted by `.`, e.g. `192.168.1.3`


TODO
----

* Parse command-line arguments using getopt and validate them
* DB entry listing, insertion, update and deletion


License
-------
MIT license
