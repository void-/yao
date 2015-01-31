Implementation Protocol of a Solution to Yao's Millionaire's Problem
====================================================================
Overview
--------
This program allows two parties to compare numbers without revealing their
values via the network using a secure multi-party computation. This is
formalized as [Yao's Millionaire's
Problem](https://en.wikipedia.org/wiki/Yao%27s_Millionaires%27_Problem).

This is an implementation of the protocol outlined in "An Efficient Protocol
for Yao's Millionaire's Problem" (Ioannidis&Grama 03).

Use
---
An example application:

Alice and Bob want to determine who received the better score on their most
recent exam. However, neither one wants to reveal the actual value of their
respective scores. Alice will act as the server, Bob the client.

Alice

    $ SECRET=93
    $ PORT=8080
    $ ./yao $SECRET $PORT
    Listening on port 8080
    ...
    Ask the client for the result

Bob

    $ SECRET=23
    $ PORT=8080
    $ ALICE=192.168.1.111
    $ ./yao $SECRET $ALICE $PORT
    ...
    Server's is >= Client's

Building
--------

To build the main program, run:
> $ make

Dependant on:
- libssl
- libcrypto
- glibc
- unix headers

To generate documentation, run:
> $ make docs

Dependant on:
- doxygen

Current Issues
--------------

- The implementation appears to be correct, but its probably riddled with
vulnerabilities.

- Anticipating network failure hasn't been accounted for. Currently,
disconnection in the middle of the protocol will just cause the other
participant to spin in an infinite loop.

- This has only been tested on GNU/Linux, it may build on some other Unix-like
  systems
