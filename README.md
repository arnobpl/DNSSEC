# DNSSEC

Introduction
============
This project simulates DNSSEC (especially NSEC) focusing how to prevent zone walking attack. For simplification, DNSSEC server has been seen as a single server instead of multiple servers. It also contains an experimental mechanism (called low profiling) to prevent such attack.


Code Overview
=============
## Automated Test (`src/AutomatedTest.java`)
For automatic testing, only the `main` method in this source should be used. It automatically runs server with low profiling mechanism and attacker clients. It also generates files (in `AutomatedTest` folder) containing the test results. The results contain the data of 
1 input column for attacker (`AttackNoise`) and 1 input column for server (`TotalSuspiciousRecords`):
  - `AttackNoise` (for attacker): The amount of noise in scale of 0.0 to 1.0 (inclusive), higher noise for stronger attack
  - `TotalSuspiciousRecords` (for server): The limiting value of total suspicious records for each client to detect attacker

Each input column has 4 output columns common for both attacker and server:
  - `DomainFetched`: The number of domains fetched from the server by the attacker using zone walking attack
  - `AttackCoverage`: The ratio between the number of domains fetched by the attacker and the number of domains stored in the server
  - `AttackRuntime (msec)`: The elapsed runtime of the attacker client (in milliseconds)
  - `AttackSpeed (domain per msec)`: The speed of fetching domain by the attacker (in the number of domains fetched per millisecond)

## Server Package (`src/DNSSEC/ServerPack`)
  - `Server` class: It is an abstract class. The methods `setupServer` and `respond` must be implemented in subclasses.
  - `Security` package: All the classes inside the package implement `Server` abstract class. Here are the classes:
    - `NSEC` class: It contains standard NSEC implementation.
    - `LowProfiling` class: It contains an experimental mechanism to prevent zone walking attack. It is based on NSEC but with added mechanism to detect and block probable attackers.

## Client Package (`src/DNSSEC/ClientPack`)
  - `Client` class: It is an abstract class. The methods `setupClient` and `request` must be implemented in subclasses.
  - `Behaviour`package: All the classes inside the package implement `Client` abstract class. Here are the classes:
    - `Legitimate` class: It contains a standard implementation in which a domain from console input will be sent to the server.
    - `Attacker` class: It contains a possible behaviour to perform zone walking attack. It is interesting that only the DNSSEC server implemented by `LowProfiling` can prevent the attack. But the DNSSEC server implemented by `NSEC` cannot prevent the attack at all.

## Common Package (`src/DNSSEC/Common`)
It contains the classes which is common for both server and client. Here are the classes:
  - `RSA_Cryptography` class: It contains all the methods related to RSA encryption and decryption. They have been used in signature creation (inside server) and verification (inside client).
  - `NetworkTask` class: It contains common network task(s).

## RSA Keys (`RSA_keyPair` folder)
It contains the public key (`publicKey` file) and the private key (`privateKey` file). Both files are binary files. It is obvious that the private key cannot be accessed by any of the classes inside `Client` package.

## Domain-IP Records (`domain_ip.csv` file)
It contains more than 200 domains along with their corresponding IP addresses. For simulation purpose, all the records will be stored at a time in the volatile memory (RAM) by the server at the beginning of the simulation.

## Attacker File (`Attacker` folder)
It contains the file(s) created by `Attacker` client. If zone walking attack is successful, then the file in the folder will store almost all the data from the server's domain-IP records.

## Main Files (`ClientMain.java` and `ServerMain.java` in `src` folder)
These are the classes containing `main` methods for server and client. To test the simulation in various server-client combinations, these files may be edited. It is obvious that server must be run before running any client. Only a single server can be run at a time using same port, but more than one clients can be run simultaneously.


Acknowledgement
===============
The sources which have been used in this simulation:
  - Domain-IP records: The domain list has been taken from a Github user named [Hipo](https://github.com/Hipo/university-domains-list). To retrieve the corresponding IP addresses, a Python script by [hasan151623](https://github.com/hasan151623) has been used.
  - RSA cryptography and RSA keys: The main part of RSA cryptography and RSA keys has been taken from [Mkyong.com](https://www.mkyong.com/java/java-asymmetric-cryptography-example/). I have only added the signature and hashing part here.

