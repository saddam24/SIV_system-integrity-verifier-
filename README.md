# SIV_system-integrity-verifier-

In this 
assignment,
I  implemented a very simple system integrity verifier (SIV)
for a Linux system.
The goal of the SIV is to detect file system modifications occurring within a directory 
tree
. The SIV outputs statistics and warnings about changes to a report file specified by the 
user.The SIV can be run either in initialization mode or in verification mode.


#Initialization mode
In initialization mode, the SIV  program requires
the user to enter a path to a monitored 
directory, another path to a verification file (outside the monitored directory), a third path to a report file and a hash function (e.g., the SIVshould support at least MD-5 
and SHA-1

