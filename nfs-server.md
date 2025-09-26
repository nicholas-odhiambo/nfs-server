### MANUAL NFS SERVER

\*\*Priority Level\*\*: HIGH

\*\*Estimated Time\*\*: 20 minutes

\*\*Required Access\*\*:

\*\*Risk Level\*\*:

#### Description

Configuring a Network File Sharing Server (NFSv4) a local network.

#### Platform → RedHat

#### Prerequisites

\- Server-Client Architecture

\- Install Required Packages

BASIC INSTALLATION SETUP SERVER SIDE:

1\. Update computer packages List and Install the nfs package:

-   dnf update -y
-   dnf install nfs-utils -y

2\. Start the server and check the status

-   systemctl start nfs-server
-   systemctl status nfs-server
-   systemctl enable –now nfs-server

3\. Configure exports

Create and configure the directories you want to share with the clients.
This is done by editing **/etc/exports.d, **and create a drop-in file to
share:

**vim /etc/exports.d/shared_directory_name** and edit specifying:

1.  Directories to be shared
2.  Target client
3.  Permissions assigned

4\. Create directories specified in the previous step:

-   mkdir -pv / shared_directory_name

5\. Add files to be shared:

cp \~/Documents /shared_directory_name -r

comdu

6\. Re-initilaize the nfs services

-   exportfs -r

6\. Allow firewall rules:

firewall-cmd –add-service nfs

firewall-cmd –realod

**BASIC INSTALLATION SETUP CLIENT SIDE**

1\. Install the Package

dnf install nfs-utils

2\. Create a mount point for a our shared directory

mkdir -pv /mnt/directory_name

3\. Mount the shared_directory using fstab file:

vim /etc/fstab i

4\. start the nfs service

Confirm if the shared_directory is mounted.

Cd /mnt/directoty_name
