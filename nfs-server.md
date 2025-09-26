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

1.  Directories to be shared, Target client & Permissions assigned

<img src="nfs_media/Pictures/1000000100000400000003001E602FAB.png" style="width:4.6244in;height:1.8862in" />

Create directories specified in the previous step:

-   mkdir -pv / shared_directory_name

Add files to be shared:

cd ** / shared_directory_name**

** **cp \~/Documents /shared_directory_name -r

Check and Set correct Selinux Context

ls -z /shared

Assign the public_contect_t or nfs_t type (commonly used for NFS
exports)

semanage fcontext -a -t nfs_t “/shared()”

restorecon -Rv /shared

Re-initilaize the nfs services

-   exportfs -r
-   exportfs -v

<img src="nfs_media/Pictures/1000000100000400000003004E65A21D.png" style="width:6.4937in;height:2.6783in" />

Show the mounted directories: showmount -e

<img src="nfs_media/Pictures/1000000100000400000003000F895E1C.png" style="width:5.6047in;height:2.4063in" />

Allow firewall rules, NFS-related services and reload firewall :

firewall-cmd --permanent --add-service=nfs

firewall-cmd –reload

<img src="nfs_media/Pictures/1000000100000400000003006662B01E.png" style="width:5.8591in;height:2.7799in" />

verify the firewall rules are updated:

firewall-cmd –list-all

You should see the following:

<img src="nfs_media/Pictures/100000010000040000000300422B38EB.png" style="width:5.398in;height:3.5083in" />

**BASIC INSTALLATION SETUP CLIENT SIDE**

1\. Update computer packages List and Install the nfs package:

-   dnf update -y
-   dnf install nfs-utils -y

<img src="nfs_media/Pictures/1000000100000AB0000007207D01524C.png" style="width:6.3382in;height:2.8in" />

2\. Create a mount point for a shared directory

-   **mkdir -pv /mnt/remote\_share**

<img src="nfs_media/Pictures/1000000100000AB000000720E9A6BBFA.png" style="width:5.8693in;height:2.4555in" />

3\. Mount the shared_directory using fstab file: **vim /etc/fstab**

<img src="nfs_media/Pictures/1000000100000AB000000720DCA1A22E.png" style="width:6.9252in;height:2.4992in" />

4\. start the nfs service: systemctl start nfs-utils.service

5\. Mount it persistently and confirm if the shared_directory is
mounted.:

-   mount -av

-   ls /mnt/directoty_name

<img src="nfs_media/Pictures/1000000100000AB000000720B7FA4A8B.png" style="width:6.4272in;height:2.8453in" />

=== END
