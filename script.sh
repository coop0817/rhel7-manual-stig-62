#!/bin/bash

# The following script is designed to assist the System Administrator in
# checking the 62 manual STIG controls not covered by the Benchmark STIG
# automated method.

# This script has been written specifically to address these controls
# within the known desired setup, configuration and known requirements of
# the proprietary destination enclaved Information Systems (IS).

# This script was written based upon the current STIG released for
# RHEL 7 which is V2R6 realease on 24 JAN 2020.

# Author: Colby French, April 2020

START=$SECONDS
HOST=`hostname -s`
DATE=`date +%Y%m%d.%H%M%S`
UDATE=`date`
DEST=$HOME
FILE=$DEST/STIG_Report-$HOST"-"$DATE.txt
OSREV=`rpm -q centos-release`

echo "
#############################################################################################

This Health Check and Manual STIG Report for" $HOST "was run on" $UDATE >> $FILE

echo "
Operating system type and version are:" $OSREV >> $FILE

echo "
#############################################################################################
#
# This is the beginning of the system health check

---------------------------------------------------------------------------------------------

Most recent patch information - last 10 patches installed:
" >> $FILE
rpm -qa --last | head -10 >> $FILE
echo "
---------------------------------------------------------------------------------------------


Current rev of the installed Symantec Antivirus Definitions (if exists):
" >> $FILE
/opt/Symantec/symantec_antivirus/sav info -d &>> $FILE

echo "
---------------------------------------------------------------------------------------------

Current rev of the installed ClamAV Software and Definitions (if exists):
" >> $FILE
/bin/clamscan --version &>> $FILE

echo "
---------------------------------------------------------------------------------------------

Disk usage information (verify that disks are not full or close to full):
" >> $FILE
df -lh >> $FILE

echo "
---------------------------------------------------------------------------------------------

Disk encryption status (if TYPE of any of the physical volumes does not contain "crypt" then it is unencrypted:
" >> $FILE
lsblk -f >> $FILE

echo "
---------------------------------------------------------------------------------------------

Root account details (check for password expiration): " >> $FILE
chage -l root >> $FILE

echo "
---------------------------------------------------------------------------------------------

Local user account details (check for password expiration): " >> $FILE
cat /etc/passwd | grep /home | awk -F: '{print$1}' | xargs -n 1 -I {} bash -c " echo -e '\n{}' ; chage -l {}" >> $FILE

echo "
---------------------------------------------------------------------------------------------

Failed login attempts:
" >> $FILE
lastb &>> $FILE

echo "
---------------------------------------------------------------------------------------------

Currently logged in users:
" >> $FILE
who >> $FILE

echo "
---------------------------------------------------------------------------------------------

System uptime:
" >> $FILE
uptime >> $FILE
uptime -p >> $FILE

echo "
---------------------------------------------------------------------------------------------

#############################################################################################
# This is the beginning of the 62 manual STIG controls check.
# The Rule Title, STIG ID, Rule ID, Vul ID, and Severity will be listed
# in the output file prior to the STIG check outputs and remediation details.
#
# THERE SHOULD BE DATA BELOW EVERY ***COMMAND OUTPUT ON (systemname)***
# BE SURE TO REVIEW THE NOTES AND POTENTIAL FINDING REMARKS TO DETERMINE ACTION." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must be configured so that the file permissions, ownership, and group membership of system files and commands match the vendor values.

STIG ID: RHEL-07-010010  Rule ID: SV-86473r4_rule  Vul ID: V-71849
Severity: CAT I

ACTION: Verify the file permissions, ownership, and group membership of system files and commands match the vendor values.

COMMAND: Check the default file permissions, ownership, and group membership of system files and commands with the following command:
# for i in \`rpm -Va | egrep -i '^\.[M|U|G|.]{8}' | cut -d \" \" -f4,5\`;do for j in \`rpm -qf \$i\`;do rpm -ql \$j --dump | cut -d \" \" -f1,5,6,7 | grep \$i;done;done

EXAMPLE OUTPUT:
/var/log/gdm 040755 root root
/etc/audisp/audisp-remote.conf 0100640 root root
/usr/bin/passwd 0104755 root root

***COMMAND OUTPUT on $HOST***:" >> $FILE
for i in `rpm -Va | egrep -i '^\.[M|U|G|.]{8}' | cut -d " " -f4,5`;do for j in `rpm -qf $i`;do rpm -ql $j --dump | cut -d " " -f1,5,6,7 | grep $i;done;done &>> $FILE

echo "
POTENTIAL FINDING:
If the file is more permissive than the default permissions, this is a finding.

If the file is not owned by the default owner and is not documented with the Information System Security Officer (ISSO), this is a finding.

If the file is not a member of the default group and is not documented with the Information System Security Officer (ISSO), this is a finding.

If the file is more permissive than the default permissions, this is a finding.

If the file is not owned by the default owner and is not documented with the Information System Security Officer (ISSO), this is a finding.

If the file is not a member of the default group and is not documented with the Information System Security Officer (ISSO), this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must be configured to lock accounts for a minimum of 15 minutes after three unsuccessful logon attempts within a 15-minute timeframe.

STIG ID: RHEL-07-010320  Rule ID: SV-86567r5_rule  Vul ID: V-71943
Severity: CAT II

ACTION: Check that the system locks an account for a minimum of 15 minutes after three unsuccessful logon attempts within a period of 15 minutes with the following command:

CHECK #1

COMMAND:
# grep pam_faillock.so /etc/pam.d/password-auth

EXAMPLE OUTPUT:
auth required pam_faillock.so preauth silent audit deny=3 even_deny_root fail_interval=900 unlock_time=900
auth [default=die] pam_faillock.so authfail audit deny=3 even_deny_root fail_interval=900 unlock_time=900
account required pam_faillock.so

***COMMAND OUTPUT on $HOST***:" >> $FILE
grep pam_faillock.so /etc/pam.d/password-auth >> $FILE || echo No ouput was received from the above command! >> $FILE

echo "
POTENTIAL FINDING:
If the "deny" parameter is set to "0" or a value less than "3" on both "auth" lines with the "pam_faillock.so" module, or is missing from these lines, this is a finding.

If the "even_deny_root" parameter is not set on both "auth" lines with the "pam_faillock.so" module, or is missing from these lines, this is a finding.

If the "fail_interval" parameter is set to "0" or is set to a value less than "900" on both "auth" lines with the "pam_faillock.so" module, or is missing from these lines, this is a finding.

If the "unlock_time" parameter is not set to "0", "never", or is set to a value less than "900" on both "auth" lines with the "pam_faillock.so" module, or is missing from these lines, this is a finding.

Note: The maximum configurable value for "unlock_time" is "604800".

If any line referencing the "pam_faillock.so" module is commented out, this is a finding.

CHECK #2

COMMAND:
# grep pam_faillock.so /etc/pam.d/system-auth

EXAMPLE OUTPUT:
auth required pam_faillock.so preauth silent audit deny=3 even_deny_root fail_interval=900 unlock_time=900
auth [default=die] pam_faillock.so authfail audit deny=3 even_deny_root fail_interval=900 unlock_time=900
account required pam_faillock.so

***COMMAND OUTPUT on $HOST***:" >> $FILE
grep pam_faillock.so /etc/pam.d/system-auth >> $FILE || echo No ouput was received from the above command! >> $FILE

echo "
POTENTIAL FINDING:
If the "deny" parameter is set to "0" or a value less than "3" on both "auth" lines with the "pam_faillock.so" module, or is missing from these lines, this is a finding.

If the "even_deny_root" parameter is not set on both "auth" lines with the "pam_faillock.so" module, or is missing from these lines, this is a finding.

If the "fail_interval" parameter is set to "0" or is set to a value less than "900" on both "auth" lines with the "pam_faillock.so" module, or is missing from these lines, this is a finding.

If the "unlock_time" parameter is not set to "0", "never", or is set to a value less than "900" on both "auth" lines with the "pam_faillock.so" module or is missing from these lines, this is a finding.

Note: The maximum configurable value for "unlock_time" is "604800".
If any line referencing the "pam_faillock.so" module is commented out, this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must lock the associated account after three unsuccessful root logon attempts are made within a 15-minute period.

STIG ID: RHEL-07-010330  Rule ID: SV-86569r4_rule  Vul ID: V-71945
Severity: CAT II

ACTION: Verify the operating system automatically locks the root account until it is released by an administrator when three unsuccessful logon attempts in 15 minutes are made.

CHECK #1

COMMAND:
# grep pam_faillock.so /etc/pam.d/password-auth

EXAMPLE OUTPUT:
auth required pam_faillock.so preauth silent audit deny=3 even_deny_root fail_interval=900 unlock_time=900
auth [default=die] pam_faillock.so authfail audit deny=3 even_deny_root fail_interval=900 unlock_time=900
account required pam_faillock.so

***COMMAND OUTPUT on $HOST***:" >> $FILE
grep pam_faillock.so /etc/pam.d/password-auth >> $FILE || echo No ouput was received from the above command! >> $FILE

echo "
POTENTIAL FINDING:
If the "even_deny_root" setting is not defined on both lines with the "pam_faillock.so" module, is commented out, or is missing from a line, this is a finding.

CHECK #2

COMMAND:
# grep pam_faillock.so /etc/pam.d/system-auth

EXAMPLE OUTPUT:
auth required pam_faillock.so preauth silent audit deny=3 even_deny_root fail_interval=900 unlock_time=900
auth [default=die] pam_faillock.so authfail audit deny=3 even_deny_root fail_interval=900 unlock_time=900
account required pam_faillock.so

***COMMAND OUTPUT on $HOST***:" >> $FILE
grep pam_faillock.so /etc/pam.d/system-auth >> $FILE || echo No ouput was received from the above command! >> $FILE

echo "
POTENTIAL FINDING:
If the "even_deny_root" setting is not defined on both lines with the "pam_faillock.so" module, is commented out, or is missing from a line, this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must uniquely identify and must authenticate organizational users (or processes acting on behalf of organizational users) using multifactor authentication.

STIG ID: RHEL-07-010500  Rule ID: SV-86589r2_rule  Vul ID: V-71965
Severity: CAT II

ACTION: Verify the operating system requires multifactor authentication to uniquely identify organizational users using multifactor authentication.

COMMAND: Check to see if smartcard authentication is enforced on the system:
# authconfig --test | grep "pam_pkcs11 is enabled"

***COMMAND OUTPUT on $HOST***:" >> $FILE
authconfig --test | grep "pam_pkcs11 is enabled" >> $FILE || echo No ouput was received from the above command! >> $FILE

echo "
POTENTIAL FINDING:
If no results are returned, this is a finding.

COMMAND:
# authconfig --test | grep "smartcard removal action"

***COMMAND OUTPUT on $HOST***:" >> $FILE
authconfig --test | grep "smartcard removal action" >> $FILE

echo "
POTENTIAL FINDING:
If "smartcard removal action" is blank, this is a finding.

COMMAND:
# authconfig --test | grep "smartcard module"

***COMMAND OUTPUT on $HOST***:" >> $FILE
authconfig --test | grep "smartcard module" >> $FILE

echo "
POTENTIAL FINDING:
If "smartcard module" is blank, this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must prevent non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.

STIG ID: RHEL-07-020020  Rule ID: SV-86595r2_rule  Vul ID: V-71971
Severity: CAT II

ACTION: If an HBSS or HIPS is active on the system, this is Not Applicable.

Verify the operating system prevents non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.

Get a list of authorized users (other than System Administrator and guest accounts) for the system.

COMMAND: Check the list against the system by using the following command:
# semanage login -l | more

EXAMPLE OUTPUT:
Login Name SELinux User MLS/MCS Range Service
__default__ user_u s0-s0:c0.c1023 *
root unconfined_u s0-s0:c0.c1023 *
system_u system_u s0-s0:c0.c1023 *
joe staff_u s0-s0:c0.c1023 *

***COMMAND OUTPUT on $HOST***:" >> $FILE
semanage login -l | more >> $FILE

echo "
POTENTIAL FINDING:
All administrators must be mapped to the "sysadm_u" or "staff_u" users role.

All authorized non-administrative users must be mapped to the "user_u" role.

If they are not mapped in this way, this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must be configured so that designated personnel are notified if baseline configurations are changed in an unauthorized manner.

STIG ID: RHEL-07-020040  Rule ID: SV-86599r2_rule  Vul ID: V-71975
Severity: CAT II

ACTION: Verify the operating system notifies designated personnel if baseline configurations are changed in an unauthorized manner.

Note: A file integrity tool other than Advanced Intrusion Detection Environment (AIDE) may be used, but the tool must be executed and notify specified individuals via email or an alert.

COMMAND: Check to see if AIDE is installed on the system with the following command:
# yum list installed aide

***COMMAND OUTPUT on $HOST***:" >> $FILE
yum list installed aide &>> $FILE

echo "
If AIDE is not installed, ask the SA how file integrity checks are performed on the system.

ACTION: Check for the presence of a cron job running routinely on the system that executes AIDE to scan for changes to the system baseline. The commands used in the example will use a daily occurrence.

COMMAND: Check the cron directories for a "crontab" script file controlling the execution of the file integrity application. For example, if AIDE is installed on the system, use the following command:
# ls -al /etc/cron.* | grep aide

EXAMPLE OUTPUT:
-rwxr-xr-x 1 root root 32 Jul 1 2011 aide

***COMMAND OUTPUT on $HOST***:" >> $FILE
ls -al /etc/cron.* | grep aide >> $FILE || echo No ouput was received from the above command! >> $FILE

echo "
COMMAND:
# grep aide /etc/crontab /var/spool/cron/root

EXAMPLE OUTPUT:
/etc/crontab: 30 04 * * * /root/aide
/var/spool/cron/root: 30 04 * * * /root/aide

***COMMAND OUTPUT on $HOST***:" >> $FILE
grep aide /etc/crontab /var/spool/cron/root 2>/dev/null >> $FILE || echo No ouput was received from the above command! >> $FILE

echo "
ACTION: AIDE does not have a configuration that will send a notification, so the cron job uses the mail application on the system to email the results of the file integrity run as in the following example:

COMMAND:
# more /etc/cron.daily/aide

EXAMPLE OUTPUT:
#!/bin/bash
/usr/sbin/aide --check | /bin/mail -s "$HOSTNAME - Daily aide integrity check run" root@sysname.mil

***COMMAND OUTPUT on $HOST***:" >> $FILE
cat /etc/cron.daily/aide 2>/dev/null >> $FILE || echo No ouput was received from the above command! >> $FILE

echo "
POTENTIAL FINDING:
If the file integrity application does not notify designated personnel of changes, this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must enable SELinux.

STIG ID: RHEL-07-020210  Rule ID: SV-86613r3_rule  Vul ID: V-71989
Severity: CAT I

Note: If an HBSS or HIPS is active on the system, this is Not Applicable.

ACTION: Verify the operating system verifies correct operation of all security functions.

COMMAND: Check if "SELinux" is active and in "Enforcing" mode with the following command:
# getenforce

EXAMPLE OUTPUT:
Enforcing

***COMMAND OUTPUT on $HOST***:" >> $FILE
getenforce >> $FILE

echo "
POTENTIAL FINDING:
If "SELinux" is not active and not in "Enforcing" mode, this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must enable the SELinux targeted policy.

STIG ID: RHEL-07-020220  Rule ID: SV-86615r5_rule  Vul ID: V-71991
Severity: CAT I

Note: If an HBSS or HIPS is active on the system, this is Not Applicable.

ACTION: Verify the operating system verifies correct operation of all security functions.

COMMAND: Check if "SELinux" is active and is enforcing the targeted policy with the following command:
# sestatus

EXAMPLE OUTPUT:
SELinux status: enabled
SELinuxfs mount: /selinux
SELinux root directory: /etc/selinux
Loaded policy name: targeted
Current mode: enforcing
Mode from config file: enforcing
Policy MLS status: enabled
Policy deny_unknown status: allowed
Max kernel policy version: 28

***COMMAND OUTPUT on $HOST***:" >> $FILE
sestatus >> $FILE

echo "
POTENTIAL FINDING:
If the "Loaded policy name" is not set to "targeted", this is a finding.

COMMAND: Verify that the /etc/selinux/config file is configured to the "SELINUXTYPE" to "targeted":
# grep -i "selinuxtype" /etc/selinux/config | grep -v '^#'

EXAMPLE OUTPUT:
SELINUXTYPE = targeted

***COMMAND OUTPUT on $HOST***:" >> $FILE
grep -i "selinuxtype" /etc/selinux/config | grep -v '^#' >> $FILE || echo No ouput was received from the above command! >> $FILE

echo "
POTENTIAL FINDING:
If no results are returned or "SELINUXTYPE" is not set to "targeted", this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must be configured so that the x86 Ctrl-Alt-Delete key sequence is disabled on the command line.

STIG ID: RHEL-07-020230  Rule ID: SV-86617r5_rule  Vul ID: V-71993
Severity: CAT I

ACTION: Verify the operating system is not configured to reboot the system when Ctrl-Alt-Delete is pressed.

COMMAND: Check that the ctrl-alt-del.target is masked and not active with the following command:
# systemctl status ctrl-alt-del.target

EXAMPLE OUTPUT:
ctrl-alt-del.target
Loaded: masked (/dev/null; bad)
Active: inactive (dead)

***COMMAND OUTPUT on $HOST***:" >> $FILE
systemctl status ctrl-alt-del.target >> $FILE

echo "
POTENTIAL FINDING:
If the ctrl-alt-del.target is not masked, this is a finding.

If the ctrl-alt-del.target is active, this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system security patches and updates must be installed and up to date.

STIG ID: RHEL-07-020260  Rule ID: SV-86623r4_rule  Vul ID: V-71999
Severity: CAT II

ACTION: Verify the operating system security patches and updates are installed and up to date. Updates are required to be applied with a frequency determined by the site or Program Management Office (PMO).

Obtain the list of available package security updates from Red Hat. The URL for updates is https://rhn.redhat.com/errata/. It is important to note that updates provided by Red Hat may not be present on the system if the underlying packages are not installed.

COMMAND: Check that the available package security updates have been installed on the system with the following command:
# yum history list

EXAMPLE OUTPUT:
Loaded plugins: langpacks, product-id, subscription-manager
ID     | Command line             | Date and time    | Action(s)      | Altered
-------------------------------------------------------------------------------
    70 | install aide             | 2016-05-05 10:58 | Install        |    1
    69 | update -y                | 2016-05-04 14:34 | Update         |   18 EE
    68 | install vlc              | 2016-04-21 17:12 | Install        |   21
    67 | update -y                | 2016-04-21 17:04 | Update         |    7 EE
    66 | update -y                | 2016-04-15 16:47 | E, I, U        |   84 EE

***COMMAND OUTPUT on $HOST***:" >> $FILE
yum history list 2>/dev/null >> $FILE

echo "
POTENTIAL FINDING:
If package updates have not been performed on the system within the timeframe that the site/program documentation requires, this is a finding.

Typical update frequency may be overridden by Information Assurance Vulnerability Alert (IAVA) notifications from CYBERCOM.

If the operating system is in non-compliance with the Information Assurance Vulnerability Management (IAVM) process, this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must not have unnecessary accounts.

STIG ID: RHEL-07-020270  Rule ID: SV-86625r2_rule  Vul ID: V-72001
Severity: CAT II

ACTION: Verify all accounts on the system are assigned to an active system, application, or user account.

Obtain the list of authorized system accounts from the Information System Security Officer (ISSO).

COMMAND: Check the system accounts on the system with the following command:
# more /etc/passwd

EXAMPLE OUTPUT:
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
games:x:12:100:games:/usr/games:/sbin/nologin
gopher:x:13:30:gopher:/var/gopher:/sbin/nologin

Note:Accounts such as "games" and "gopher" are not authorized accounts as they do not support authorized system functions.

***COMMAND OUTPUT on $HOST***:" >> $FILE
cat /etc/passwd >> $FILE

echo "
POTENTIAL FINDING:
If the accounts on the system do not match the provided documentation, or accounts that do not support an authorized system function are present, this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must be configured so that all files and directories have a valid owner.

STIG ID: RHEL-07-020320  Rule ID: SV-86631r3_rule  Vul ID: V-72007
Severity: CAT II

ACTION: Verify all files and directories on the system have a valid owner.

COMMAND: Check the owner of all files and directories with the following command:
Note: The value after -fstype must be replaced with the filesystem type. XFS is used as an example.
# find / -fstype xfs -nouser (for the purposes of this automated output report "fstype" option was removed)

***COMMAND OUTPUT on $HOST***:" >> $FILE
find / -nouser 2>/dev/null >> $FILE || echo No ouput was received from the above command! >> $FILE

echo "
POTENTIAL FINDING:
If any files on the system do not have an assigned owner, this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must be configured so that all files and directories have a valid group owner.

STIG ID: RHEL-07-020330  Rule ID: SV-86633r3_rule  Vul ID: V-72009
Severity: CAT II

ACTION: Verify all files and directories on the system have a valid group.

COMMAND: Check the owner of all files and directories with the following command:
Note: The value after -fstype must be replaced with the filesystem type. XFS is used as an example.
# find / -fstype xfs -nogroup (for the purposes of this automated output report "fstype" option was removed)

***COMMAND OUTPUT on $HOST***:" >> $FILE
find / -nogroup 2>/dev/null >> $FILE || echo No ouput was received from the above command! >> $FILE

echo "
POTENTIAL FINDING:
If any files on the system do not have an assigned group, this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must be configured so that all local interactive user home directories have mode 0750 or less permissive.

STIG ID: RHEL-07-020630  Rule ID: SV-86641r3_rule  Vul ID: V-72017
Severity: CAT II

ACTION: Verify the assigned home directory of all local interactive users has a mode of "0750" or less permissive.

COMMAND: Check the home directory assignment for all non-privileged users on the system with the following command:
Note: This may miss interactive users that have been assigned a privileged User Identifier (UID). Evidence of interactive use may be obtained from a number of log files containing system logon information.
# ls -ld \$(egrep ':[0-9]{4}' /etc/passwd | cut -d: -f6)

EXAMPLE OUTPUT:
-rwxr-x--- 1 smithj users  18 Mar  5 17:06 /home/smithj

***COMMAND OUTPUT on $HOST***:" >> $FILE
ls -ld $(egrep ':[0-9]{4}' /etc/passwd | cut -d: -f6) >> $FILE

echo "
POTENTIAL FINDING:
If home directories referenced in "/etc/passwd" do not have a mode of "0750" or less permissive, this is a finding" >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must be configured so that all local interactive user home directories are owned by their respective users.

STIG ID: RHEL-07-020640  Rule ID: SV-86643r5_rule  Vul ID: V-72019
Severity: CAT II

ACTION: Verify the assigned home directory of all local interactive users on the system exists.

COMMAND: Check the home directory assignment for all local interactive users on the system with the following command:
# ls -ld \$(egrep ':[0-9]{4}' /etc/passwd | cut -d: -f6)

EXAMPLE OUTPUT:
-rwxr-x--- 1 smithj users 18 Mar 5 17:06 /home/smithj

***COMMAND OUTPUT on $HOST***:" >> $FILE
ls -ld $(egrep ':[0-9]{4}' /etc/passwd | cut -d: -f6) >> $FILE

echo "
POTENTIAL FINDING:
If any home directories referenced in "/etc/passwd" are not owned by the interactive user, this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must be configured so that all local interactive user home directories are group-owned by the home directory owners primary group.

STIG ID: RHEL-07-020650  Rule ID: SV-86645r5_rule  Vul ID: V-72021
Severity: CAT II

ACTION: Verify the assigned home directory of all local interactive users is group-owned by that user's primary GID.

COMMAND: Check the home directory assignment for all local interactive users on the system with the following command:
# ls -ld \$(egrep ':[0-9]{4}' /etc/passwd | cut -d: -f6)

EXAMPLE OUTPUT:
-rwxr-x--- 1 smithj users 18 Mar 5 17:06 /home/smithj

***COMMAND OUTPUT on $HOST***:" >> $FILE
ls -ld $(egrep ':[0-9]{4}' /etc/passwd | cut -d: -f6) >> $FILE

echo "
COMMAND: Check the user's primary group with the following command:
# grep users /etc/group
NOTE: (showing all groups for the purposes of the report)

EXAMPLE OUTPUT:
users:x:250:smithj,jonesj,jacksons

***COMMAND OUTPUT on $HOST***:" >> $FILE
cat /etc/group >> $FILE

echo "
POTENTIAL FINDING:
If the user home directory referenced in "/etc/passwd" is not group-owned by that user's primary GID, this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must be configured so that all files and directories contained in local interactive user home directories are owned by the owner of the home directory.

STIG ID: RHEL-07-020660  Rule ID: SV-86647r2_rule  Vul ID: V-72023
Severity: CAT II

ACTION: Verify all files and directories in a local interactive user's home directory are owned by the user.

COMMAND: Check the owner of all files and directories in a local interactive user's home directory with the following command:
Note: The example will be for the user "smithj", who has a home directory of "/home/smithj".
# ls -lLR /home/smithj
NOTE: (for the purposes of this report, a list of commands will inserted into the report to be run and manually verified post report creation)

EXAMPLE OUTPUT:
-rw-r--r-- 1 smithj smithj  18 Mar  5 17:06 file1
-rw-r--r-- 1 smithj smithj 193 Mar  5 17:06 file2
-rw-r--r-- 1 smithj smithj 231 Mar  5 17:06 file3

***COMMAND OUTPUT on $HOST***:" >> $FILE
ls -1 /home | while read line; do echo ls -lLR /home/$line; done >> $FILE

echo "
POTENTIAL FINDING:
If any files are found with an owner different than the home directory user, this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must be configured so that all files and directories contained in local interactive user home directories are group-owned by a group of which the home directory owner is a member.

STIG ID: RHEL-07-020670  Rule ID: SV-86649r2_rule  Vul ID: V-72025
Severity: CAT II

ACTION: Verify all files and directories in a local interactive user home directory are group-owned by a group the user is a member of.

COMMAND: Check the group owner of all files and directories in a local interactive user's home directory with the following command:
Note: The example will be for the user "smithj", who has a home directory of "/home/smithj".
# ls -lLR /<home directory>/<users home directory>/
NOTE: (for the purposes of this report, a list of commands will inserted into the report to be run and manually verified post report creation)

EXAMPLE OUTPUT:
-rw-r--r-- 1 smithj smithj  18 Mar  5 17:06 file1
-rw-r--r-- 1 smithj smithj 193 Mar  5 17:06 file2
-rw-r--r-- 1 smithj smithj 231 Mar  5 17:06 file3

***COMMAND OUTPUT on $HOST***:" >> $FILE
ls -1 /home | while read line; do echo ls -lLR /home/$line; done >> $FILE

echo "
POTENTIAL FINDING:
If any files are found with an owner different than the group home directory user, check to see if the user is a member of that group with the following command:

COMMAND:
# grep smithj /etc/group

EXAMPLE OUTPUT:
sa:x:100:juan,shelley,bob,smithj
smithj:x:521:smithj

***COMMAND OUTPUT on $HOST***:" >> $FILE
echo "MANUALLY VERIFY THE ABOVE COMMAND EXAMPLE WITH THE DIFFERING GROUP DISCOVERED IN THE 'ls -lLR /<home directory>/<users home directory>/' COMMAND THAT WAS RUN PRIOR" >> $FILE

echo "
POTENTIAL FINDING:
If the user is not a member of a group that group owns file(s) in a local interactive user's home directory, this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must be configured so that all files and directories contained in local interactive user home directories have a mode of 0750 or less permissive.

STIG ID: RHEL-07-020680  Rule ID: SV-86651r2_rule  Vul ID: V-72027
Severity: CAT II

ACTION: Verify all files and directories contained in a local interactive user home directory, excluding local initialization files, have a mode of "0750".

COMMAND: Check the mode of all non-initialization files in a local interactive user home directory with the following command:
Files that begin with a "." are excluded from this requirement.
Note: The example will be for the user "smithj", who has a home directory of "/home/smithj".
# ls -lLR /home/smithj
NOTE: (For the purposes of this report, echoing commands to be run manually post report finalization)
NOTE: (The command will list all files/directories that have permissions greater than 0750)

EXAMPLE OUTPUT:
-rwxr-x--- 1 smithj smithj  18 Mar  5 17:06 file1
-rwxr----- 1 smithj smithj 193 Mar  5 17:06 file2
-rw-r-x--- 1 smithj smithj 231 Mar  5 17:06 file3

***COMMAND OUTPUT on $HOST***:" >> $FILE
echo "find /home/ -perm -0751 -o -perm -0760 -o -perm -1750 -o -perm -2750 -o -perm -4750 " >> $FILE

echo "
POTENTIAL FINDING:
If any files are found with a mode more permissive than "0750", this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must be configured so that all local initialization files for interactive users are owned by the home directory user or root.

STIG ID: RHEL-07-020690  Rule ID: SV-86653r3_rule  Vul ID: V-72029
Severity: CAT II

ACTION: Verify the local initialization files of all local interactive users are group-owned by that user's primary Group Identifier (GID).

COMMAND: Check the home directory assignment for all non-privileged users on the system with the following command:
Note: The example will be for the smithj user, who has a home directory of "/home/smithj" and a primary group of "users".
# cut -d: -f 1,4,6 /etc/passwd | egrep ":[1-4][0-9]{3}"

EXAMPLE OUTPUT:
smithj:1000:/home/smithj

***COMMAND OUTPUT on $HOST***:" >> $FILE
cut -d: -f 1,4,6 /etc/passwd | egrep ":[1-4][0-9]{3}" >> $FILE

echo "
COMMAND:
# grep 1000 /etc/group
NOTE: This may miss interactive users that have been assigned a privileged User Identifier (UID). Evidence of interactive use may be obtained from a number of log files containing system logon information.
NOTE: This command is modified to take the output from the first command and search for all found GIDs in /etc/group.

EXAMPLE OUTPUT:
users:x:1000:smithj,jonesj,jacksons

***COMMAND OUTPUT on $HOST***:" >> $FILE
cut -d: -f 4 /etc/passwd | egrep "[1-4][0-9]{3}" | while read line; do grep $line /etc/group; done >> $FILE

echo "
COMMAND: Check the group owner of all local interactive user's initialization files with the following command:
# ls -al /home/smithj/.[^.]* | more
NOTE: (For the purposes of this report, echoing commands to be run manually post report finalization)
NOTE: The above script does not perform the requested action. Modified as can be seen in the echo'd command below.

EXAMPLE OUTPUT:
-rwxr-xr-x 1 smithj users 896 Mar 10 2011 .profile
-rwxr-xr-x 1 smithj users 497 Jan 6 2007 .login
-rwxr-xr-x 1 smithj users 886 Jan 6 2007 .something

***COMMAND OUTPUT on $HOST***:" >> $FILE
echo "cut -d: -f 1,4,6 /etc/passwd | egrep ":[1-4][0-9]{3}" | cut -d: -f 3 | while read line; do find \$line/ -type f -name ".*" -exec ls -la {} \;" >> $FILE

echo "
POTENTIAL FINDING:
If all local interactive user's initialization files are not group-owned by that user's primary GID, this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must be configured so that all local initialization files for local interactive users are be group-owned by the users primary group or root.

STIG ID: RHEL-07-020700  Rule ID: SV-86655r4_rule  Vul ID: V-72031
Severity: CAT II

NOTE: The actions listed below are identical to the actions listed in the STIG ID: RHEL-07-020690. These are separate control requirements and the fix text is different. The only difference in the description is that this STIG identifies interactive users as "local".

ACTION: Verify the local initialization files of all local interactive users are group-owned by that user's primary Group Identifier (GID).

COMMAND: Check the home directory assignment for all non-privileged users on the system with the following command:
Note: The example will be for the smithj user, who has a home directory of "/home/smithj" and a primary group of "users".
# cut -d: -f 1,4,6 /etc/passwd | egrep ":[1-4][0-9]{3}"

EXAMPLE OUTPUT:
smithj:1000:/home/smithj

***COMMAND OUTPUT on $HOST***:" >> $FILE
cut -d: -f 1,4,6 /etc/passwd | egrep ":[1-4][0-9]{3}" >> $FILE

echo "
COMMAND:
# grep 1000 /etc/group
NOTE: This may miss interactive users that have been assigned a privileged User Identifier (UID). Evidence of interactive use may be obtained from a number of log files containing system logon information.
NOTE: This command is modified to take the output from the first command and search for all found GIDs in /etc/group.

EXAMPLE OUTPUT:
users:x:1000:smithj,jonesj,jacksons
***COMMAND OUTPUT on $HOST***:" >> $FILE
cut -d: -f 4 /etc/passwd | egrep "[1-4][0-9]{3}" | while read line; do grep $line /etc/group; done >> $FILE

echo "
COMMAND: Check the group owner of all local interactive user's initialization files with the following command:
# ls -al /home/smithj/.[^.]* | more
NOTE: (For the purposes of this report, echoing commands to be run manually post report finalization)
NOTE: The above script does not perform the requested action. Modified as can be seen in the echo'd command below.

EXAMPLE OUTPUT:
-rwxr-xr-x 1 smithj users 896 Mar 10 2011 .profile
-rwxr-xr-x 1 smithj users 497 Jan 6 2007 .login
-rwxr-xr-x 1 smithj users 886 Jan 6 2007 .something

***COMMAND OUTPUT on $HOST***:" >> $FILE
echo "cut -d: -f 1,4,6 /etc/passwd | egrep ":[1-4][0-9]{3}" | cut -d: -f 3 | while read line; do find \$line/ -type f -name ".*" -exec ls -la {} \;" >> $FILE

echo "
POTENTIAL FINDING:
If all local interactive user's initialization files are not group-owned by that user's primary GID, this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must be configured so that all local initialization files have mode 0740 or less permissive.

STIG ID: RHEL-07-020710  Rule ID: SV-86657r3_rule  Vul ID: V-72033
Severity: CAT II

ACTION: Verify that all local initialization files have a mode of "0740" or less permissive.

COMMAND: Check the mode on all local initialization files with the following command:
Note: The example will be for the "smithj" user, who has a home directory of "/home/smithj".
# ls -al /home/smithj/.[^.]* | more
NOTE: This command is modified to query the initialization files of all /home directories.
NOTE: As this output can be very lengthy, for the purposes of this report the command will be echo'd to the report to be run manually.
NOTE: The above script does not perform the requested action. Modified as can be seen in the echo'd command below. This is the same command as in the last control with the addition of a test for permissions greater than 740 to limit findings.

EXAMPLE OUTPUT:
-rwxr----- 1 smithj users 896 Mar 10 2011 .profile
-rwxr----- 1 smithj users 497 Jan 6 2007 .login
-rwxr----- 1 smithj users 886 Jan 6 2007 .something

***COMMAND OUTPUT on $HOST***:" >> $FILE
echo "cut -d: -f 1,4,6 /etc/passwd | egrep ":[1-4][0-9]{3}" | cut -d: -f 3 | while read line; do find \$line/ -type f -name ".*" -perm -0740 -exec ls -la {} \;" >> $FILE

echo "
POTENTIAL FINDING:
If any local initialization files have a mode more permissive than "0740", this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must be configured so that all local interactive user initialization files executable search paths contain only paths that resolve to the users home directory.

STIG ID: RHEL-07-020720  Rule ID: SV-86659r4_rule  Vul ID: V-72035
Severity: CAT II

ACTION: Verify that all local interactive user initialization files' executable search path statements do not contain statements that will reference a working directory other than the users' home directory.

COMMAND: Check the executable search path statement for all local interactive user initialization files in the users' home directory with the following commands:
Note: The example will be for the smithj user, which has a home directory of "/home/smithj".
NOTE: The command run for the purposes of this report is modified from this command to search all home directories for this string.
# grep -i path /home/smithj/.*

EXAMPLE OUTPUT:
/home/smithj/.bash_profile:PATH=$PATH:$HOME/.local/bin:$HOME/bin
/home/smithj/.bash_profile:export PATH

***COMMAND OUTPUT on $HOST***:" >> $FILE
cut -d: -f 1,4,6 /etc/passwd | egrep ":[1-4][0-9]{3}" | cut -d: -f 3 | while read line; do grep -i path $line/.*; done 2> /dev/null >> $FILE

echo "
POTENTIAL FINDING:
If any local interactive user initialization files have executable search path statements that include directories outside of their home directory, this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must be configured so that local initialization files do not execute world-writable programs.

STIG ID: RHEL-07-020730  Rule ID: SV-86661r2_rule  Vul ID: V-72037
Severity: CAT II

ACTION: Verify that local initialization files do not execute world-writable programs.

COMMAND: Check the system for world-writable files with the following command:
# find / -xdev -perm -002 -type f -exec ls -ld {} \; | more

***COMMAND OUTPUT on $HOST***:" >> $FILE
find / -xdev -perm -002 -type f -exec ls -ld {} \; >> $FILE

echo "
COMMAND: For all files listed, check for their presence in the local initialization files with the following commands:
Note: The example will be for a system that is configured to create users' home directories in the "/home" directory.
# grep <file> /home/*/.*

***COMMAND OUTPUT on $HOST***:" >> $FILE
find / -xdev -perm -002 -type f | while read line; do grep $line /home/*/.*; done 2> /dev/null >> $FILE || echo No ouput was received from the above command! >> $FILE

echo "
POTENTIAL FINDING:
If any local initialization files are found to reference world-writable files, this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must be configured so that all system device files are correctly labeled to prevent unauthorized modification.

STIG ID: RHEL-07-020900  Rule ID: SV-86663r2_rule  Vul ID: V-72039
Severity: CAT II

ACTION: Verify that all system device files are correctly labeled to prevent unauthorized modification.

COMMAND: List all device files on the system that are incorrectly labeled with the following commands:
Note: Device files are normally found under "/dev", but applications may place device files in other directories and may necessitate a search of the entire system.
#find /dev -context *:device_t:* \( -type c -o -type b \) -printf "%p %Z\n"

***COMMAND OUTPUT on $HOST***:" >> $FILE
find /dev -context *:device_t:* \( -type c -o -type b \) -printf "%p %Z\n" 2> /dev/null >> $FILE || echo No ouput was received from the above command! >> $FILE

echo "
#find /dev -context *:unlabeled_t:* \( -type c -o -type b \) -printf "%p %Z\n"

***COMMAND OUTPUT on $HOST***:" >> $FILE
find /dev -context *:unlabeled_t:* \( -type c -o -type b \) -printf "%p %Z\n" 2> /dev/null >> $FILE || echo No ouput was received from the above command! >> $FILE

echo "
Note: There are device files, such as "/dev/vmci", that are used when the operating system is a host virtual machine. They will not be owned by a user on the system and require the "device_t" label to operate. These device files are not a finding.

POTENTIAL FINDING:
If there is output from either of these commands, other than already noted, this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must be configured so that file systems containing user home directories are mounted to prevent files with the setuid and setgid bit set from being executed.

STIG ID: RHEL-07-021000  Rule ID: SV-86665r4_rule  Vul ID: V-72041
Severity: CAT II

ACTION: Verify file systems that contain user home directories are mounted with the "nosuid" option.

COMMAND: Find the file system(s) that contain the user home directories with the following command:
Note: If a separate file system has not been created for the user home directories (user home directories are mounted under "/"), this is not a finding as the "nosuid" option cannot be used on the "/" system.
# cut -d: -f 1,3,6 /etc/passwd | egrep ":[1-4][0-9]{3}"

EXAMPLE OUTPUT:
smithj:1001:/home/smithj
thomasr:1002:/home/thomasr

***COMMAND OUTPUT on $HOST***:" >> $FILE
cut -d: -f 1,3,6 /etc/passwd | egrep ":[1-4][0-9]{3}" >> $FILE

echo "
COMMAND: Check the file systems that are mounted at boot time with the following command:
# more /etc/fstab

EXAMPLE OUTPUT:
UUID=a411dc99-f2a1-4c87-9e05-184977be8539 /home   ext4   rw,relatime,discard,data=ordered,nosuid 0 2

***COMMAND OUTPUT on $HOST***:" >> $FILE
cat /etc/fstab >> $FILE

echo "
POTENTIAL FINDING:
If a file system found in "/etc/fstab" refers to the user home directory file system and it does not have the "nosuid" option set, this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must prevent files with the setuid and setgid bit set from being executed on file systems that are used with removable media.

STIG ID: RHEL-07-021010  Rule ID: SV-86667r2_rule  Vul ID: V-72043
Severity: CAT II

ACTION: Verify file systems that are used for removable media are mounted with the "nosuid" option.

COMMAND: Check the file systems that are mounted at boot time with the following command:
# more /etc/fstab

EXAMPLE OUTPUT:
UUID=2bc871e4-e2a3-4f29-9ece-3be60c835222 /mnt/usbflash vfat noauto,owner,ro,nosuid 0 0

***COMMAND OUTPUT on $HOST***:" >> $FILE
cat /etc/fstab >> $FILE

echo "
POTENTIAL FINDING:
If a file system found in "/etc/fstab" refers to removable media and it does not have the "nosuid" option set, this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must set the umask value to 077 for all local interactive user accounts.
STIG ID: RHEL-07-021040  Rule ID: SV-86673r2_rule  Vul ID: V-72049
Severity: CAT II

ACTION: Verify that the default umask for all local interactive users is "077".
Identify the locations of all local interactive user home directories by looking at the "/etc/passwd" file.

COMMAND: Check all local interactive user initialization files for interactive users with the following command:
Note: The example is for a system that is configured to create users home directories in the "/home" directory.
# grep -i umask /home/*/.*

***COMMAND OUTPUT on $HOST***:" >> $FILE
grep -i umask /home/*/.* 2> /dev/null >> $FILE || echo No ouput was received from the above command! >> $FILE

echo "
POTENTIAL FINDING:
If any local interactive user initialization files are found to have a umask statement that has a value less restrictive than "077", this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must have cron logging implemented.

STIG ID: RHEL-07-021100  Rule ID: SV-86675r2_rule  Vul ID: V-72051
Severity: CAT II

ACTION: Verify that "rsyslog" is configured to log cron events.

COMMAND: Check the configuration of "/etc/rsyslog.conf" or "/etc/rsyslog.d/*.conf" files for the cron facility with the following command:
Note: If another logging package is used, substitute the utility configuration file for "/etc/rsyslog.conf" or "/etc/rsyslog.d/*.conf" files.
# grep cron /etc/rsyslog.conf  /etc/rsyslog.d/*.conf

EXAMPLE OUTPUT:
cron.* /var/log/cron.log

***COMMAND OUTPUT on $HOST***:" >> $FILE
grep cron /etc/rsyslog.conf  /etc/rsyslog.d/*.conf >> $FILE || echo No ouput was received from the above command! >> $FILE

echo "
If the command does not return a response, check for cron logging all facilities by inspecting the "/etc/rsyslog.conf" or "/etc/rsyslog.d/*.conf" files.
Look for the following entry:

EXAMPLE OUTPUT:
*.* /var/log/messages

***COMMAND OUTPUT on $HOST***:" >> $FILE
grep /var/log/messages /etc/rsyslog.conf  /etc/rsyslog.d/*.conf >> $FILE

echo "
POTENTIAL FINDING:
If "rsyslog" is not logging messages for the cron facility or all facilities, this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must disable Kernel core dumps unless needed.

STIG ID: RHEL-07-021300  Rule ID: SV-86681r2_rule  Vul ID: V-72057
Severity: CAT II

ACTION: Verify that kernel core dumps are disabled unless needed.

COMMAND: Check the status of the "kdump" service with the following command:
# systemctl status kdump.service

EXAMPLE OUTPUT:
kdump.service - Crash recovery kernel arming
   Loaded: loaded (/usr/lib/systemd/system/kdump.service; enabled)
   Active: active (exited) since Wed 2015-08-26 13:08:09 EDT; 43min ago
 Main PID: 1130 (code=exited, status=0/SUCCESS)
kernel arming.

***COMMAND OUTPUT on $HOST***:" >> $FILE
systemctl status kdump.service >> $FILE

echo "
If the "kdump" service is active, ask the System Administrator if the use of the service is required and documented with the Information System Security Officer (ISSO).

POTENTIAL FINDING:
If the service is active and is not documented, this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must be configured so that the file integrity tool is configured to verify Access Control Lists (ACLs).

STIG ID: RHEL-07-021600  Rule ID: SV-86693r3_rule  Vul ID: V-72069
Severity: CAT III

ACTION: Verify the file integrity tool is configured to verify ACLs.

COMMAND: Check to see if Advanced Intrusion Detection Environment (AIDE) is installed on the system with the following command:
# yum list installed aide

***COMMAND OUTPUT on $HOST***:" >> $FILE
yum list installed aide &>> $FILE

echo "
If AIDE is not installed, ask the System Administrator how file integrity checks are performed on the system.

POTENTIAL FINDING:
If there is no application installed to perform file integrity checks, this is a finding.

Note: AIDE is highly configurable at install time. These commands assume the "aide.conf" file is under the "/etc" directory.

COMMAND: Use the following command to determine if the file is in another location:
# find / -name aide.conf

***COMMAND OUTPUT on $HOST***:" >> $FILE
find / -name aide.conf -exec ls -la {} \; 2> /dev/null >> $FILE
find / -name aide.conf -exec cat {} \; 2> /dev/null >> $FILE

echo "
Check the "aide.conf" file to determine if the "acl" rule has been added to the rule list being applied to the files and directories selection lists.

An example rule that includes the "acl" rule is below:
All= p+i+n+u+g+s+m+S+sha512+acl+xattrs+selinux
/bin All # apply the custom rule to the files in bin
/sbin All # apply the same custom rule to the files in sbin

POTENTIAL FINDING:
If the "acl" rule is not being used on all uncommented selection lines in the "/etc/aide.conf" file, or ACLs are not being checked by another file integrity tool, this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must be configured so that the file integrity tool is configured to verify extended attributes.

STIG ID: RHEL-07-021610  Rule ID: SV-86695r3_rule  Vul ID: V-72071
Severity: CAT III

ACTION: Verify the file integrity tool is configured to verify extended attributes.

COMMAND: Check to see if Advanced Intrusion Detection Environment (AIDE) is installed on the system with the following command:
# yum list installed aide

***COMMAND OUTPUT on $HOST***:" >> $FILE
yum list installed aide &>> $FILE

echo "
If AIDE is not installed, ask the System Administrator how file integrity checks are performed on the system.

POTENTIAL FINDING:
If there is no application installed to perform file integrity checks, this is a finding.

Note: AIDE is highly configurable at install time. These commands assume the "aide.conf" file is under the "/etc" directory.

COMMAND: Use the following command to determine if the file is in another location:
# find / -name aide.conf

***COMMAND OUTPUT on $HOST***:" >> $FILE
find / -name aide.conf -exec ls -la {} \; 2> /dev/null >> $FILE
find / -name aide.conf -exec cat {} \; 2> /dev/null >> $FILE

echo "
Check the "aide.conf" file to determine if the "xattrs" rule has been added to the rule list being applied to the files and directories selection lists.

An example rule that includes the "xattrs" rule follows:
All= p+i+n+u+g+s+m+S+sha512+acl+xattrs+selinux
/bin All # apply the custom rule to the files in bin
/sbin All # apply the same custom rule to the files in sbin

POTENTIAL FINDING:
If the "xattrs" rule is not being used on all uncommented selection lines in the "/etc/aide.conf" file, or extended attributes are not being checked by another file integrity tool, this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must use a file integrity tool that is configured to use FIPS 140-2 approved cryptographic hashes for validating file contents and directories.

STIG ID: RHEL-07-021620  Rule ID: SV-86697r3_rule  Vul ID: V-72073
Severity: CAT II

ACTION: Verify the file integrity tool is configured to use FIPS 140-2 approved cryptographic hashes for validating file contents and directories.
Note: If RHEL-07-021350 is a finding, this is automatically a finding too as the system cannot implement FIPS 140-2 approved cryptographic algorithms and hashes.

COMMAND: Check to see if Advanced Intrusion Detection Environment (AIDE) is installed on the system with the following command:
# yum list installed aide

***COMMAND OUTPUT on $HOST***:" >> $FILE
yum list installed aide &>> $FILE

echo "
If AIDE is not installed, ask the System Administrator how file integrity checks are performed on the system.

POTENTIAL FINDING:
If there is no application installed to perform file integrity checks, this is a finding.

Note: AIDE is highly configurable at install time. These commands assume the "aide.conf" file is under the "/etc" directory.

COMMAND: Use the following command to determine if the file is in another location:
# find / -name aide.conf

***COMMAND OUTPUT on $HOST***:" >> $FILE
find / -name aide.conf -exec ls -la {} \; 2> /dev/null >> $FILE
find / -name aide.conf -exec cat {} \; 2> /dev/null >> $FILE

echo "
Check the "aide.conf" file to determine if the "sha512" rule has been added to the rule list being applied to the files and directories selection lists.

An example rule that includes the "sha512" rule follows:

All=p+i+n+u+g+s+m+S+sha512+acl+xattrs+selinux
/bin All # apply the custom rule to the files in bin
/sbin All # apply the same custom rule to the files in sbin

POTENTIAL FINDING:
If the "sha512" rule is not being used on all uncommented selection lines in the "/etc/aide.conf" file, or another file integrity tool is not using FIPS 140-2 approved cryptographic hashes for validating file contents and directories, this is a finding. " >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must not allow removable media to be used as the boot loader unless approved.

STIG ID: RHEL-07-021700  Rule ID: SV-86699r2_rule  Vul ID: V-72075
Severity: CAT II

ACTION: Verify the system is not configured to use a boot loader on removable media.
Note: GRUB 2 reads its configuration from the "/boot/grub2/grub.cfg" file on traditional BIOS-based machines and from the "/boot/efi/EFI/redhat/grub.cfg" file on UEFI machines.

COMMAND: Check for the existence of alternate boot loader configuration files with the following command:
# find / -name grub.cfg

EXAMPLE OUTPUT:
/boot/grub2/grub.cfg

***COMMAND OUTPUT on $HOST***:" >> $FILE
find / -name grub.cfg 2> /dev/null >> $FILE

echo "
If a "grub.cfg" is found in any subdirectories other than "/boot/grub2" and "/boot/efi/EFI/redhat", ask the System Administrator if there is documentation signed by the ISSO to approve the use of removable media as a boot loader.

COMMAND: Check that the grub configuration file has the set root command in each menu entry with the following commands:
# grep -c menuentry /boot/grub2/grub.cfg

EXAMPLE OUTPUT:
1

***COMMAND OUTPUT on $HOST***:" >> $FILE
grep -c menuentry /boot/grub2/grub.cfg >> $FILE || echo No ouput was received from the above command! >> $FILE

echo "
COMMAND:
# grep 'set root' /boot/grub2/grub.cfg

EXAMPLE OUTPUT:
set root=(hd0,1)

***COMMAND OUTPUT on $HOST***:" >> $FILE
grep 'set root' /boot/grub2/grub.cfg >> $FILE || echo No ouput was received from the above command! >> $FILE

echo "
POTENTIAL FINDING:
If the system is using an alternate boot loader on removable media, and documentation does not exist approving the alternate configuration, this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must initiate an action to notify the System Administrator (SA) and Information System Security Officer ISSO, at a minimum, when allocated audit record storage volume reaches 75% of the repository maximum audit record storage capacity.

STIG ID: RHEL-07-030330  Rule ID: SV-86713r4_rule  Vul ID: V-72089
Severity: CAT II

ACTION: Verify the operating system initiates an action to notify the SA and ISSO (at a minimum) when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity.

COMMAND: Check the system configuration to determine the partition the audit records are being written to with the following command:
# grep -iw log_file /etc/audit/auditd.conf

EXAMPLE OUTPUT:
log_file = /var/log/audit/audit.log

***COMMAND OUTPUT on $HOST***:" >> $FILE
grep -iw log_file /etc/audit/auditd.conf >> $FILE || echo No ouput was received from the above command! >> $FILE

echo "
COMMAND: Check the size of the partition that audit records are written to (with the example being "/var/log/audit/"):
# df -h /var/log/audit/

EXAMPLE OUTPUT:
0.9G /var/log/audit

***COMMAND OUTPUT on $HOST***:" >> $FILE
df -h /var/log/audit/ >> $FILE

echo "
COMMAND: If the audit records are not being written to a partition specifically created for audit records (in this example "/var/log/audit" is a separate partition), determine the amount of space other files in the partition are currently occupying with the following command:
# du -sh <partition>

EXAMPLE OUTPUT:
1.8G /var

***COMMAND OUTPUT on $HOST***:" >> $FILE
du -sh >> $FILE

echo "
COMMAND: Determine what the threshold is for the system to take action when 75 percent of the repository maximum audit record storage capacity is reached:
# grep -iw space_left /etc/audit/auditd.conf

EXAMPLE OUTPUT:
space_left = 225

***COMMAND OUTPUT on $HOST***:" >> $FILE
grep -iw space_left /etc/audit/auditd.conf >> $FILE || echo No ouput was received from the above command! >> $FILE

echo "
POTENTIAL FINDING:
If the value of the "space_left" keyword is not set to 25 percent of the total partition size, this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must send rsyslog output to a log aggregation server.

STIG ID: RHEL-07-031000  Rule ID: SV-86833r2_rule  Vul ID: V-72209
Severity: CAT II

ACTION: Verify "rsyslog" is configured to send all messages to a log aggregation server.

COMMAND: Check the configuration of "rsyslog" with the following command:
Note: If another logging package is used, substitute the utility configuration file for "/etc/rsyslog.conf".
# grep @ /etc/rsyslog.conf /etc/rsyslog.d/*.conf

EXAMPLE OUTPUT:
*.* @@logagg.site.mil

***COMMAND OUTPUT on $HOST***:" >> $FILE
grep @ /etc/rsyslog.conf /etc/rsyslog.d/*.conf >> $FILE || echo No ouput was received from the above command! >> $FILE

echo "
If there are no lines in the "/etc/rsyslog.conf" or "/etc/rsyslog.d/*.conf" files that contain the "@" or "@@" symbol(s), and the lines with the correct symbol(s) to send output to another system do not cover all "rsyslog" output, ask the System Administrator to indicate how the audit logs are off-loaded to a different system or media.

POTENTIAL FINDING:
If the lines are commented out or there is no evidence that the audit logs are being sent to another system, this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must be configured so that the rsyslog daemon does not accept log messages from other servers unless the server is being used for log aggregation.

STIG ID: RHEL-07-031010  Rule ID: SV-86835r2_rule  Vul ID: V-72211
Severity: CAT II

ACTION: Verify that the system is not accepting "rsyslog" messages from other systems unless it is documented as a log aggregation server.

COMMAND: Check the configuration of "rsyslog" with the following command:
# grep imtcp /etc/rsyslog.conf

EXAMPLE OUTPUT:
\$ModLoad imtcp

***COMMAND OUTPUT on $HOST***:" >> $FILE
grep imtcp /etc/rsyslog.conf >> $FILE || echo No ouput was received from the above command! >> $FILE

echo "
COMMAND:
# grep imudp /etc/rsyslog.conf

EXAMPLE OUTPUT:
\$ModLoad imudp

***COMMAND OUTPUT on $HOST***:" >> $FILE
grep imudp /etc/rsyslog.conf >> $FILE || echo No ouput was received from the above command! >> $FILE

echo "
COMMAND:
# grep imrelp /etc/rsyslog.conf

EXAMPLE OUTPUT:
$ModLoad imrelp

***COMMAND OUTPUT on $HOST***:" >> $FILE
grep imrelp /etc/rsyslog.conf >> $FILE || echo No ouput was received from the above command! >> $FILE

echo "
If any of the above modules are being loaded in the "/etc/rsyslog.conf" file, ask to see the documentation for the system being used for log aggregation.

POTENTIAL FINDING:
If the documentation does not exist, or does not specify the server as a log aggregation system, this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must use a virus scan program.

STIG ID: RHEL-07-032000  Rule ID: SV-86837r3_rule  Vul ID: V-72213
Severity: CAT I

ACTION: Verify an anti-virus solution is installed on the system. The anti-virus solution may be bundled with an approved host-based security solution.

COMMAND: Current rev of the installed Symantec Antivirus Definitions (if exists):
# /opt/Symantec/symantec_antivirus/sav info -d

***COMMAND OUTPUT on $HOST***:" >> $FILE
/opt/Symantec/symantec_antivirus/sav info -d &>> $FILE

echo "
COMMAND: Current rev of the installed ClamAV Software and Definitions (if exists):
# /bin/clamscan --version

***COMMAND OUTPUT on $HOST***:" >> $FILE
/bin/clamscan --version &>> $FILE

echo "
POTENTIAL FINDING:
If there is no anti-virus solution installed on the system, this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the Ports, Protocols, and Services Management Component Local Service Assessment (PPSM CLSA) and vulnerability assessments.

STIG ID: RHEL-07-040100  Rule ID: SV-86843r2_rule  Vul ID: V-72219
Severity: CAT II

ACTION: Inspect the firewall configuration and running services to verify that it is configured to prohibit or restrict the use of functions, ports, protocols, and/or services that are unnecessary or prohibited.

COMMAND: Check which services are currently active with the following command:
# firewall-cmd --list-all

EXAMPLE OUTPUT:
public (default, active)
  interfaces: enp0s3
  sources:
  services: dhcpv6-client dns http https ldaps rpc-bind ssh
  ports:
  masquerade: no
  forward-ports:
  icmp-blocks:
  rich rules:

***COMMAND OUTPUT on $HOST***:" >> $FILE
firewall-cmd --list-all >> $FILE

echo "
Ask the System Administrator for the site or program PPSM CLSA. Verify the services allowed by the firewall match the PPSM CLSA.

POTENTIAL FINDING:
If there are additional ports, protocols, or services that are not in the PPSM CLSA, or there are ports, protocols, or services that are prohibited by the PPSM Category Assurance List (CAL), this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must be configured so that all network connections associated with a communication session are terminated at the end of the session or after 10 minutes of inactivity from the user at a command prompt, except to fulfill documented and validated mission requirements.

STIG ID: RHEL-07-040160  Rule ID: SV-86847r4_rule  Vul ID: V-72223
Severity: CAT II

ACTION: Verify the operating system terminates all network connections associated with a communications session at the end of the session or based on inactivity.

COMMAND: Check the value of the system inactivity timeout with the following command:
# grep -i tmout /etc/profile.d/*

EXAMPLE OUTPUT:
/etc/profile.d/tmout.sh:TMOUT=600
/etc/profile.d/tmout.sh:readonly TMOUT
/etc/profile.d/tmout.sh:export TMOUT

***COMMAND OUTPUT on $HOST***:" >> $FILE
grep -i tmout /etc/profile.d/* >> $FILE || echo No ouput was received from the above command! >> $FILE

echo "
POTENTIAL FINDING:
If "TMOUT" is not set to "600" or less in a script located in the /etc/profile.d/ directory to enforce session termination after inactivity, this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must implement cryptography to protect the integrity of Lightweight Directory Access Protocol (LDAP) authentication communications.

STIG ID: RHEL-07-040180  Rule ID: SV-86851r4_rule  Vul ID: V-72227
Severity: CAT II

ACTION: If LDAP is not being utilized, this requirement is Not Applicable.
Verify the operating system implements cryptography to protect the integrity of remote LDAP authentication sessions.

COMMAND: To determine if LDAP is being used for authentication, use the following command:
# systemctl status sssd.service

EXAMPLE OUTPUT:
sssd.service - System Security Services Daemon
Loaded: loaded (/usr/lib/systemd/system/sssd.service; enabled; vendor preset: disabled)
Active: active (running) since Wed 2018-06-27 10:58:11 EST; 1h 50min ago

***COMMAND OUTPUT on $HOST***:" >> $FILE
systemctl status sssd.service >> $FILE

echo "
If the "sssd.service" is "active", then LDAP is being used.

COMMAND: Determine the "id_provider" the LDAP is currently using:
# grep -i "id_provider" /etc/sssd/sssd.conf

EXAMPLE OUTPUT:
id_provider = ad

***COMMAND OUTPUT on $HOST***:" >> $FILE
grep -i "id_provider" /etc/sssd/sssd.conf &>> $FILE

echo "
If "id_provider" is set to "ad", this is Not Applicable.

COMMAND: Ensure that LDAP is configured to use TLS by using the following command:
# grep -i "start_tls" /etc/sssd/sssd.conf

EXAMPLE OUTPUT:
ldap_id_use_start_tls = true

***COMMAND OUTPUT on $HOST***:" >> $FILE
grep -i "start_tls" /etc/sssd/sssd.conf &>> $FILE

echo "
POTENTIAL FINDING:
If the "ldap_id_use_start_tls" option is not "true", this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must implement cryptography to protect the integrity of Lightweight Directory Access Protocol (LDAP) communications.

STIG ID: RHEL-07-040190  Rule ID: SV-86853r4_rule  Vul ID: V-72229
Severity: CAT II

ACTION: If LDAP is not being utilized, this requirement is Not Applicable.
Verify the operating system implements cryptography to protect the integrity of remote LDAP access sessions.

COMMAND: To determine if LDAP is being used for authentication, use the following command:
# systemctl status sssd.service

EXAMPLE OUTPUT:
sssd.service - System Security Services Daemon
Loaded: loaded (/usr/lib/systemd/system/sssd.service; enabled; vendor preset: disabled)
Active: active (running) since Wed 2018-06-27 10:58:11 EST; 1h 50min ago

***COMMAND OUTPUT on $HOST***:" >> $FILE
systemctl status sssd.service >> $FILE

echo "
If the "sssd.service" is "active", then LDAP is being used.

COMMAND: Determine the "id_provider" the LDAP is currently using:
# grep -i "id_provider" /etc/sssd/sssd.conf

EXAMPLE OUTPUT:
id_provider = ad

***COMMAND OUTPUT on $HOST***:" >> $FILE
grep -i "id_provider" /etc/sssd/sssd.conf &>> $FILE

echo "
If "id_provider" is set to "ad", this is Not Applicable.

COMMAND: Verify the sssd service is configured to require the use of certificates:
# grep -i tls_reqcert /etc/sssd/sssd.conf

EXAMPLE OUTPUT:
ldap_tls_reqcert = demand

***COMMAND OUTPUT on $HOST***:" >> $FILE
grep -i tls_reqcert /etc/sssd/sssd.conf &>> $FILE

echo "
POTENTIAL FINDING:
If the "ldap_tls_reqcert" setting is missing, commented out, or does not exist, this is a finding.
If the "ldap_tls_reqcert" setting is not set to "demand" or "hard", this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must implement cryptography to protect the integrity of Lightweight Directory Access Protocol (LDAP) communications.

STIG ID: RHEL-07-040200  Rule ID: SV-86855r4_rule  Vul ID: V-72231
Severity: CAT II

ACTION: If LDAP is not being utilized, this requirement is Not Applicable.
Verify the operating system implements cryptography to protect the integrity of remote LDAP access sessions.

COMMAND: To determine if LDAP is being used for authentication, use the following command:
# systemctl status sssd.service

EXAMPLE OUTPUT:
sssd.service - System Security Services Daemon
Loaded: loaded (/usr/lib/systemd/system/sssd.service; enabled; vendor preset: disabled)
Active: active (running) since Wed 2018-06-27 10:58:11 EST; 1h 50min ago

***COMMAND OUTPUT on $HOST***:" >> $FILE
systemctl status sssd.service &>> $FILE

echo "
If the "sssd.service" is "active", then LDAP is being used.

COMMAND: Determine the "id_provider" that the LDAP is currently using:
# grep -i "id_provider" /etc/sssd/sssd.conf

EXAMPLE OUTPUT:
id_provider = ad

***COMMAND OUTPUT on $HOST***:" >> $FILE
grep -i "id_provider" /etc/sssd/sssd.conf &>> $FILE

echo "
If "id_provider" is set to "ad", this is Not Applicable.

COMMAND: Check the path to the X.509 certificate for peer authentication with the following command:
# grep -i tls_cacert /etc/sssd/sssd.conf

EXAMPLE OUTPUT:
ldap_tls_cacert = /etc/pki/tls/certs/ca-bundle.crt

***COMMAND OUTPUT on $HOST***:" >> $FILE
grep -i tls_cacert /etc/sssd/sssd.conf &>> $FILE

echo "
Verify the "ldap_tls_cacert" option points to a file that contains the trusted CA certificate.

POTENTIAL FINDING:
If this file does not exist, or the option is commented out or missing, this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must be configured so that all networked systems use SSH for confidentiality and integrity of transmitted and received information as well as information during preparation for transmission.

STIG ID: RHEL-07-040310  Rule ID: SV-86859r3_rule  Vul ID: V-72235
Severity: CAT II

COMMAND: Verify SSH is loaded and active with the following command:
# systemctl status sshd

EXAMPLE OUTPUT:
sshd.service - OpenSSH server daemon
Loaded: loaded (/usr/lib/systemd/system/sshd.service; enabled)
Active: active (running) since Tue 2015-11-17 15:17:22 EST; 4 weeks 0 days ago
Main PID: 1348 (sshd)
CGroup: /system.slice/sshd.service
1053 /usr/sbin/sshd -D

***COMMAND OUTPUT on $HOST***:" >> $FILE
systemctl status sshd >> $FILE

echo "
POTENTIAL FINDING:
If "sshd" does not show a status of "active" and "running", this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must, for networked systems, synchronize clocks with a server that is synchronized to one of the redundant United States Naval Observatory (USNO) time servers, a time server designated for the appropriate DoD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS).

STIG ID: RHEL-07-040500  Rule ID: SV-86893r5_rule  Vul ID: V-72269
Severity: CAT II

COMMAND: Check to see if NTP is running in continuous mode:
# ps -ef | grep ntp

***COMMAND OUTPUT on $HOST***:" >> $FILE
ps -ef | grep ntp >> $FILE

echo "
COMMAND: If NTP is not running, check to see if "chronyd" is running in continuous mode:
# ps -ef | grep chronyd

***COMMAND OUTPUT on $HOST***:" >> $FILE
ps -ef | grep chronyd >> $FILE

echo "
POTENTIAL FINDING:
If NTP or "chronyd" is not running, this is a finding.

COMMAND: If the NTP process is found, then check the "ntp.conf" file for the "maxpoll" option setting:
# grep maxpoll /etc/ntp.conf

EXAMPLE OUTPUT:
server 0.rhel.pool.ntp.org iburst maxpoll 10

***COMMAND OUTPUT on $HOST***:" >> $FILE
grep maxpoll /etc/ntp.conf >> $FILE || echo No ouput was received from the above command! >> $FILE

echo "
POTENTIAL FINDING:
If the option is set to "17" or is not set, this is a finding.

COMMAND: If the file does not exist, check the "/etc/cron.daily" subdirectory for a crontab file controlling the execution of the "ntpd -q" command.
# grep -i "ntpd -q" /etc/cron.daily/*

***COMMAND OUTPUT on $HOST***:" >> $FILE
grep -i "ntpd -q" /etc/cron.daily/* >> $FILE || echo No ouput was received from the above command! >> $FILE

echo "
COMMAND:
# ls -al /etc/cron.* | grep ntp

EXAMPLE OUTPUT:
ntp

***COMMAND OUTPUT on $HOST***:" >> $FILE
ls -al /etc/cron.* | grep ntp >> $FILE || echo No ouput was received from the above command! >> $FILE

echo "
POTENTIAL FINDING:
If a crontab file does not exist in the "/etc/cron.daily" that executes the "ntpd -q" command, this is a finding.

COMMAND: If the "chronyd" process is found, then check the "chrony.conf" file for the "maxpoll" option setting:
# grep maxpoll /etc/chrony.conf

EXAMPLE OUTPUT:
server 0.rhel.pool.ntp.org iburst maxpoll 10

***COMMAND OUTPUT on $HOST***:" >> $FILE
grep maxpoll /etc/chrony.conf >> $FILE || echo No ouput was received from the above command! >> $FILE

echo "
POTENTIAL FINDING:
If the option is not set or the line is commented out, this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must enable an application firewall, if available.

STIG ID: RHEL-07-040520  Rule ID: SV-86897r2_rule  Vul ID: V-72273
Severity: CAT II

ACTION: Verify the operating system enabled an application firewall.

COMMAND: Check to see if "firewalld" is installed with the following command:
# yum list installed firewalld

EXAMPLE OUTPUT:
firewalld-0.3.9-11.el7.noarch.rpm

***COMMAND OUTPUT on $HOST***:" >> $FILE
yum list installed firewalld &>> $FILE

echo "
If the "firewalld" package is not installed, ask the System Administrator if another firewall application (such as iptables) is installed.

POTENTIAL FINDING:
If an application firewall is not installed, this is a finding.

COMMAND: Check to see if the firewall is loaded and active with the following command:
# systemctl status firewalld

EXAMPLE OUTPUT:
firewalld.service - firewalld - dynamic firewall daemon

   Loaded: loaded (/usr/lib/systemd/system/firewalld.service; enabled)
   Active: active (running) since Tue 2014-06-17 11:14:49 CEST; 5 days ago

***COMMAND OUTPUT on $HOST***:" >> $FILE
systemctl status firewalld >> $FILE

echo "
POTENTIAL FINDING:
If "firewalld" does not show a status of "loaded" and "active", this is a finding.

COMMAND: Check the state of the firewall:
# firewall-cmd --state

EXAMPLE OUTPUT:
running

***COMMAND OUTPUT on $HOST***:" >> $FILE
firewall-cmd --state >> $FILE

echo "
POTENTIAL FINDING:
If "firewalld" does not show a state of "running", this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  Network interfaces configured on the Red Hat Enterprise Linux operating system must not be in promiscuous mode.

STIG ID: RHEL-07-040670  Rule ID: SV-86919r2_rule  Vul ID: V-72295
Severity: CAT II

ACTION: Verify network interfaces are not in promiscuous mode unless approved by the ISSO and documented.

COMMAND: Check for the status with the following command:
# ip link | grep -i promisc

***COMMAND OUTPUT on $HOST***:" >> $FILE
ip link | grep -i promisc >> $FILE || echo No ouput was received from the above command! >> $FILE

echo "
POTENTIAL FIDNING:
If network interfaces are found on the system in promiscuous mode and their use has not been approved by the ISSO and documented, this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must be configured to prevent unrestricted mail relaying.

STIG ID: RHEL-07-040680  Rule ID: SV-86921r3_rule  Vul ID: V-72297
Severity: CAT II

ACTION: Verify the system is configured to prevent unrestricted mail relaying.

COMMAND: Determine if "postfix" is installed with the following commands:
# yum list installed postfix

EXAMPLE OUTPUT:
postfix-2.6.6-6.el7.x86_64.rpm

***COMMAND OUTPUT on $HOST***:" >> $FILE
yum list installed postfix &>> $FILE

echo "
If postfix is not installed, this is Not Applicable.

COMMAND: If postfix is installed, determine if it is configured to reject connections from unknown or untrusted networks with the following command:
# postconf -n smtpd_client_restrictions

EXAMPLE OUTPUT:
smtpd_client_restrictions = permit_mynetworks, reject

***COMMAND OUTPUT on $HOST***:" >> $FILE
postconf -n smtpd_client_restrictions >> $FILE || echo No ouput was received from the above command! >> $FILE

echo "
POTENTIAL FINDING:
If the "smtpd_client_restrictions" parameter contains any entries other than "permit_mynetworks" and "reject", this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must be configured so that if the Trivial File Transfer Protocol (TFTP) server is required, the TFTP daemon is configured to operate in secure mode.

STIG ID: RHEL-07-040720  Rule ID: SV-86929r3_rule  Vul ID: V-72305
Severity: CAT II

ACTION: Verify the TFTP daemon is configured to operate in secure mode.

COMMAND: Check to see if a TFTP server has been installed with the following commands:
# yum list installed tftp-server

EXAMPLE OUTPUT:
tftp-server.x86_64 x.x-x.el7 rhel-7-server-rpms

***COMMAND OUTPUT on $HOST***:" >> $FILE
yum list installed tftp-server &>> $FILE

echo "
If a TFTP server is not installed, this is Not Applicable.

COMMAND: If a TFTP server is installed, check for the server arguments with the following command:
# grep server_args /etc/xinetd.d/tftp

EXAMPLE OUTPUT:
server_args = -s /var/lib/tftpboot

***COMMAND OUTPUT on $HOST***:" >> $FILE
grep server_args /etc/xinetd.d/tftp &>> $FILE

echo "
POTENTIAL FINDING:
If the "server_args" line does not have a "-s" option and a subdirectory is not assigned, this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must be configured so that the Network File System (NFS) is configured to use RPCSEC_GSS.

STIG ID: RHEL-07-040750  Rule ID: SV-86935r4_rule  Vul ID: V-72311
Severity: CAT II

ACTION: Verify "AUTH_GSS" is being used to authenticate NFS mounts.

COMMAND: To check if the system is importing an NFS file system, look for any entries in the "/etc/fstab" file that have a file system type of "nfs" with the following command:
# cat /etc/fstab | grep nfs

EXAMPLE OUTPUT:
192.168.21.5:/mnt/export /data1 nfs4 rw,sync ,soft,sec=krb5:krb5i:krb5p

***COMMAND OUTPUT on $HOST***:" >> $FILE
cat /etc/fstab | grep nfs >> $FILE || echo No ouput was received from the above command! >> $FILE

echo "
If the system is mounting file systems via NFS and has the sec option without the "krb5:krb5i:krb5p" settings, the "sec" option has the "sys" setting, or the "sec" option is missing, this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system access control program must be configured to grant or deny system access to specific hosts and services.

STIG ID: RHEL-07-040810  Rule ID: SV-86939r3_rule  Vul ID: V-72315
Severity: CAT II

ACTION: If the "firewalld" package is not installed, ask the System Administrator (SA) if another firewall application (such as iptables) is installed. If an application firewall is not installed, this is a finding.
Verify the system's access control program is configured to grant or deny system access to specific hosts.

COMMAND: Check to see if "firewalld" is active with the following command:
# systemctl status firewalld

EXAMPLE OUTPUT:
firewalld.service - firewalld - dynamic firewall daemon
Loaded: loaded (/usr/lib/systemd/system/firewalld.service; enabled)
Active: active (running) since Sun 2014-04-20 14:06:46 BST; 30s ago

***COMMAND OUTPUT on $HOST***:" >> $FILE
systemctl status firewalld &>> $FILE

echo "
COMMAND: If "firewalld" is active, check to see if it is configured to grant or deny access to specific hosts or services with the following commands:
# firewall-cmd --get-default-zone

EXAMPLE OUTPUT:
public

***COMMAND OUTPUT on $HOST***:" >> $FILE
firewall-cmd --get-default-zone &>> $FILE

echo "
COMMAND:
# firewall-cmd --list-all --zone=public

EXAMPLE OUTPUT:
public (active)
target: default
icmp-block-inversion: no
interfaces: eth0
sources:
services: mdns ssh
ports:
protocols:
masquerade: no
forward-ports:
icmp-blocks:

***COMMAND OUTPUT on $HOST***:" >> $FILE
firewall-cmd --list-all --zone=public &>> $FILE

echo "
COMMAND: If "firewalld" is not active, determine whether "tcpwrappers" is being used by checking whether the "hosts.allow" and "hosts.deny" files are empty with the following commands:
# ls -al /etc/hosts.allow

EXAMPLE OUTPUT:
rw-r----- 1 root root 9 Aug 2 23:13 /etc/hosts.allow

***COMMAND OUTPUT on $HOST***:" >> $FILE
ls -al /etc/hosts.allow &>> $FILE

echo "
COMMAND:
# ls -al /etc/hosts.deny

EXAMPLE OUTPUT:
-rw-r----- 1 root root 9 Apr 9 2007 /etc/hosts.deny

***COMMAND OUTPUT on $HOST***:" >> $FILE
ls -al /etc/hosts.deny &>> $FILE

echo "
If "firewalld" and "tcpwrappers" are not installed, configured, and active, ask the SA if another access control program (such as iptables) is installed and active. Ask the SA to show that the running configuration grants or denies access to specific hosts or services.

POTENTIAL FINDING:
If "firewalld" is active and is not configured to grant access to specific hosts or "tcpwrappers" is not configured to grant or deny access to specific hosts, this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must not have unauthorized IP tunnels configured.

STIG ID: RHEL-07-040820  Rule ID: SV-86941r2_rule  Vul ID: V-72317
Severity: CAT II

ACTION: Verify the system does not have unauthorized IP tunnels configured.

COMMAND: Check to see if "libreswan" is installed with the following command:
# yum list installed libreswan

EXAMPLE OUTPUT:
libreswan.x86-64 3.20-5.el7_4

***COMMAND OUTPUT on $HOST***:" >> $FILE
yum list installed libreswan &>> $FILE

echo "
COMMAND: If "libreswan" is installed, check to see if the "IPsec" service is active with the following command:
# systemctl status ipsec

EXAMPLE OUTPUT:
ipsec.service - Internet Key Exchange (IKE) Protocol Daemon for IPsec
Loaded: loaded (/usr/lib/systemd/system/ipsec.service; disabled)
Active: inactive (dead)

***COMMAND OUTPUT on $HOST***:" >> $FILE
systemctl status ipsec >> $FILE

echo "
COMMAND: If the "IPsec" service is active, check to see if any tunnels are configured in "/etc/ipsec.conf" and "/etc/ipsec.d/" with the following commands:
# grep -iw conn /etc/ipsec.conf /etc/ipsec.d/*.conf

***COMMAND OUTPUT on $HOST***:" >> $FILE
grep -iw conn /etc/ipsec.conf /etc/ipsec.d/*.conf &>> $FILE || echo No ouput was received from the above command! >> $FILE

echo "
If there are indications that a "conn" parameter is configured for a tunnel, ask the System Administrator if the tunnel is documented with the ISSO.

POTENTIAL FINDING:
If "libreswan" is installed, "IPsec" is active, and an undocumented tunnel is active, this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must prevent a user from overriding the session idle-delay setting for the graphical user interface.

STIG ID: RHEL-07-010082  Rule ID: SV-87809r4_rule  Vul ID: V-73157
Severity: CAT II

ACTION: Verify the operating system prevents a user from overriding session idle delay after a 15-minute period of inactivity for graphical user interfaces.
Note: If the system does not have GNOME installed, this requirement is Not Applicable. The screen program must be installed to lock sessions on the console.

COMMAND: Determine which profile the system database is using with the following command:
# grep system-db /etc/dconf/profile/user

EXAMPLE OUTPUT:
system-db:local

***COMMAND OUTPUT on $HOST***:" >> $FILE
grep system-db /etc/dconf/profile/user &>> $FILE

echo "
COMMAND: Check for the session idle delay setting with the following command:
Note: The example below is using the database "local" for the system, so the path is "/etc/dconf/db/local.d". This path must be modified if a database other than "local" is being used.
# grep -i idle-delay /etc/dconf/db/local.d/locks/*

EXAMPLE OUTPUT:
/org/gnome/desktop/session/idle-delay

***COMMAND OUTPUT on $HOST***:" >> $FILE
grep -i idle-delay /etc/dconf/db/local.d/locks/* &>> $FILE

echo "
POTENTIAL FINDING:
If the command does not return a result, this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must be configured so that all wireless network adapters are disabled.

STIG ID: RHEL-07-041010  Rule ID: SV-87829r2_rule  Vul ID: V-73177
Severity: CAT II

ACTION: Verify that there are no wireless interfaces configured on the system.
This is N/A for systems that do not have wireless network adapters.

COMMAND: Check for the presence of active wireless interfaces with the following command:
# nmcli device

EXAMPLE OUTPUT:
DEVICE TYPE STATE
eth0 ethernet connected
wlp3s0 wifi disconnected
lo loopback unmanaged

***COMMAND OUTPUT on $HOST***:" >> $FILE
nmcli device >> $FILE

echo "
POTENTIAL FINDING:
If a wireless interface is configured and its use on the system is not documented with the Information System Security Officer (ISSO), this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must prevent a user from overriding the screensaver lock-enabled setting for the graphical user interface.

STIG ID: RHEL-07-010062  Rule ID: SV-93701r3_rule  Vul ID: V-78995
Severity: CAT II

Verify the operating system prevents a user from overriding the screensaver lock-enabled setting for the graphical user interface.

Note: If the system does not have GNOME installed, this requirement is Not Applicable. The screen program must be installed to lock sessions on the console.

COMMAND: Determine which profile the system database is using with the following command:
# grep system-db /etc/dconf/profile/user

EXAMPLE OUTPUT:
system-db:local

***COMMAND OUTPUT on $HOST***:" >> $FILE
grep system-db /etc/dconf/profile/user &>> $FILE

echo "
COMMAND: Check for the lock-enabled setting with the following command:
Note: The example below is using the database "local" for the system, so the path is "/etc/dconf/db/local.d". This path must be modified if a database other than "local" is being used.
# grep -i lock-enabled /etc/dconf/db/local.d/locks/*

EXAMPLE OUTPUT:
/org/gnome/desktop/screensaver/lock-enabled

***COMMAND OUTPUT on $HOST***:" >> $FILE
grep -i lock-enabled /etc/dconf/db/local.d/locks/* &>> $FILE

echo "
POTENTIAL FINDING:
If the command does not return a result, this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must mount /dev/shm with the nodev option.
STIG ID: RHEL-07-021022  Rule ID: SV-95721r2_rule  Vul ID: V-81009
Severity: CAT III

ACTION: Verify that the "nodev" option is configured for /dev/shm:

COMMAND:
# cat /etc/fstab | grep /dev/shm

EXAMPLE OUTPUT:
tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0

***COMMAND OUTPUT on $HOST***:" >> $FILE
cat /etc/fstab | grep /dev/shm >> $FILE || echo No ouput was received from the above command! >> $FILE

echo "
POTENTIAL FINDING:
If any results are returned and the "nodev" option is not listed, this is a finding.

COMMAND: Verify "/dev/shm" is mounted with the "nodev" option:
# mount | grep "/dev/shm" | grep nodev

***COMMAND OUTPUT on $HOST***:" >> $FILE
mount | grep "/dev/shm" | grep nodev >> $FILE || echo No ouput was received from the above command! >> $FILE

echo "
POTENTIAL FINDING:
If no results are returned, this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must mount /dev/shm with the nosuid option.

STIG ID: RHEL-07-021023  Rule ID: SV-95723r2_rule  Vul ID: V-81011
Severity: CAT III

COMMAND: Verify that the "nosuid" option is configured for /dev/shm:
# cat /etc/fstab | grep /dev/shm

EXAMPLE OUTPUT:
tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0

***COMMAND OUTPUT on $HOST***:" >> $FILE
cat /etc/fstab | grep /dev/shm >> $FILE || echo No ouput was received from the above command! >> $FILE

echo "
POTENTIAL FIDNING:
If any results are returned and the "nosuid" option is not listed, this is a finding.

COMMAND: Verify "/dev/shm" is mounted with the "nosuid" option:
# mount | grep "/dev/shm" | grep nosuid

***COMMAND OUTPUT on $HOST***:" >> $FILE
mount | grep "/dev/shm" | grep nosuid >> $FILE || echo No ouput was received from the above command! >> $FILE

echo "
POTENTIAL FINDING:
If no results are returned, this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must mount /dev/shm with the noexec option.

STIG ID: RHEL-07-021024  Rule ID: SV-95725r2_rule  Vul ID: V-81013
Severity: CAT III

COMMAND: Verify that the "noexec" option is configured for /dev/shm:
# cat /etc/fstab | grep /dev/shm

EXAMPLE OUTPUT:
tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0

***COMMAND OUTPUT on $HOST***:" >> $FILE
cat /etc/fstab | grep /dev/shm >> $FILE || echo No ouput was received from the above command! >> $FILE

echo "
POTENTIAL FINDING:
If any results are returned and the "noexec" option is not listed, this is a finding." >> $FILE

echo "
COMMAND: Verify "/dev/shm" is mounted with the "noexec" option:
# mount | grep "/dev/shm" | grep noexec

***COMMAND OUTPUT on $HOST***:" >> $FILE
mount | grep "/dev/shm" | grep noexec >> $FILE || echo No ouput was received from the above command! >> $FILE

echo "
POTENTIAL FINDING:
If no results are returned, this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must use a reverse-path filter for IPv4 network traffic when possible on all interfaces.

STIG ID: RHEL-07-040611  Rule ID: SV-102353r1_rule  Vul ID: V-92251
Severity: CAT II

COMMAND: Verify the system uses a reverse-path filter for IPv4:
# grep net.ipv4.conf.all.rp_filter /etc/sysctl.conf /etc/sysctl.d/*

EXAMPLE OUTPUT:
net.ipv4.conf.all.rp_filter = 1

***COMMAND OUTPUT on $HOST***:" >> $FILE
grep net.ipv4.conf.all.rp_filter /etc/sysctl.conf /etc/sysctl.d/* &>> $FILE || echo No ouput was received from the above command! >> $FILE

echo "
POTENTIAL FINDING:
If "net.ipv4.conf.all.rp_filter" is not configured in the /etc/sysctl.conf file or in the /etc/sysctl.d/ directory, is commented out, or does not have a value of "1", this is a finding.

COMMAND: Check that the operating system implements the accept source route variable with the following command:
NOTE: Modified command for cleaner output
# /sbin/sysctl -a | grep net.ipv4.conf.all.rp_filter

EXAMPLE OUTPUT:
net.ipv4.conf.all.rp_filter = 1

***COMMAND OUTPUT on $HOST***:" >> $FILE
/sbin/sysctl -a --ignore 2> /dev/null | grep net.ipv4.conf.all.rp_filter >> $FILE

echo "
POTENTIAL FINDING:
If the returned line does not have a value of "1", this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must use a reverse-path filter for IPv4 network traffic when possible by default.

STIG ID: RHEL-07-040612  Rule ID: SV-102355r1_rule  Vul ID: V-92253
Severity: CAT II

COMMAND: Verify the system uses a reverse-path filter for IPv4:
# grep net.ipv4.conf.default.rp_filter /etc/sysctl.conf /etc/sysctl.d/*

EXAMPLE OUTPUT:
net.ipv4.conf.default.rp_filter = 1

***COMMAND OUTPUT on $HOST***:" >> $FILE
grep net.ipv4.conf.default.rp_filter /etc/sysctl.conf /etc/sysctl.d/* || echo No ouput was received from the above command! >> $FILE

echo "
POTENTIAL FINDING:
If "net.ipv4.conf.default.rp_filter" is not configured in the /etc/sysctl.conf file or in the /etc/sysctl.d/ directory, is commented out, or does not have a value of "1", this is a finding." >> $FILE

echo "
COMMAND: Check that the operating system implements the accept source route variable with the following command:
# /sbin/sysctl -a | grep net.ipv4.conf.default.rp_filter

EXAMPLE OUTPUT:
net.ipv4.conf.default.rp_filter = 1

***COMMAND OUTPUT on $HOST***:" >> $FILE
/sbin/sysctl -a --ignore 2> /dev/null | grep net.ipv4.conf.default.rp_filter >> $FILE

echo "
POTENTIAL FINDING:
If the returned line does not have a value of "1", this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must have a host-based intrusion detection tool installed.

STIG ID: RHEL-07-020019  Rule ID: SV-102357r1_rule  Vul ID: V-92255
Severity: CAT II

ACTION: Ask the SA or ISSO if a host-based intrusion detection application is loaded on the system. Per OPORD 16-0080, the preferred intrusion detection system is McAfee HBSS available through the U.S. Cyber Command (USCYBERCOM).
If another host-based intrusion detection application is in use, such as SELinux, this must be documented and approved by the local Authorizing Official.

COMMAND: Examine the system to determine if the Host Intrusion Prevention System (HIPS) is installed:
# rpm -qa | grep MFEhiplsm

***COMMAND OUTPUT on $HOST***:" >> $FILE
rpm -qa | grep MFEhiplsm >> $FILE || echo No ouput was received from the above command! >> $FILE

echo "
COMMAND: Verify that the McAfee HIPS module is active on the system:
# ps -ef | grep -i “hipclient”

***COMMAND OUTPUT on $HOST***:" >> $FILE
ps -ef | grep -i “hipclient” >> $FILE

echo "
NOTE: If the MFEhiplsm package is not installed, check for another intrusion detection system:
# find / -name <daemon name>
Where <daemon name> is the name of the primary application daemon to determine if the application is loaded on the system.

Determine if the application is active on the system:
# ps -ef | grep -i <daemon name>

POTENTIAL FINDING:
If the MFEhiplsm package is not installed and an alternate host-based intrusion detection application has not been documented for use, this is a finding.

If no host-based intrusion detection system is installed and running on the system, this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------

Rule Title:  The Red Hat Enterprise Linux operating system must be configured so that the x86 Ctrl-Alt-Delete key sequence is disabled in the GUI.

STIG ID: RHEL-07-020231  Rule ID: SV-104673r1_rule  Vul ID: V-94843
Severity: CAT I

ACTION: Verify the operating system is not configured to reboot the system when Ctrl-Alt-Delete is pressed.

COMMAND: Check that the ctrl-alt-del.target is masked and not active in the GUI with the following command:
# grep logout /etc/dconf/local.d/*

EXAMPLE OUTPUT:
logout=''

***COMMAND OUTPUT on $HOST***:" >> $FILE
grep logout /etc/dconf/local.d/* &>> $FILE || echo No ouput was received from the above command! >> $FILE

echo "
If "logout" is not set to use two single quotations, or is missing, this is a finding." >> $FILE

echo "
---------------------------------------------------------------------------------------------
This is the end of the report.
---------------------------------------------------------------------------------------------" >> $FILE

########################################################################################################################
END=$SECONDS
echo "This script has completed"
echo "Script duration was: $((END-START)) seconds."
#sleep 5s
#tail -50 $FILE | more
#more $FILE
