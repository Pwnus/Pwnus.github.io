---
title: "NextGenInCyber CTF"
date: 2024-11-28 01:09:33 +0300
authors: [oste, Mystique, m3tadr0id, B0nf4c3, dr0idbot]
description: NextGenInCyber CTF Writeups
image: /assets/img/Posts/nextgenincyber.png
categories: [CTF-Time]
tags:
  [ctf,forensics, Registry, Registry explorer,pwn,web,crypo,reverse,CyberChef,Volatility,memory forensics,event viewer,powershell,DeflateStream ,iex,StreamReader,DNA Cipher]
math: true
---

In this blog post, we explore the challenges tackled during the NextgenInCyber CTF 2024, organized by AfricaCERT for the SADC region. Our team proudly secured 5th place out of 25 competing teams.  Shoutout to our MVP, [Oste](https://x.com/oste_ke), who crushed all the forensic challenges like a pro! 🔥

![image](https://gist.github.com/user-attachments/assets/074500e8-af0c-4095-bcf7-776b349ec62d)


# Forensics

## Investigation1

### Description

A software was started and immediately closed. What's the name of this one?

Flag format : NGCCTF{software_name}

https://mega.nz/file/sxEmxAhK#2FLrWfkCOlFZeU9Ats7fyDjoyN6ngF3wjAD4HsbSheU

**Solved & Documented by:** [oste](https://x.com/oste_ke)

### Solution

First, we need to identify the right profile to use for analysis.

The `imageinfo` plugin analyzes the memory dump to suggest the appropriate profile for further analysis, identifying key details about the operating system and memory structure. In this case, the suggested profiles include Win7SP1x86 variations, indicating the dump is from a 32-bit Windows 7 system with Service Pack 1.

```bash
remnux@remnux:~/Desktop/CASE/NextGeninCyber$ vol.py -f Dump_forensic.mem imageinfo

Volatility Foundation Volatility Framework 2.6.1

INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x86_23418, Win7SP0x86, Win7SP1x86_24000, Win7SP1x86
                     AS Layer1 : IA32PagedMemoryPae (Kernel AS)
                     AS Layer2 : FileAddressSpace (/home/remnux/Desktop/CASE/NextGeninCyber/Dump_forensic.mem)
                      PAE type : PAE
                           DTB : 0x185000L
                          KDBG : 0x82b69c28L
          Number of Processors : 1
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0x82b6ac00L
             KUSER_SHARED_DATA : 0xffdf0000L
           Image date and time : 2023-09-25 11:27:39 UTC+0000
     Image local date and time : 2023-09-25 12:27:39 +0100
```
{: .nolineno }

The psxview plugin reveals hidden or terminated processes by comparing visibility across various scanning methods. In this case, FoxitPDFReader (`PID: 2148`) stands out as it does not appear in `pslist` (False) but has an `ExitTime`, indicating it executed briefly before terminating.

```bash
vol.py -f Dump_forensic.mem --profile=Win7SP1x86_23418 psxview
```
{: .nolineno }

![image](https://gist.github.com/user-attachments/assets/3593eccd-5347-471f-9852-f3f52a1a9418)

`NGCCTF{FoxitPDFReader}`

## Investigation2

### Description

A file was opened using the software from the previous challenge. Can you find the file name ? ( without extension)

Flag format : NGCCTF{file_name}

 https://mega.nz/file/sxEmxAhK#2FLrWfkCOlFZeU9Ats7fyDjoyN6ngF3wjAD4HsbSheU

**Solved & Documented by:** [oste](https://x.com/oste_ke)

----

### Solution


Using the `cmdline` plugin, we retrieved the command-line arguments for processes in the memory dump. For *FoxitPDFReader (PID: 1804)*, the command line indicates the software opened a file located at `C:\Users\uzzer_hl\Downloads\un-zeste-de-python.pdf`. Stripping the extension, the filename `un-zeste-de-python` is the flag. 


```bash
remnux@remnux:~/Desktop/CASE/NextGeninCyber$ vol.py -f Dump_forensic.mem --profile=Win7SP1x86_23418 cmdline

----REDACTED----

************************************************************************
FoxitPDFReader pid:   1408
Command line : "C:\Program Files\Common Files\Foxit\Foxit PDF Reader\FoxitPDFReaderUpdateService.exe"

----REDACTED----

FoxitPDFReader pid:   1804
Command line : "C:\Program Files\Foxit Software\Foxit PDF Reader\FoxitPDFReader.exe" "C:\Users\uzzer_hl\Downloads\un-zeste-de-python.pdf"

----REDACTED----

```
{: .nolineno }


`NGCCTF{un-zeste-de-python}`

## Investigation3

### Description

A txt file is opened during memory dump. The file is located in the Documents folder. A flag is inside the file.

 https://mega.nz/file/sxEmxAhK#2FLrWfkCOlFZeU9Ats7fyDjoyN6ngF3wjAD4HsbSheU

**Solved & Documented by:** [oste](https://x.com/oste_ke)

----

### Solution

Using the previous `cmdline` plugin, I noticed notepad.exe (PID: 2292) opened the file `H0GqNwewe.txt.txt.txt` located in the Documents folder.



```bash
remnux@remnux:~/Desktop/CASE/NextGeninCyber$ vol.py -f Dump_forensic.mem --profile=Win7SP1x86_23418 cmdline

----REDACTED----

************************************************************************
notepad.exe pid:   2292
Command line : "C:\Windows\system32\NOTEPAD.EXE" C:\Users\uzzer_hl\Documents\H0GqNwewe.txt.txt.txt
************************************************************************

----REDACTED----

```
{: .nolineno }

Locate the file in memory using the `filescan` plugin. The filescan plugin identified the file's memory object at offset 0x000000003d939c30.

```bash
remnux@remnux:~/Desktop/CASE/NextGeninCyber$ vol.py -f Dump_forensic.mem --profile=Win7SP1x86_23418 filescan | grep H0GqNwewe
Volatility Foundation Volatility Framework 2.6.1

0x000000003d939c30      8      0 R--rwd \Device\HarddiskVolume1\Users\uzzer_hl\Documents\H0GqNwewe.txt.txt.txt
```
{: .nolineno }

Extract the file using the `dumpfiles` plugin as shown: 

```bash
remnux@remnux:~/Desktop/CASE/NextGeninCyber$ vol.py -f Dump_forensic.mem --profile=Win7SP1x86_23418 dumpfiles -Q 0x000000003d939c30 -D .
Volatility Foundation Volatility Framework 2.6.1

DataSectionObject 0x3d939c30   None   \Device\HarddiskVolume1\Users\uzzer_hl\Documents\H0GqNwewe.txt.txt.txt

remnux@remnux:~/Desktop/CASE/NextGeninCyber$ ls -la
total 1082508
drwxrwxrwx 3 remnux remnux       4096 Nov 27 05:36 .
drwxrwxr-x 3 remnux remnux       4096 Nov 27 04:50 ..
-rwxrw-rw- 1 remnux remnux 1073741824 Nov 27 04:39 Dump_forensic.mem
-rw-rw-r-- 1 remnux remnux       4096 Nov 27 05:36 file.None.0xadedc150.dat
```
{: .nolineno }

Examining the dumped file revealed the flag

```bash
remnux@remnux:~/Desktop/CASE/NextGeninCyber$ cat file.None.0xadedc150.dat 
CTF_1vest1G4tion_D3s_tresor
```
{: .nolineno }


`NGCCTF{CTF_1vest1G4tion_D3s_tresor}`


## Show_me

### Description

Show me

https://mega.nz/file/sxdgRbyK#KLldNXXhNVgGAjzRRsjfhW5mHbrmAPrYZ8vu4HZLivA

**Solved & Documented by:** [oste](https://x.com/oste_ke)

----

### Solution

As previously explained in Investigation Challenge, we start with getting the memory dump's profile :


```bash
Volatility Foundation Volatility Framework 2.6.1

INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x86_23418, Win7SP0x86, Win7SP1x86_24000, Win7SP1x86
                     AS Layer1 : IA32PagedMemoryPae (Kernel AS)
                     AS Layer2 : FileAddressSpace (/home/remnux/Desktop/CASE/NextGeninCyber/forensic1.mem)
                      PAE type : PAE
                           DTB : 0x185000L
                          KDBG : 0x82b7fc28L
          Number of Processors : 1
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0x82b80c00L
             KUSER_SHARED_DATA : 0xffdf0000L
           Image date and time : 2023-09-20 23:51:57 UTC+0000
     Image local date and time : 2023-09-21 00:51:57 +0100
```
{: .nolineno }

Next, we can check all running processes using the `pstree` plugin as shown:

```bash
remnux@remnux:~/Desktop/CASE/NextGeninCyber$ vol.py -f forensic1.mem --profile=Win7SP1x86_23418 pstree
Volatility Foundation Volatility Framework 2.6.1


Name                                                  Pid   PPid   Thds   Hnds Time
-------------------------------------------------- ------ ------ ------ ------ ----
 0x85cef030:csrss.exe                                 424    404      8    370 2023-09-20 21:36:28 UTC+0000
. 0x84e15d40:conhost.exe                             1408    424      2     53 2023-09-20 23:32:09 UTC+0000
 0x8c1cf530:winlogon.exe                              464    404      3    110 2023-09-20 21:36:30 UTC+0000
 0x857d2d40:explorer.exe                             1464   1436     43   1310 2023-09-20 21:36:39 UTC+0000
. 0x84399478:wordpad.exe                             2732   1464      4    170 2023-09-20 23:50:56 UTC+0000
. 0x843b3030:chrome.exe                              2056   1464     28    930 2023-09-20 22:02:12 UTC+0000
.. 0x843ea2f0:chrome.exe                             3900   2056      8     86 2023-09-20 22:02:12 UTC+0000
.. 0x856c1750:chrome.exe                              428   2056     14    311 2023-09-20 22:03:34 UTC+0000
.. 0x84a3e7e0:chrome.exe                              916   2056      7    131 2023-09-20 22:02:17 UTC+0000
.. 0x84e53030:chrome.exe                              288   2056     11    185 2023-09-20 22:02:25 UTC+0000
.. 0x84e08d40:chrome.exe                             2264   2056     14    264 2023-09-20 22:07:27 UTC+0000
.. 0x843c79c0:chrome.exe                             2356   2056     17    266 2023-09-20 22:07:38 UTC+0000
.. 0x843e7510:chrome.exe                             4072   2056     15    208 2023-09-20 22:02:17 UTC+0000
. 0x84e53b48:FTK Imager.exe                          2232   1464     14    414 2023-09-20 22:05:36 UTC+0000
. 0x8bdf27b0:cmd.exe                                  936   1464      1     19 2023-09-20 23:32:09 UTC+0000
 0x8413aa20:System                                      4      0     78    517 2023-09-20 21:36:13 UTC+0000
. 0x8d9ff5e8:smss.exe                                 252      4      2     29 2023-09-20 21:36:13 UTC+0000
 0x84f21d40:wininit.exe                               412    316      3     74 2023-09-20 21:36:28 UTC+0000
. 0x8574f530:lsm.exe                                  508    412      9    140 2023-09-20 21:36:31 UTC+0000
. 0x85742438:lsass.exe                                500    412      7    548 2023-09-20 21:36:31 UTC+0000
. 0x856db438:services.exe                             492    412      8    191 2023-09-20 21:36:30 UTC+0000
.. 0x8550d468:svchost.exe                             264    492      7     95 2023-09-20 21:36:46 UTC+0000
.. 0x84f54550:svchost.exe                             908    492     28   1060 2023-09-20 21:36:36 UTC+0000
.. 0x857cd030:spoolsv.exe                            1304    492     12    265 2023-09-20 21:36:38 UTC+0000
.. 0x85836030:svchost.exe                            1348    492     19    298 2023-09-20 21:36:38 UTC+0000
.. 0x84e4c548:svchost.exe                            3616    492      9    151 2023-09-20 22:00:54 UTC+0000
.. 0x9ec425f0:sppsvc.exe                             2864    492      4    146 2023-09-20 21:38:50 UTC+0000
.. 0x859ad9a8:svchost.exe                            1052    492     12    308 2023-09-20 21:36:36 UTC+0000
.. 0x854bf030:SearchIndexer.                          944    492     12    593 2023-09-20 21:38:08 UTC+0000
.. 0x855609c8:svchost.exe                            2612    492     11    146 2023-09-20 21:38:42 UTC+0000
.. 0x858c7d40:svchost.exe                             700    492      7    250 2023-09-20 21:36:34 UTC+0000
.. 0x859c8bd0:svchost.exe                            1164    492     17    377 2023-09-20 21:36:37 UTC+0000
.. 0x8426fd40:svchost.exe                            3024    492      9    310 2023-09-20 21:38:53 UTC+0000
.. 0x84f28990:taskhost.exe                           1360    492      8    208 2023-09-20 21:36:39 UTC+0000
.. 0x85975030:svchost.exe                             868    492     19    487 2023-09-20 21:36:36 UTC+0000
... 0x857a0828:dwm.exe                               1452    868      3     81 2023-09-20 21:36:39 UTC+0000
... 0x843e5030:WUDFHost.exe                          1204    868      9    211 2023-09-20 23:49:53 UTC+0000
.. 0x85909c88:svchost.exe                             752    492     19    462 2023-09-20 21:36:34 UTC+0000
... 0x84392540:audiodg.exe                           3816    752      5    126 2023-09-20 23:45:52 UTC+0000
.. 0x85876030:svchost.exe                             628    492     10    357 2023-09-20 21:36:34 UTC+0000
.. 0x859f9d40:FoxitPDFReader                         1660    492      3     57 2023-09-20 21:36:42 UTC+0000
 0x86181348:csrss.exe                                 324    316      9    359 2023-09-20 21:36:16 UTC+0000
 0x85272638:GoogleCrashHan                            712   1580      5     81 2023-09-20 21:38:04 UTC+0000
```
{: .nolineno }

Having that in mind, I was particularly drawn to the `wordpad.exe` process. Perhaps the flag is in the `note.txt` file? 

```bash
remnux@remnux:~/Desktop/CASE/NextGeninCyber$ vol.py -f forensic1.mem --profile=Win7SP1x86_23418 cmdline
Volatility Foundation Volatility Framework 2.6.1

-----REDACTED----

************************************************************************
wordpad.exe pid:   2732
Command line : "C:\Program Files\Windows NT\Accessories\WORDPAD.EXE" "C:\Users\uzzer_hl\Documents\note.txt"
```
{: .nolineno }

Like we did previously, we can proceed to do a filescan and extract the note as shown:

```bash
remnux@remnux:~/Desktop/CASE/NextGeninCyber$ vol.py -f forensic1.mem --profile=Win7SP1x86_23418 filescan | grep note.txt
Volatility Foundation Volatility Framework 2.6.1

0x0000000017175038      8      0 RW-rw- \Device\HarddiskVolume1\Users\uzzer_hl\Documents\note.txt
0x000000003e41e9d8      8      0 RW---- \Device\HarddiskVolume1\Users\uzzer_hl\Documents\note.txt
0x000000003e8c6398      8      0 RW-rw- \Device\HarddiskVolume1\Users\uzzer_hl\Documents\note.txt


remnux@remnux:~/Desktop/CASE/NextGeninCyber$ vol.py -f forensic1.mem --profile=Win7SP1x86_23418 dumpfiles -Q 0x0000000017175038 -D .
Volatility Foundation Volatility Framework 2.6.1

DataSectionObject 0x17175038   None   \Device\HarddiskVolume1\Users\uzzer_hl\Documents\note.txt
```
{: .nolineno }

Cating the file, you get a flag.

```bash
remnux@remnux:~/Desktop/CASE/NextGeninCyber$ cat file.None.0x84376200.dat 
B�hanzin est n� en 1844 et est devenu roi en 1889. Il a succ�d� � son p�re, le roi Glele, et a r�gn� pendant une p�riode tumultueuse marqu�e par des conflits avec les forces coloniales europ�ennes, en particulier la France.
Un jour le roi donne CTF_YOU_ARE_GREAT_IN_FORENSIC

Voici un r�cit condens� de son histoire :

B�hanzin a h�rit� d'un royaume qui �tait d�j� en conflit avec les Fran�ais, qui cherchaient � �tendre leur emprise coloniale en Afrique de l'Ouest. D�s le d�but de son r�gne, il a fait preuve d'une grande d�termination pour d�fendre son royaume et son peuple contre les forces coloniales.
```
{: .nolineno }

## Artefact

### Description

Artefact
200
The Treasure Guardian Incident Response Investigation (IR) team conducted a search operation at the home of a member of the BlackHatHacker group. You must find :

1. How many user accounts are there on the system
2. Which account has never authenticated on the system

Flag format NGCCTF{number_of_accounts:name_of_account}

**Solved & Documented by:** [oste](https://x.com/oste_ke)

----

### Solution

This was a simple and fun registry forensics chall. You are given a bunch of registry artifacts:

![image](https://gist.github.com/user-attachments/assets/a17f3661-2fcf-40a8-bb70-e255a226d713)

The `SAM` registry hive contains critical information about user accounts on a Windows system. By examining the `SAM` hive, I determined the total number of user accounts on the system, which includes default and custom-created accounts. Here i got 7 users.


> In Windows, custom-created accounts typically start with a **Relative Identifier (RID)** of **1000** or higher. This is part of the Security Identifier (SID) and distinguishes them from built-in accounts, which have predefined RIDs, such as:
> 
> - **500**: Administrator account.
> - **501**: Guest account.
{: .prompt-tip }

Further analysis of account data, specifically the *Last Login* timestamp revealed which accounts have never authenticated. 

![image](https://gist.github.com/user-attachments/assets/2fc2206e-1449-485c-ba4f-759e0d9d2054)

Hence the flag: `NGCCTF{3:danhomeyboy}`


## Intrusion

### Description

Cyberattack by the BlackHatHacker group on Zambia National reserve. IR analysts were able to recover Windows events logs from a suspect machine. Your role as incident responder is to analyze the artifact.

**Solved & Documented by:** [oste](https://x.com/oste_ke)

----

### Solution

Import the `.evtx` in Windows event viewer as shown:

![image](https://gist.github.com/user-attachments/assets/a4539b8e-960d-4793-a25e-10dc331dd793)

Particularly, my focus was on the `HostApplication` field that shows the command or executable that launched the PowerShell session.

![image](https://gist.github.com/user-attachments/assets/56aad03a-9f24-45fd-883c-a98e8c9f886f)

So I used a powershell one-liner to extract all the `HostApplication` fields:

```powershell
Get-WinEvent -Path ".\NGCCTF_Forensic.evtx" | ForEach-Object { if ($_.Message -match "HostApplication=(.*)") { $Matches[1] } }
```
{: .nolineno }

Aside the binary strings (rabbit hole), you get some base64 strings.

![image](https://gist.github.com/user-attachments/assets/2cbb46d1-1645-4618-a838-8d21fcd0a2b8)

Decode using [Cyberchef](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)Remove_null_bytes()&input=TGdBb0FDY0FhUUJsQUZnQUp3QXBBQ2dBYmdCRkFIY0FMUUJ2QUdJQWFnQkZBR01BZEFBZ0FGTUFXUUJ6QUhRQVpRQk5BQzRBU1FCdkFDNEFVd0IwQUZJQVpRQkJBRTBBY2dCbEFHRUFaQUJGQUhJQUtBQWdBQ2dBSUFCdUFFVUFkd0F0QUc4QVlnQnFBRVVBWXdCMEFDQUFJQUJUQUhrQWN3QjBBRVVBVFFBdUFFa0FUd0F1QUVNQVR3Qk5BRkFBVWdCRkFITUFjd0JwQUU4QVRnQXVBR1FBWlFCbUFHd0FZUUJVQUVVQVV3QjBBSElBWlFCaEFFMEFLQUJiQUVrQWJ3QXVBRTBBWlFCdEFHOEFVZ0I1QUhNQVZBQlNBRVVBUVFCTkFGMEFJQUJiQUhNQVdRQnpBRlFBWlFCTkFDNEFZd0JQQUc0QWRnQkZBSElBVkFCZEFEb0FPZ0JtQUZJQVR3Qk5BRUlBUVFCVEFFVUFOZ0EwQUZNQVZBQnlBR2tBYmdCbkFDZ0FJQUFuQUdRQVdRQXhBRUlBVXdCM0FFMEFlQUJGQUVrQVdBQjJBRU1BTHdCekFHWUFXQUJ4QUhNQVVRQkdBREVBZUFCUkFFVUFSQUI0QUVvQU1BQlpBRzhBYndCREFFa0FjQUJKQURFQVpBQlBBSGtBV2dCeEFHTUFOZ0IxQUVNQVdRQjRBRTBBTWdCckFGQUFOQUJ1QURnQU13Qk9BRmtBYndCSUFHTUFWUUEwQUZBQU13QjJBR1VBS3dCeEFGTUFkZ0JyQUVrQUx3QjJBSE1BVFFCWUFEQUFad0F5QUdNQVZ3QmhBRTBBVUFCdkFGWUFXUUJZQUVZQWVRQlFBRW9BYmdCWEFGWUFaZ0F6QUZZQVlnQXJBRWNBVXdCWkFIa0FOQUJKQUhJQU1RQTBBSGdBUlFCRkFFa0FkZ0JSQUdvQWJRQkZBSGdBU1FCTUFGSUFTZ0JQQUZjQVVnQndBRllBWkFCTEFITUFVUUI1QURJQU1nQlpBRmNBYXdCUEFFMEFTUUJPQURrQVZRQk9BRGNBTndCckFGWUFhQUJ5QUhZQVRnQnRBRGNBWlFCT0FHY0FaZ0J4QURJQVRBQXlBRk1BZWdCNUFHc0FhUUJzQUVNQUt3QkpBQzhBWkFBckFHZ0FhQUJLQUdjQWJnQmtBRVFBZHdCWUFHMEFTZ0J1QUZjQU9RQjJBRk1BTWdBNEFIY0FPQUE1QUhVQWVnQTNBSFFBVXdBdkFDc0FUd0JVQUhVQWRnQmhBRk1BVHdCV0FHSUFjUUJ1QUhZQVdRQlFBRVFBWWdCMEFDc0FkQUJJQUc0QWRRQjRBR3NBV1FCTkFESUFhZ0JYQUc0QWR3QllBSFVBWWdCQkFGZ0FWd0JUQUd3QU9RQnBBSElBY0FCU0FHMEFTQUJ0QUVjQU53QXpBRllBYVFCVEFHNEFNUUJDQURJQWFnQk5BRlFBTHdBckFFSUFUQUExQUhjQWRBQXJBRUVBT1FCa0FGWUFOUUE0QUQwQUp3QXBBQ3dBSUFCYkFITUFXUUJUQUhRQVJRQk5BQzRBYVFCdkFDNEFRd0JQQUUwQVVBQlNBR1VBVXdCVEFHa0Fid0JPQUM0QVl3QlBBRzBBY0FCeUFHVUFjd0JUQUdrQVR3Qk9BRzBBVHdCa0FFVUFYUUE2QURvQVJBQmxBRU1BYndCdEFGQUFjZ0JGQUZNQVV3QXBBQ0FBS1FBc0FGc0Fjd0I1QUhNQVZBQkZBRzBBTGdCVUFFVUFXQUIwQUM0QVpRQnVBR01BVHdCa0FFa0FUZ0JIQUYwQU9nQTZBRUVBY3dCakFHa0FTUUFwQUNBQUtRQXVBSElBWlFCaEFFUUFWQUJ2QUVVQVRnQkVBQ2dBS1FBPQ&ieol=CRLF&oeol=CRLF)


![image](https://gist.github.com/user-attachments/assets/7275bf65-4ef7-4ad2-af3e-580fa61bcba6)

You get yet another base64 like string.

```powershell
.('ieX')(nEw-objEct SYsteM.Io.StReAMreadEr( ( nEw-objEct  SystEM.IO.COMPREssiON.deflaTEStreaM([Io.MemoRysTREAM] [sYsTeM.cOnvErT]::fROMBASE64STring( 'dY1BSwMxEIXvC/sfXqsQF1xQEDxJ0YooCIpI1dOyZqc6uCYxM2kP4n83NYoHcU4P3ve+qSvkI/vsMX0g2cWaMPoVYXFyPJnWVf3Vb+GSYy4Ir14xEEIvQjmExILRJOWRpVdKsQy22YWkOMIN9UN77kVhrvNm7eNgfq2L2SzykilC+I/d+hhJgndDwXmJnW9vS28w89uz7tS/+OTuvaSOVbqnvYPDbt+tHnuxkYM2jWnwXubAXWSl9irpRmHmG73ViSn1B2jMT/+BL5wt+A9dV58='), [sYStEM.io.COMPReSSioN.cOmpresSiONmOdE]::DeComPrESS) ),[sysTEm.TEXt.encOdING]::AsciI) ).reaDToEND()
```
{: .nolineno }

This PowerShell string decodes a Base64-encoded payload into binary data using `System.Convert::FromBase64String`. It decompresses the data with `DeflateStream` and reads it as ASCII text via `StreamReader`. The resulting text, is executed using Invoke-Expression  `.('ieX')`.

To decode this, here's some powershell-foo and you get the flag.

![image](https://gist.github.com/user-attachments/assets/c0c0563e-81c8-40ab-9b02-b76983018b06)



Technically:

```powershell
# Base64 encoded string
$base64String = 'dY1BSwMxEIXvC/sfXqsQF1xQEDxJ0YooCIpI1dOyZqc6uCYxM2kP4n83NYoHcU4P3ve+qSvkI/vsMX0g2cWaMPoVYXFyPJnWVf3Vb+GSYy4Ir14xEEIvQjmExILRJOWRpVdKsQy22YWkOMIN9UN77kVhrvNm7eNgfq2L2SzykilC+I/d+hhJgndDwXmJnW9vS28w89uz7tS/+OTuvaSOVbqnvYPDbt+tHnuxkYM2jWnwXubAXWSl9irpRmHmG73ViSn1B2jMT/+BL5wt+A9dV58='

# Step 1: Decode the Base64 string into a byte array
$decodedBytes = [Convert]::FromBase64String($base64String)

# Step 2: Create a MemoryStream with the decoded byte array
$memoryStream = New-Object System.IO.MemoryStream
$memoryStream.Write($decodedBytes, 0, $decodedBytes.Length)
$memoryStream.Position = 0  # Reset position to the start of the stream

# Step 3: Create a DeflateStream object for decompression
$deflateStream = New-Object System.IO.Compression.DeflateStream($memoryStream, [System.IO.Compression.CompressionMode]::Decompress)

# Step 4: Create a StreamReader to read the decompressed data as text
$streamReader = New-Object System.IO.StreamReader($deflateStream)

# Step 5: Read the decompressed string and output it
$decompressedText = $streamReader.ReadToEnd()

# Step 6: Output the decompressed result
$decompressedText
```
{: .nolineno }


`NGCCTF{CTF_DokounXosu_its_g047_1nvbascript))}`


# Crypto

## DNA

### Description

There are some pretty unusual encoding methods. Find the flag PS: Replace spaces with “_”`

**Solved & Documented by:** [dr0idbot](https://x.com/dr0idbot)

### Solution

You are given this image:

![genes](https://gist.github.com/user-attachments/assets/5b310947-24ea-4e55-ad50-29c9be45c08b)

Extracted the string by reading the characters from left to right starting from the top going down. The resulting extracted string from the image: 

```bash
TCATAGGCTAGCTACACTCGTTGTACACTAGACAGCTACACTCTCTGAAGCTAGCTATGAAGCGTCCTACTCCTATGA
```
{: .nolineno }

The challenge also has the following instructions  _There are some pretty unusual encoding methods. Find the flag PS: Replace spaces with “_”_

From research this seems to be some kind of DNA type of encryption. I also learnt that I need to break the string into 3s, so that made it look like this:

```bash
TCA TAG GCT AGC TAC ACT CGT TGT ACA CTA GAC AGC TAC ACT CTC TGA AGC TAG CTA TGA AGC GTC CTA CTC CTA TGA
```
{: .nolineno }


My team mate shared with me this [site](https://earthsciweb.org/js/bio/dna-writer/index.html?seq=CGTCTAATCATCTGTAGCGTCGATGACTGA#base_to_text) that has mappings that could decode the above string.

The resulting string: `CTF DAHOMEY DANS TES GENES`

I then replaced the spaces (" ") with underscores as per the instructions, then embedded the flag prefix to the string.

`NGCCTF{CTF_DAHOMEY_DANS_TES_GENES}`


## Lettres

### Description

Help me decipher this message: I AZLZH ZFHNZ HFVNYNN FTH YT FNFYZK Y FYZ NWKKF NLH LZ KAHFZZ ATZNZAK NAKYN AZ KAF INY YKHZNFH AYYHZH AX ZHYKY FHHZFYA AZAYVZZ.

Flag format : NGCCTF{}

**Solved & Documented by:** [oste](https://x.com/oste_ke)
----

### Solution

This was preety easy. I used the [cipher-identifier](https://www.dcode.fr/cipher-identifier) to identify the possible cipher used.

![image](https://gist.github.com/user-attachments/assets/45506a60-5630-4e60-9108-c4cb91cd41ef)

I got a strong hit on [Letters Bars](https://www.dcode.fr/letter-lines-cipher). Using this cipher i was able to get the flag as shown:

![image](https://gist.github.com/user-attachments/assets/5d2d653d-3b4a-40ab-9027-af84af2bdd0c)


`NGCCTF{ANOTHERCIPHERTOFIGUREOUT}`


# Reverse Engineering

## AGBA

**Solved & Documented by:** [m3tadr0id](https://x.com/m3tadr0id)

#### Initial Thoughts


The challenge revolves around reversing the password-checking mechanism. We need to identify the hardcoded values used in the XOR operation and figure out how to derive the correct password. The key here is to understand the logic inside the loop and reverse engineer the password transformation.

#### Solution

The code uses an array of 25 predefined values  and a transformation constant `0x4768243`. The password is validated by XORing each character of the password with a value derived from the loop index (i). Specifically, the formula for the transformed index is:

`transformed_index = (i << 2) + transformation_constant`


To get the original character, we reverse the XOR operation:
`original_char = transformed_index ^ var_88[i]`

```python
var_88 = [
    0x0d, 0x77, 0x08, 0x7f, 0x1d, 0x62, 0x6c, 0x2d, 0x57, 0x56,
    0x25, 0x58, 0x46, 0x47, 0x35, 0x3c, 0xf1, 0xb4, 0xbf, 0xb8,
    0xa2, 0xc1, 0xaa, 0xa8, 0xfa
]

transformation_constant = 0x4768243
password_length = 25
password = []

for i in range(password_length):
    transformed_index = (i << 2) + transformation_constant
    input_char = transformed_index ^ var_88[i]
    input_char = input_char % 256
    password.append(chr(input_char))

password_str = ''.join(password)
print(password_str)
```
{: .nolineno }


`NGCCTF{N0C0N57r41N750NCr3471V17Y}`


## Custom Encryption

### Description

**Solved & Documented by:** [m3tadr0id](https://x.com/m3tadr0id)

### Solution

The encryption process involves:

* XORing each character with a fixed key (key1).
* Performing a circular left shift on the result.
* Adding 42 and applying modulo 256 to ensure the result stays within byte limits.
* Inverting the binary representation of the result.
* Our job is to reverse these steps and decrypt the flag.



To decrypt the flag, we must reverse the encryption process. We analyze the steps involved and reverse each one:

* Invert the Binary: First, we invert the binary string (flip 1s and 0s) to undo the inversion performed during encryption.
* Binary to Integer: Convert the inverted binary string back to an integer.
* Undo Modulo Addition: Subtract 42 from the result to reverse the addition during encryption.
* Circular Right Shift: Reverse the left circular shift by performing a right circular shift by 5 positions.
* XOR with Key: Finally, XOR the result with key1 to recover the original character.

```python
def decrypt_c(encrypted_text):
    decrypted_text = ''
    key1 = 0b1101101
    key2 = 5

    encrypted_chunks = encrypted_text.split()

    for chunk in encrypted_chunks:
        inverted_binary = ''.join('0' if bit == '1' else '1' for bit in chunk)
        encrypted_char = int(inverted_binary, 2)
        encrypted_char = (encrypted_char - 42) % 256
        encrypted_char = (encrypted_char >> key2) | (encrypted_char << (8 - key2)) & 0xFF
        original_char = chr(encrypted_char ^ key1)
        decrypted_text += original_char

    return decrypted_text

flag_binary = "00010000 10101110 01110000 10001111 11110000 01010000 10110000 10001111 01001010 01110001 00101110 11010010 10101110 10001111 00001110 11010100 01110001 10101110"

decrypted_flag = decrypt_c(flag_binary)
print(decrypted_flag)
```
{: .nolineno }


`NGCCTF{CTF_BAD_1NPuT_SeNT}`


# Web

## Login1

### Description

Will you be able to connect?

`http://ctf.nextgencyber.africa:2400`

**Solved & Documented by:** [B0nf4c3](https://x.com/B0nf4c3)

### Solution

This is a simple web challenge that tests your ability to analyze the source code and some decoding.

Visiting the link we get a log in page.

![image](https://gist.github.com/user-attachments/assets/129cb3e3-7fda-4216-86a1-570a15d1fe41)

The page doesn't have much for we cannot register an account but only login.

At this point we can try some default creds but they don't work here also sql injection :(

Viewing the source code we get that a javascript code is being used for verification.

![image](https://gist.github.com/user-attachments/assets/6b86e9c2-50bf-42d5-9648-331ea6f53914)

But is it that easy?? Let's see :)

Reading the code we get the email address

![image](https://gist.github.com/user-attachments/assets/98bdcda1-0c51-4565-81f8-78ccfd804331)

But the password is no where to be found.
Let's Visit the developer options to see if we can manipulate the request to bypass the password verification function.
The request seems very solid and hard to tamper with,still at developer options let's see if we can get html code for the sigup button.
But to our suprise we get an ecoded text that was not visible in the soure code.

![image](https://gist.github.com/user-attachments/assets/593160e0-12ea-4594-923d-9a76920b70b1)

Decoding we get what looks like the password.

![image](https://gist.github.com/user-attachments/assets/b9f30358-4a29-42b9-b058-6bd6c5f4b346)

Lets login using the creds

```
email : admin@hackerlab.bj
password : 61239yKJc3r74UKRXJAalGN99wOqVo
```
{: .nolineno }

![image](https://gist.github.com/user-attachments/assets/96b08858-6c19-4d6e-b093-ca08fedb158f)

Easy peasy...:)....


`NGCCTF{J5_@uth_based_g0O0O0OO0Oes_wR0ng}`


<!-- # Misc

## Design 

### Description

Can you sculpt me ?

### Solution -->