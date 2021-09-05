---
Challenge Name: Tampered
Category: Forensics
Difficulty: Medium
---

This challenge was a continuation of Tampered.

**Challenge Description**
```
Our Employee finally realized his wrong doings and he confessed that he was going to 
attack the company infrastructure from a remote computer we need you to further investigate this matter 
and figure out what was he doing on the remote computer.

Note : Challenge File is same as Tampered Challenge.
```

So, after doing autopsy we had got two software Anydesk and teamviewer.But in the files of these we had nothing useful.
Anydesk had a private key  and an ip but it was a rabbit hole.

So, I searched for RDP cache and found a blog 

https://nasbench.medium.com/windows-forensics-analysis-windows-artifacts-part-i-c7ad81ada16c#:~:text=RDP%20Cache%20Forensics%20Sometimes%20attackers%20use%20RDP%20to,we%20are%20connect%20to%20that%20are%20rarely%20changing.

Hence I extracted the cache files 

![](/confession1.png)

Tranferred them to linux and stored them in a folder.Then, ran the BMC script from github https://github.com/ANSSI-FR/bmc-tools 
and it extracted a lot of bmp images from these cache.

![](/confession2.png)


![](/confession3.png)

Oberving these images I found that some images contains part of the flag.I found and joined them in proper order to get the flag

![](/confession4.png)


**GrabCON{RDP_Cach3_4nalysis_1s_Aw3s0me}**
