---
Challenge Name: First step
Category: Forensics
Difficulty: Medium
---

Challenge Description
```
My friend created a challenge for me and she wants me to find some information inside the memory dump but i don't have any clue about it so i need your help for finding the information.

    1.She Created Some file what is the name of the file ? For example : test
    2.What was the content inside it ? For example : randomtextforexample

Example Flag : GrabCON{test_randomtextforexample}

Author : White_Wolf#9361
```
Basically it was a challenge in which we had to learn how to build linux profile in volatility
If you have no prior knowledge please watch this it will help

https://www.youtube.com/watch?v=qoplmHxmOp4&ab_channel=DFIR.Science

Following the steps of this and formed the latest Ubuntu 4.15.0 generic profile.Then uploaded the zip to 

![](/firststep3.png)

then, I ran volatility with profile=LinuxUbuntu_4_15_0-112-generic_profilex64

![](/firststep1.png)

![](/firststep2.png)

And we have the file welcome and the content: 402051f4be0cc3aad33bcf3ac3d6532b


**flag : GrabCON{welcome_402051f4be0cc3aad33bcf3ac3d6532b}**
