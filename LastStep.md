---
Challenge Name: Last step
Category: Forensics
Difficulty: Medium
---

```
While making the second challenge for me she created an account on some website but something went wrong and almost all
her account got compromised now she needs my help for resolving this issue also she left some clue in the file that she created before.
I need your help to investigate it further.
```
In this challenge I used enumerate files plugin and grep for string backup and got a file backup.hidden

![](/laststep.png)

Then extracted it to get a mega.nz link and it was a firefox profile backup

![](/laststep2.png)

Then, used firefox decrypt.py to get the flag

![](/laststep3.png)

**flag :GrabCON{d0n't_try_t0_l0gin_with_this_p4ss}**
