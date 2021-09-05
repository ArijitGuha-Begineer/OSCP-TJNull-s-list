---
Challenge Name: Tampered
Category: Forensics
Difficulty: Medium
---

**Challenge Description**
```
In our company we caught one of the employee tampering a file so we took a some backup from his computer and now we need your help to figure few things.

    1.Name of the new file which our employee was tampering. Example : "important note.txt"

    2.Which tool he was using ? Example : random.exe

    3.What was the changed timestamp on the new file? Example : 2001-01-27_23:12:56 (YYYY-MM-DD)

    4.Content inside the file? Example : e977656fea7ea5b9a8887ecf730860af

Example Flag : GrabCON{important_note.txt_random.exe_2001-01-27_23:12:56_e977656fea7ea5b9a8887ecf730860af}
```



We were given a E01 file.Ran autopsy and the first thing I did was searching some txt files by extension and I got some important info in 
console history

![](/tamperd1.png)

They were running timestomp.exe to change the timestamp of don't open it.txt and then renamed it to don't open it.hidden

When I read about timestomp from this blog https://niiconsulting.com/checkmate/2006/06/timestompexe/ 
I got that it was a metasploit module used to change timestamp of all four attributes of NTFS and -z sets all four attributes (MACE) of the file
This gives answer to most of our questions
as we got 
**name of the new file: don't open it.hidden**(PART-1)

**Application used for tampering:timestomp.exe**(PART-2)


Now I searched for don't open it.hidden

![](/tamperd2.png)

and got the **contents of the file: 6b751689f3cdaed05e552eff51115684**(PART-4)

Now I tried the timestamp of the file and the timestamp in the console as well but nothing worked

So, I searched for timestomp artifacts and got https://forensicnoobsecurity.blogspot.com/2019/03/detecting-timestomped-values-cal-poly.html
which says that analysing MFT might help

Hence, I extracted the MFT file 

![](/tamperd3.png)

Tranferred it to my linux machine and used the github tool https://github.com/dkovar/analyzeMFT to analyse the MFT with the command

```./analyzeMFT.py -f MFT -o MFT.csv -e``` extracted the csv file.

checking the timestmap of the file in the csv 

![](/tamperd4.png)

we get the 

**timestamp of the new file: 1969-08-10 16:33:33**(PART-3)

Now combining all the four parts we get out flag

**GrabCON{don't_open_it.hidden_timestomp.exe_1969-08-10_16:33:33_6b751689f3cdaed05e552eff51115684}**

