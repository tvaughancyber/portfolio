---
title: "My OSCP+ Journey: Preparation, Failure, and What Finally Got Me Certified"
date: 2026-06-08
summary: "How I failed the OSCP, what I changed, and what I would tell someone earlier in that same process."
draft: False
---
![OSCP+ Certificate](/img/OSCP_Cert.png)
## 1. Introduction 
I failed the OSCP . . .  *well kinda*. That is where this story actually starts. After failing, I did not immediately reschedule. I took time to figure out where I actually went wrong, fixed those gaps, and came back better prepared. This post covers what changed, what worked, and what I would tell someone earlier in that same process.

## 2. Before You Start: Setting Expectations
The OSCP+ tests your methodology, your persistence, and your ability to document your work clearly enough that someone else could replicate it. That is it. That distinction matters more than people realize. You can know a lot and still fail because you rushed enumeration, skipped steps, or could not put together a coherent report. On the flip side, a disciplined tester with a solid methodology can work through boxes that feel impossible at first.

Before you buy the course, you should be comfortable at the command line on both Linux and Windows, understand basic networking, and have at least some exposure to common tools like Nmap and Burp Suite. You do not need to be an expert. You just need a baseline so the course is not teaching you two things at once.

*On time commitment:* I was working full time throughout my entire prep. That means evenings and weekends. If you are in the same boat, be realistic about your schedule. This is not something you can cram. Budget several months of consistent work and build a pace you can actually hold.

## 3. My Preparation Methodology
TryHackMe was my starting point. If you are newer to the field the guided rooms are good for building foundational skills without the frustration of staring at a blank terminal with no direction. I used it heavily early on before transitioning to Hack The Box as my primary platform. [TJ Null's NetSecFocus Trophy Room](https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8) is worth bookmarking during this phase as well. It is a community maintained list of OSCP relevant machines across both THM and HTB that takes a lot of the guesswork out of what to work on.

Once I moved to HTB, I followed [LainKusanagi's list of OSCP like machines](https://docs.google.com/spreadsheets/d/18weuz_Eeynr6sXFQ87Cd5F0slOj9Z6rt/edit) to guide what I worked through. By the time I sat for my exam I had completed almost all of the Active Directory boxes on the list. Volume on realistic machines builds the pattern recognition that the exam demands.

Standalone boxes are just as important as AD sets. Do not neglect them. That said, make sure you are genuinely comfortable with Active Directory before you sit for the exam. AD is a significant portion of the exam and it rewards repetition more than almost any other skill area.

*Build a methodology notebook.* Keep a living document covering enumeration checklists, privilege escalation paths, AD attack chains, and tool syntax. Every machine you complete should add something to it. When you are hours into an exam box and hitting a wall, a solid checklist to return to is worth more than any single piece of knowledge.
## 4. The PEN-200 Course

I will be honest: I did not lean heavily on the PEN-200 course for my second attempt. My first attempt was over two years before my second and that was the last time I engaged with the material in any real depth. By the time I came back, the volume of HTB work I had put in had already covered most of what the course teaches.

That is not a knock on the course. If you are newer to offensive security, PEN-200 gives you structured coverage of the core topics and that has real value. But do not mistake finishing the course for being exam ready. The course can get you familiar with the concepts. Hands on practice is where you build the muscle memory to actually execute under pressure.

Since my lab time had long expired I did not complete the OSCP labs A, B, or C. From what I have heard those are the closest thing to the actual exam AD environment and I would strongly recommend completing them if your lab access is still active. My biggest struggle during my second round of studying was not having a multi machine AD set that required pivoting and tunneling. HTB standalone boxes and even most HTB AD machines do not replicate that experience well. If I could go back that is the one gap I would have filled differently.

My honest take: *use the course as a foundation, not a ceiling*. Work through the material, do the exercises, and complete the labs while you have access. Just know that the exam requires a level of autonomous problem solving that guided lab work alone will not fully prepare you for.

## 5. The Exam Experience
I cannot discuss exam specifics per OffSec's policy so I will keep this section brief.

Going into my second attempt I felt prepared in a way I did not the first time. That confidence was not arrogance. It came from knowing I had actually done the work. I had a methodology I trusted and enough reps that enumeration felt automatic.

Time management matters more than most people say. The exam is long enough that knowing when to push, when to pivot, and when to step away is its own skill. I took more breaks than I can count on two hands. After making progress I would step away for 5 to 10 minutes to reset before continuing. When I had been stuck for a couple of hours I would take a longer 15 to 30 minute break to fully clear my head. Those breaks were not wasted time. I had 60 points within the first 8 hours and I genuinely believe the breaks contributed to that. Staring at the same box for hours with a frustrated mindset is not productive and you have enough time to afford a reset.

The report is due shortly after the exam ends and it counts just as much as your performance on the boxes so do not treat it as an afterthought going in.

## 6. The Report
The report is not an afterthought. It is half the exam and I treated it that way.

My documentation workflow during practice was built around one principle: *document as if you will not remember anything when you sit down to write*. That means screenshots of every meaningful step, not just the proof of access. It means logging your commands with enough context that you know why you ran them, not just what you ran. If you are doing this right during practice it becomes habit by the time you sit the exam.

During the exam specifically, over-document in the moment rather than trying to reconstruct later. I ended up only using about 70% of the screenshots I took. That is fine. You can cut irrelevant material when you write the report. You cannot recover a missing screenshot of a critical step. I also wrote a rough draft during the exam itself just to make sure I had everything accounted for before my time was up. Once the exam ends you cannot go back. Having even a skeleton of the report written before that clock hits zero takes a lot of stress off the back end.

Practice writing reports even if they never get published and even if they are not perfect. Every HTB machine you complete is an opportunity to practice documenting and reporting a finding. It does not need to be polished. The goal is building the habit of translating your work into something readable. By the time you are writing your exam report it should feel familiar, not foreign.

For the exam report itself I used a structured template and wrote it methodically after the exam concluded. Clear language, logical structure, and enough detail that someone could reproduce every step. That is the standard OffSec expect. Treat it like a professional deliverable because that is exactly what it is.
## 7. Advice by Experience Level
### Complete beginners
Start with TryHackMe. Get comfortable with the command line, basic networking, and common tools before you think about OSCP. Do not rush it. The exam will not hold your hand and neither will the course. Build the baseline first.
### People with Security+ or a network background
You have the foundation. Now you need the offensive mindset. The shift from understanding how something works to understanding how to abuse it is real and it takes time. Start with TryHackMe, move to HTB, and work through a mix of standalone boxes and AD machines before you consider purchasing the course.
### People mid prep who are stuck
Work the list. If AD feels foreign start with the easier ranked AD machines on LainKusanagi's list and work your way up. Do not just root boxes and move on. Read the writeups after, understand the intended path, and compare it to what you did. That comparison is where the real learning happens.
### People who failed once
I have been here. Do not immediately reschedule. Sit with it long enough to do an honest gap analysis. Where did you run out of time? Where did you freeze? What did you avoid because it was uncomfortable? The answers to those questions are your study plan. The path back is specific, not general. *Figure out exactly what failed, fix that thing, and go back*. One failed attempt does not tell you whether you belong in this field. It tells you where your methodology broke down under pressure. That is a solvable problem
## 8. What Comes Next
Passing the OSCP was a milestone, not a finish line. My two main paths forward right now are working toward OSCE3 and exploring the emerging AI security space . AI security is becoming impossible to ignore and getting ahead of it early feels like the right move.

The long term goal is still OSCE3. I am treating it as a multi year commitment and pacing accordingly. There is no point rushing a certification I am not ready for.

Outside of certifications I am building in public. HTB writeups and blog posts documenting what I am learning along the way.
## 9. Conclusion
The OSCP was worth it for me. Not because it opens every door or proves you are elite, but because more than a certification it was a goal I had set for myself. Coming back after a failure, putting in the work, and actually passing taught me something about persistence that I could not have gotten any other way. The methodology discipline, the documentation habits, the hours in front of machines that do not give you easy answers. All of that compounds.

Go in with clear eyes. It is hard, it takes longer than you expect, and you might not pass the first time. I did not. What matters is whether you do the honest work, learn from what goes wrong, and keep going.

If you have questions or just want to talk through your approach feel free to connect and reach out with me on LinkedIn. 
