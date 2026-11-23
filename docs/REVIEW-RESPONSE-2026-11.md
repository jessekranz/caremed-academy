# Response to William Murray's review notes (November 2026)

This document goes through each of William's notes on the preview site and the secure portal. For each one it says what was changed and what CareMed still has to decide. Anything marked **Decision needed** is a policy or content call for CareMed, not something the software can settle.

## 1. A summary of what the academy does and does not do, with an outline and timeline

**Changed.** The preview now has an **About this academy** page, opened by clicking the logo in the top-left corner (or the new menu item under Overview). It contains:

- a "demonstration platform" notice at the top;
- what the academy does, and what it does not do (it is not HFS-approved training, not a certification, gives no clearance for trips, is not manufacturer-approved, and teaches no medical care);
- the syllabus: the 18 lessons grouped by track, with planned minutes (about 7 h 46 min of study, plus about 30 minutes of simulations and 30 minutes for the exam);
- the 10 onboarding steps in order, with who does each one and an estimated time for each.

**Decision needed.** The time estimates in the onboarding timeline are placeholders. CareMed should confirm the ones it controls, such as document verification, supervised training and compliance approval.

## 2. The 12-second videos are two or three times too fast

**Changed.** The three briefings now play at 0.4× speed, so each runs about 30 seconds and each caption screen stays up for roughly 7 seconds. This applies on the Visual studio page, inside the lessons, and on the secure portal's media page. Viewers can still pause at any point. Downloaded copies play at the original speed.

**Still to do.** Slowing playback also slows the motion, which can look sluggish. The better long-term fix is to re-cut each video so the motion runs at normal speed and every caption screen holds for 5–8 seconds. That needs the original source files or a video editor; the full-length videos planned in `VIDEO-PRODUCTION-BOOK.md` should be cut that way from the start.

## 3. "Field simulations" duplicated the Visual studio

**Changed.** The separate menu item is gone. The menu item is now **Visual studio & simulations**, and that page shows all five simulations with their completed/not-completed status. Links that used to go to the simulations page now go there.

## 4. The "Management" section is not for students

**Changed.** **Instructor & compliance** and **Regulatory library** have been removed from the driver menu. They are now linked from a "For CareMed staff" section at the bottom of the About page, and each carries a "CareMed staff page, not part of driver training" banner. In the secure portal these pages were already limited to staff by role.

## 5. Lesson 1: where is the line on helping with medication?

**Changed (as a draft).** Lesson 1 has a new section, "Medication: helping versus administering", marked **DRAFT POLICY, pending CareMed approval**:

> You may give simple help that is not medical while the passenger stays in charge of their own medication: handing them their bag, opening a bottle or container they ask you to open, or holding a cup of water. You must not choose a medication or dose, put medication into the passenger's hand or mouth for them, give injections, inhalers or eye drops, or decide whether they should take something. If the passenger seems confused, drowsy or unable to direct their own care, do not help: park safely and contact dispatch. Call 911 for any emergency.

The first Lesson 1 question now tests exactly this grey area: an alert passenger asks the driver to open a pill bottle and hand over water. The exam adds a clear "do not" case: a passenger asks the driver to give an insulin injection.

**Decision needed.** CareMed must approve, change or replace this policy, ideally after checking with legal counsel and the payer contracts (some Medicaid or facility contracts are stricter). Points to settle:

- Is opening a container and handing over water allowed, or should drivers keep their hands off anything to do with medication?
- How should a driver judge that the passenger is "directing their own care"? Is it the driver's call, or should they ask dispatch every time?
- Should the driver log every such request?

## 6. Lesson 2, question 3: onboarding should make this question moot

**Changed.** The question no longer asks drivers to judge local licensing law. The lesson now says CareMed checks each driver's local licenses before assigning trips in an area. The question asks what the driver does if that check fails: they are offered a Chicago trip without a verified Chicago license (answer: decline it, tell dispatch, and send the license to compliance).

**Still to do.** The secure portal already records local permits as extra credentials, but no trip assignment system exists yet. Making the question fully moot needs the dispatch integration to refuse a trip in an area where the driver's local license is not verified, in the same way `GET /transport-authorization` already blocks drivers who have not finished onboarding.

## 7. Lesson 17 should not be left in this state

**Changed (holding position).** Lesson 17 now opens with a **Placeholder lesson** warning and a "Status of this lesson" section. Both explain that the trip steps were written before the real CareMed Driver app was reviewed and will be rewritten. It is also flagged PLACEHOLDER in the syllabus. The question that asked drivers whether the app states were "production-verified" (a note for developers, not training) has been replaced with a real safety question (the app shows the ramp is not stowed).

**Decision needed: suggested agenda for the Lesson 17 discussion** with whoever owns the CareMed Driver app:

1. Walk through a real wheelchair trip in the app, screen by screen, and record the actual trip statuses and their names.
2. What does the app do with pre-trip vehicle inspections and defects? Can a driver mark a ramp or tie-down defect, and does that put the van on hold?
3. Does the app have (or will it have) safety confirmations before departure, such as ramp stowed, wheelchair secured and occupant belted?
4. How does the driver report an incident, a destination change or a refused trip through the app?
5. What does the app do while the vehicle is moving: does it lock out typing?
6. Who will supply screenshots for the lesson, and who signs off that the lesson matches the app?

The rewritten lesson should then use real screenshots, and its questions should be about the real screens.

## 8. Is there any real difference between the Knowledge exam and finishing the Learning paths?

There was not. The preview exam reused one question from each lesson quiz word for word, and the portal exam was all 54 lesson questions again, so the exam only tested whether drivers remembered questions they had already passed.

**Changed.** The exam now has its own bank of 18 new scenario questions, one per lesson, none repeated from a lesson quiz. Each one asks the driver to apply the lesson to a new situation (for example a frayed tie-down found on the walkaround, a clinic that is closed at drop-off, freezing rain mid-trip). Questions appear in a random order on both the preview and the portal. Pass rules are unchanged: 90% on the preview, every answer correct on the portal. A test now checks that no exam question repeats a lesson question.

**Decision needed / still to do.**

- The 18 exam questions are drafts and need the same instructor and legal review as the lessons. Question 8 (passenger declines the shoulder belt) depends on a CareMed policy that does not exist yet.
- A stronger exam would draw from a larger pool (for example 3–5 questions per lesson, picking some at random each attempt), limit attempts, and require retraining after a failed attempt. That needs more questions written and approved first.

## Note for the secure portal

Lesson text and lesson questions are copied into the portal's database only when it is first created. A portal database that already exists keeps the old Lesson 1, 2 and 17 content until those changes are applied through a reviewed migration. The new exam bank is copied into an existing database automatically on its next start.
