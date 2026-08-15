# SHUTDOWN.md: how a session ends

Binding on every lane and on the advisor (AGENTS.md rule 14).

**A session that ends without this is unfinished work, not completed work.** The
difference between the two is invisible to the next session, which is exactly why
this file exists.

Every item below traces to something that actually went wrong in this repository.
None of it is generic hygiene. Where an item cites an incident, that incident cost
real time or produced a false claim on `main`.

---

## The nine checks

Run them in order. Stop and fix rather than noting an exception.

### 1. Push. Everything.

`git status` clean, `git log origin/<branch>..HEAD` empty. Not "committed", **pushed**.

> ADR-0007 once sat uncommitted in a sandbox worktree and had to be rescued.
> Later, 451 lines including two long-outstanding reviews sat committed but
> unpushed on one machine. Both were one power cut from gone.

A draft PR is the cheapest durability there is, and on this repo it is also the
only way a branch gets CI at all: the workflow triggers on `pull_request` and
`push` against `main`, so a branch with no open PR runs nothing.

### 2. Leave your tree clean, and only your tree.

Your worktree has no uncommitted changes. You modified no other lane's worktree
at any point, for any reason, however small the edit or however clean their tree
looked when you started.

> One lane edited another's worktree to fix a one-file CI break. It reported the
> edit honestly and asked before pushing, which is why nothing was lost. When it
> went back to revert, the other lane's staged work was already sitting beside it.
> Clean-at-that-instant is precisely the condition that changes underneath you.

If you need something in another lane's branch, push your own branch and let them
pull it (AGENTS.md rule 1: agents sync only through pushed branches).

### 3. Your status file is on `main`, or in a PR that only needs merging.

Written for a reader with **zero memory**: what is built, what is not, what is
partial, what is blocked and on whom.

> `docs/status/opus.md` sat a week stale on `main` while the real handoff lived on
> an unmerged branch. Rule 2 exists because of that week.

### 4. Report what CI says, not what your machine says.

Give the **run ID and the job verdicts**. If you also ran things locally, say so
separately and never in place of CI.

> One lane reported "fmt + clippy clean" while CI was red. The report was honest:
> the failing file was `cfg`'d out on its platform and local clippy never compiled
> it. Local green and CI red were both true statements about the same commit.

A green check is not evidence. Open the log and confirm the job ran what you
think it ran.

### 5. Say what did **not** run.

Skipped jobs, jobs that cannot trigger, platforms with no runner, tests behind an
`#[ignore]` that nothing executes.

> A CI fix was correctly routed to a branch-targeted PR and therefore could not run
> CI at all, because the workflow only triggers against `main`. The lane caught it
> and said so. Had it not, the next session would have read an empty check list as
> "nothing to worry about."

### 6. Audit the claims you made this session.

For every factual claim you wrote into a committed file, ask whether it is still
true **given what changed this session**. Pay special attention to claims made
true by a contract that moved.

> Accepting ADR-0007 narrowed an acceptance criterion. A test that satisfied the
> old wording silently stopped satisfying the new one at the moment of acceptance,
> and "four of five exit criteria" stayed committed in three files, including the
> README, for two days.
>
> **Narrowing a criterion requires re-auditing everything already counted as
> satisfying it, not just what remains.** Nothing else in this process catches
> that.

This repo has produced documentation asserting things the code does not do at
least six times. It is the single most recurrent defect here.

### 7. Every open item has a named owner.

Not "someone should." A lane, or charge. If two lanes each described half of a
task in compatible language, name who owns the middle.

> Two lanes agreed on a handoff in which one owned the harness wiring "once a
> drivable client exists" and the other owned the proof. Neither had claimed
> building the client. Work that both parties assume the other has does not
> announce itself; it just fails to happen.

### 8. Deferred work gets a gate, not a backlog.

If something is being put off, write the **event that forces it back**: "before
charge declares M2", "before the store merges". A deferral without a gate is a
deletion with extra steps.

> ADR-0006 follow-ups A through D have been "binding, tracked, not started" since
> 2026-07-24.

### 9. Declare branch state.

Which branches you own, which are merged and swept, which are deliberately open
and why. A branch outliving its PR is either unfinished work or litter, and the
two must stay distinguishable (rule 2).

---

## The report

End every session with this, to charge, in this shape. Short is fine. Missing
sections are not.

```
BRANCH:      <name> @ <sha>, pushed / PR #<n> (draft?)
CI:          run <id> — <job: verdict, ...>
DID NOT RUN: <skipped jobs, absent platforms, untriggered workflows>
BUILT:       <what actually works, verified how>
NOT BUILT:   <named, including anything an ADR requires that does not exist>
PARTIAL:     <what is half-done and what the missing half is>
BLOCKED:     <item — on whom>
OWNED NEXT:  <first action next session, specific enough to start cold>
DECISIONS:   <anything needing charge; rule 3 — nothing else authorizes it>
```

**"Done" is a claim about evidence, not about effort.** If the evidence is a
green CI run, cite it. If the evidence is local, say local. If there is no
evidence, the honest word is "written", not "done".

---

## For the advisor specifically

The advisor runs all nine and adds one: **record your own errors in
`docs/status/advisor.md` before recording anyone else's.** An advisor that
verifies others and not itself is a single point of failure wearing a review
process as a costume.

This week's, for calibration: a merge taken without authorization, a correct
citation "corrected" against the wrong file, and a stale exit-criteria count
repeated for two days.
