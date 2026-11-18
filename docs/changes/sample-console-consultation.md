# SipConsole: consultation fixes and a second-REFER test

Change proposal for the `samples/SipConsole` sample only. It follows up on [blind and attended transfer](transfer-refer.md).

| | |
|---|---|
| Base | `533f4e2` (11.13.0). |
| Scope | `samples/SipConsole/Program.cs`, README, this file. The libraries are unchanged. |
| Public API | None. |
| Behaviour change | `--attended-test` accepts a comma-separated target list, paces its hold tone, clears the transmit queue before resuming and stops ringing when the caller hangs up. New flag `--refer-twice`. |
| Verification | Build on net10.0 and net11.0. Real-PBX tests at easybell Cloud PBX, see below. |

## Why

Tests of 11.13.0 against a real PBX showed three problems in the `--attended-test` demo and one open question in the library:

1. **Echo delayed by about 2.8 s after taking the caller back.** The hold-tone loop wrote frames as fast as `TryWrite` accepted them, so the transmit queue filled up to `MaxQueuedAudio` (3 s). After `ResumeAsync` every echoed frame queued behind the remaining tone, and because the echo writes at the same rate as it plays, the delay never shrank (`queue=2820ms` until hang-up).
2. **The consultation target kept ringing after the caller hung up**, until the 20 s answer timeout ran out. The demo then tried to resume a call that had already ended.
3. **Only one consultation target.** A receptionist usually tries a second colleague when the first does not answer.
4. **No way to send two REFERs in one dialog**, so the `Event: refer;id=<CSeq>` correlation introduced in 11.13.0 (RFC 3515 section 2.4.6) could not be tested against a PBX for a second subscription.

## What changes

`samples/SipConsole/Program.cs`

- **Paced hold tone:** the loop only writes the next frame while `call.Audio.QueuedAudio` is at most 100 ms.
- **Clear before resume:** `call.Audio.ClearOutput()` drops the remaining hold tone before `ResumeAsync`, so audio sent after resuming is not delayed.
- **Caller hang-up cancels the consultation:** a token linked to the caller's `StatusChanged` (`Ended`) cancels the ringing consultation call at once. If the caller is gone, nothing is resumed.
- **Target list:** `--attended-test <target>[,<target>...]` consults the targets in order. A target that does not answer within 20 s is cancelled and the next one is called. If none answers, the caller is taken back.
- **`--refer-twice <first> <second>`** (incoming calls): five seconds after establishment, REFER to `<first>`. The first target is meant to fail, for example a `sip:` URI with a `Replaces` parameter that matches no dialog. If the call is still up, a second REFER to `<second>` is sent three seconds later in the same dialog and the outcome is printed with its duration.

Applications that hold a caller and play their own audio should follow the same two rules: keep only a small lead in the transmit queue while on hold, and call `ClearOutput()` before resuming.

## Real-PBX results (easybell Cloud PBX)

Same test endpoint as in the earlier changes (dedicated extension, TLS 5061, SDES-SRTP), caller on a mobile phone, targets on desk phones of the same PBX. All results were confirmed by the person on the phone.

| Test | Result |
|---|---|
| `--attended-test <A>,<B>`: A does not answer, B answers | A cancelled after 20 s, B called, REFER with Replaces answered with NOTIFY `200 OK`, mobile and desk phone connected. A cancelled consultation does not affect the later transfer. |
| `--attended-test <A>,<B>`: nobody answers | Caller taken back, echo without delay; transmit queue 100 to 120 ms while on hold, 20 to 40 ms after resuming (before: 2980 ms and 2820 ms). |
| `--attended-test <A>,<B>`: caller hangs up while A rings | A's consultation call cancelled immediately, B not called, no resume attempted. |
| `--refer-twice` (Replaces without dialog, then an extension) | First REFER: NOTIFY `100`, then `404 Not Found`, call stays up, outcome `Failed 404`. Second REFER: NOTIFY `100`, `180`, `200`, transfer carried out by the PBX, but `TransferAsync` returned `Unknown` after 0.2 s (see below). |

### PBX observation: no `id` parameter

easybell sends every NOTIFY of the REFER subscription with a bare `Event: refer`, without the `id` parameter, also for the second REFER in a dialog. Examples:

- `Event: refer` / `Subscription-State: active;expires=599` / sipfrag `SIP/2.0 100 Trying`
- `Event: refer` / `Subscription-State: terminated;reason=noresource` / sipfrag `SIP/2.0 200 OK`

Since 11.13.0 a missing `id` is only accepted for the first REFER in a dialog. The NOTIFYs of the second REFER are therefore rejected, and the result is `Unknown` although the transfer worked. Here it ended after 0.2 s only because the PBX then sent BYE; otherwise the call would have waited for the full timeout. A possible library change (not part of this proposal): also accept a missing `id` when the subscription of the previous REFER has already ended.

For a blind REFER the PBX also sends the final `200 OK` sipfrag when the target starts ringing, not when it answers.
