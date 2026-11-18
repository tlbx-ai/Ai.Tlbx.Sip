# Blind and attended transfer (REFER)

Change proposal for `Ai.Tlbx.Sip`. It builds on [hold, resume, session refresh and media source switching](hold-session-refresh-media-source.md); attended transfer needs local hold.

| | |
|---|---|
| Base | `31cbfa9` (11.12.0) plus the hold/session-refresh change. |
| Scope | Core library `Ai.Tlbx.Sip`, protocol tests, SipConsole sample. The VoiceAssistant adapter is unchanged. |
| Public API | Additive. `SipCallEndReason` gains the member `Transferred`; code that switches exhaustively over the enum needs a new case. |
| Behaviour change | In-dialog `NOTIFY` for the `refer` event package is accepted (other event packages get `489 Bad Event`; before, every NOTIFY got `405`). |
| Verification | Protocol tests 41/41 on net10.0 and net11.0 (Windows). Real-PBX acceptance at easybell Cloud PBX, see below. |

## Why

An AI receptionist must hand a caller over to a colleague. Two forms are needed:

- **Blind transfer:** the AI passes the caller on without talking to the colleague first, for example to a group number.
- **Attended transfer:** the AI holds the caller, calls the colleague, announces the caller and joins both only when the colleague agrees. If the colleague declines or does not answer, the AI takes the caller back. No caller is lost.

With REFER the PBX joins the two parties itself. The AI then leaves both calls and holds no media or channels for the rest of the conversation. Without REFER the application would have to bridge the audio of both calls for the whole conversation.

## What changes

### 1. Blind transfer (RFC 3515, RFC 5589 section 6)

`SipCall.cs` (`TransferAsync`, `TransferCoreAsync`, `TransferTargetUri`)

- `TransferAsync(target)` sends REFER in the call's dialog. `Refer-To` is `<sip:target@domain>` for an extension or number (domain = `SipClientConfig.Domain` or the registrar) or the given `sip:`/`sips:` URI. `Referred-By` carries this endpoint's address of record.
- The target is validated: no whitespace, control characters, angle brackets or quotes; an `@` or `:` is only accepted inside a full `sip:`/`sips:` URI.
- After `202 Accepted` the call waits for the final `NOTIFY` of the implicit subscription, at most `CallAnswerTimeout + TransactionTimeout`, because the target may ring before the PBX reports a result.
- `2xx` in the `message/sipfrag` body: this side sends BYE (RFC 5589 section 6) and the call ends with `SipCallEndReason.Transferred`.
- A rejected REFER (`>= 300`), a REFER timeout or a failure status of the target (for example `486`) returns `SipTransferOutcome.Failed` with the status code. **The call stays established with this side.**
- If the PBX ends the subscription or the call without a final status, the result is `SipTransferOutcome.Unknown`.
- REFER and re-INVITE share one lock, so a transfer never overlaps a hold or resume of the same call.

### 2. Attended transfer (RFC 5589 section 7, RFC 3891)

`SipCall.cs` (`TransferToCallAsync`, `ReplacesUri`)

- Typical sequence in the application: `caller.HoldAsync()`, `client.CreateCall(colleague)` and `StartAsync()`, announce over the consultation call, then `caller.TransferToCallAsync(consultation)`.
- The REFER goes into the caller's dialog. `Refer-To` is the consultation call's remote address of record with an escaped `Replaces` header for the consultation dialog: its Call-ID, `to-tag` = the colleague's tag and `from-tag` = this side's tag. RFC 3891 section 3 defines the tags from the point of view of the UA that receives the INVITE with Replaces.
- Both calls must belong to the same `SipClient`, the consultation call must be established, and a call cannot be transferred to itself.
- On success the caller leg ends with BYE as in blind transfer. The PBX normally ends the replaced consultation dialog itself; if it is still open after `TransactionTimeout`, this side hangs it up.
- On failure both calls stay as they are. The application decides what happens next, typically `consultation.HangupAsync()` and `caller.ResumeAsync()`. The library deliberately contains no timeouts or policies for this step: ring time, retries and fallback targets belong to the application.

### 3. NOTIFY for the REFER subscription (RFC 3515 section 2.4.4, RFC 6665)

`SipCall.cs` (`OnNotifyAsync`)

- In-dialog NOTIFY with `Event: refer` is answered with `200 OK`. The first line of the `message/sipfrag` body (`SIP/2.0 <code> <reason>`) is parsed. A status `>= 200` completes the waiting transfer; `Subscription-State: terminated` without a final status completes it as `Unknown`.
- A supplied Event ID must match the current REFER CSeq. For PBXs that omit it, a later bare `Event: refer` can match when each earlier REFER was rejected or its subscription reported termination.
- Any other event package gets `489 Bad Event`.

## Public API additions

| Member | Purpose |
|---|---|
| `SipCall.TransferAsync(string target, CancellationToken)` | Blind transfer to an extension, number or `sip:`/`sips:` URI |
| `SipCall.TransferToCallAsync(SipCall consultation, CancellationToken)` | Attended transfer: join this call's remote party with the consultation call's remote party |
| `enum SipTransferOutcome { Succeeded, Failed, Unknown }` | Result category |
| `record SipTransferResult(SipTransferOutcome Outcome, int? StatusCode, string? ReasonPhrase)` | Result with the native SIP status of the REFER or the target |
| `SipCallEndReason.Transferred` | End reason of a call that was handed over successfully |

## Tests

| Test | Covers |
|---|---|
| Blind transfer by REFER: success ends the leg, busy target or rejected REFER keep the call | `Refer-To` and `Referred-By`, `486` from the target and `403` for the REFER keep the call, invalid targets throw, success ends with `Transferred` and exactly one BYE |
| Attended transfer: REFER with Replaces of the consultation dialog, failure keeps both calls | Escaped `Replaces` with Call-ID and both tags in the correct roles, failure keeps both calls and the hold, success ends the caller leg with `Transferred` and the consultation call by the PBX's BYE |

`TestPbx` accepts REFER with `202`, sends `100 Trying` and a final `message/sipfrag` NOTIFY (configurable status, optional REFER rejection) and, for a successful REFER with Replaces, ends the replaced dialog with its own BYE.

All 41 protocol/media tests pass on net10.0 and net11.0 on Windows. Linux was not run for this change.

## Real-PBX acceptance (easybell Cloud PBX)

Reported separately from the mock tests. Test endpoint: a dedicated extension of the easybell Cloud PBX over TLS 5061 with SDES-SRTP; the caller is a mobile phone dialling in from the public network, the colleague a desk phone on the same PBX.

| Case | Result |
|---|---|
| Blind transfer (`--transfer-test`) | `202`, final NOTIFY `200 OK` after about 0.2 s, BYE sent, desk phone rings, mobile and desk phone connected |
| Attended transfer, colleague answers (`--attended-test`) | caller held with hold tone, consultation call answered, announcement tone heard at the desk phone, REFER with Replaces answered `200 OK` after 0.14 to 0.17 s, the PBX ended the consultation dialog, mobile and desk phone connected directly (tested twice) |
| Attended transfer, colleague does not answer | consultation call cancelled after 20 s, caller resumed by re-INVITE in about 0.1 s, audio back |

In Alexander Kuntze's 11.13.0 easybell retest, the PBX's blind-transfer `200 OK` sipfrag arrived when the target started ringing. `Succeeded` reports the PBX's transfer result. Applications cannot use it as proof that the target answered.

Observation: a plain 440 Hz hold tone was barely audible on the mobile phone while it was clearly audible on the desk phone. Mobile networks and handsets suppress steady tones; real hold music or a spoken announcement is the better choice.

Not yet verified at a real PBX: a REFER rejected by the PBX, a target that is busy, and transfers to Microsoft Teams users connected through the PBX.

## Sample

`samples/SipConsole`:

- `--transfer-test <target>`: five seconds after establishment, blind transfer to the target, result printed;
- `--attended-test <target>` (incoming calls): five seconds after establishment, hold the caller with an interrupted 440 Hz tone, call the target, play a 660 Hz announcement tone for three seconds when it answers, then transfer with Replaces; if the target does not answer within 20 seconds, cancel and resume the caller.

## Known limitations and follow-ups

- Incoming REFER and INVITE with Replaces (the PBX handing a call back to this endpoint) are still rejected (`405`, or `420` for `Require: replaces`).
- Only one transfer per call at a time; the implicit subscription is not refreshed or cancelled actively.
- `Refer-Sub: false` (RFC 4488) is not offered, so the PBX always sends NOTIFYs.
- Caller identity beyond the `From` URI (`P-Asserted-Identity`, `Diversion`, `History-Info`) follows in [caller-identity.md](caller-identity.md).
