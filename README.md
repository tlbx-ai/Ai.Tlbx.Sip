# Ai.Tlbx.Sip

Managed SIP clients with observable connection state, call objects, and bidirectional PCM audio for Windows and Linux.

The SIP library handles telephony. Applications decide whether to connect a call to an audio device, a recorder, or an AI voice assistant. Multiple independently authenticated SIP identities can run in the same process.

Version 1.0.0 provides direct PBX registration, incoming/outgoing calls and managed PCM media with explicit lifetime, cancellation and error handling. Protocol/media checks run on Windows and Linux. Real FRITZ!Box acceptance covers registration, incoming/outgoing echo calls, remote hangup and clean unregistration. The VoiceAssistant Web demo has also been tested over a real phone call: long AI answers play completely, and speaking over the agent interrupts playback and changes the conversation topic. See the supported transports and interoperability limits below.

Encrypted RTP/RTCP is verified with local peers and independent numeric reference vectors; encrypted interoperability with a real provider remains unverified. Earlier echo acceptance included clear continuous G.722 audio and roughly one second perceived echo delay; this is not a measured one-way or AI response latency.

## Projects

| Project | Purpose |
| --- | --- |
| `Ai.Tlbx.Sip` | SIP registration, call control, RTP/SRTP, PCM audio, and live metrics. No AI or audio-device dependency. |
| `Ai.Tlbx.VoiceAssistant.Sip` | A per-call `IAudioHardwareAccess` adapter for [Ai.Tlbx.VoiceAssistant](https://github.com/tlbx-ai/Ai.Tlbx.VoiceAssistant). |
| `SipConsole` | Explicitly controlled registration, incoming/outgoing calls, and optional audio echo. |

Uses .NET 11 and C# 15. The SIP core references the cross-platform MIT-licensed `NAudio.Core` package for its managed G.722 codec. The VoiceAssistant adapter references the published VoiceAssistant package. No native SIP/media binary, FFmpeg, ALSA, or Windows audio API is required by these libraries.

## Install

```sh
dotnet add package Ai.Tlbx.Sip --version 1.0.0
# Optional AI audio adapter (also installs the SIP core):
dotnet add package Ai.Tlbx.VoiceAssistant.Sip --version 1.0.0
```

Until the initial publication completes, build from source or use the locally verified packages produced by `verify-release.ps1`.

## Create and connect a client

```csharp
using Ai.Tlbx.Sip;

await using var manager = new SipClientManager();
var client = manager.CreateClient(new SipClientConfig
{
    Id = "office",
    Registrar = "fritz.box",
    User = "my-sip-user",
    Credentials = new SipCredentials
    {
        Username = "my-auth-user",
        Password = Environment.GetEnvironmentVariable("SIP_PASSWORD")
            ?? throw new InvalidOperationException("Set SIP_PASSWORD.")
    }
});

client.StatusChanged += (_, status) =>
    Console.WriteLine($"{status.State}: {status.Error}");

await client.ConnectAsync();
```

**`Connected` means operational readiness:** the registrar has accepted the credentials, registration is valid, incoming requests are being processed, and outgoing calls can be started. Registration is refreshed to monitor reachability. An undetected network failure can temporarily precede the corresponding state change; registration alone cannot prove end-to-end audio routing.

`ConnectAsync` completes after successful registration. Cancelling its wait currently cancels the caller's wait, not the client's background connection lifecycle; use `DisconnectAsync` to stop the client. Automatic recovery is configurable. Status snapshots include registration expiry and the latest failure. Configuration is never persisted by the library, and `LoadClients` initializes identities without connecting them.

Each client owns its credentials, authentication state, registration, calls, and media sockets. Removing one identity leaves the others running. Incoming and outgoing call creation share the same atomic `MaxConcurrentCalls` limit.

An expired registration leaves `Connected` even if its refresh request is still waiting for a response. Calling `ConnectAsync` during recovery waits for a new successful registration; a previous connection's completed readiness task is not reused.

```csharp
var clients = manager.LoadClients(configurations);
await Task.WhenAll(clients.Select(c => c.ConnectAsync()));
await manager.RemoveClientAsync("office"); // orderly disconnect and cleanup
```

## Make or receive a call

Create the call before starting it so handlers can be attached first:

```csharp
var call = client.CreateCall("123");
call.StatusChanged += (_, status) => Console.WriteLine(status.State);
call.Ended += (_, status) => Console.WriteLine(status.EndReason);

await call.StartAsync(); // completes when answered, throws if rejected
// ... exchange audio ...
await call.HangupAsync();
```

Cancelling `StartAsync` also cancels the remote call attempt. The endpoint waits for the required provisional response before sending CANCEL, acknowledges the final INVITE response, and closes an answer racing cancellation with ACK followed by BYE. Short-lived bounded transaction/dialog history handles retransmitted final responses after local teardown without creating duplicate BYE transactions.

`TransactionTimeout` defaults to 32 seconds for initial transaction response handling. Once an INVITE receives its first provisional response, `CallAnswerTimeout` applies instead (default: 45 seconds); repeated progress does not extend it. Both deadlines are configurable. Cancellation/timeout performs bounded SIP cleanup, which can add up to a further transaction timeout if the PBX stops responding.

`call.Status.SipStatusCode` and `SipReasonPhrase` retain the PBX response. `404`/`604` (unknown destination), `484` (incomplete number) and other final failures end the call immediately, populate `Status.Error`, and throw `SipException` with the native code. A `100 Trying` or `183 Session Progress` alone is not an accepted call or proof of a valid number; an announcement-only/progress-only exchange eventually ends as `Timeout`. The library cannot determine telephone number validity independently of the PBX/provider response, and does not play pre-answer announcements to the AI.

Incoming calls are delivered as call objects. Answering is always an application decision:

```csharp
client.IncomingCall += (_, call) =>
{
    // Put the call in your application's incoming-call queue/UI.
    incomingCalls.Writer.TryWrite(call);
};

await incomingCall.AnswerAsync();
// Or: await incomingCall.RejectAsync(486);
```

Observe `call.Completion` to wait for final teardown. A retained call object keeps its final status after it has been removed from the client's active collection. Disconnecting a client ends its calls.

Concurrent `HangupAsync` callers share teardown. Cancelling a hangup wait does not abandon the call's protocol cleanup. If an incoming answer never receives ACK, the transaction timeout ends the call and releases hangup waiters.

## Exchange PCM audio

Audio frames contain owned PCM16 mono samples, their sample rate, and their stream position. The default application-facing sample rate is 24 kHz.

```csharp
await foreach (var frame in call.Audio.ReadFramesAsync(cancellationToken))
{
    // Forward frame.Samples to your audio device, recorder, or processing pipeline.
}

bool accepted = call.Audio.TryWrite(pcm16Samples, sampleRate: 24000);
call.Audio.ClearOutput(); // discard queued speech, e.g. when interrupted
bool drained = await call.Audio.WaitForDrainAsync(TimeSpan.FromSeconds(5));
```

`ReadFramesAsync` is a consuming stream: multiple readers distribute frames rather than broadcast them. Use one reader and fan out in your application if needed. The receive queue discards its oldest frames when its bounded capacity is exceeded.

`TryWrite` copies/resamples accepted samples and returns `false` before media starts or when the bounded transmit queue cannot accept the input. It never waits indefinitely for a slow peer. RTP transmission is paced at 20 ms; missing output is filled with silence. The streaming windowed-sinc resampler retains filter history and fractional phase across input chunks and supports upsampling, downsampling, and non-integer ratios. G.722 uses 16-kHz PCM with its required 8-kHz RTP clock; received packet durations are converted to the 20-ms playout cadence.

Call metrics expose transmitted/received packets and bytes, playout loss, duplicate/late packets, estimated jitter, queue duration, and underruns. `Metrics.Control` contains RTCP datagram counters, rejected control packets, control transport errors, the peer's reported cumulative loss/fraction/jitter, and the last report time. These peer-reported values remain separate from local measurements.

`RoundTripMilliseconds` becomes available when a valid peer report acknowledges one of this call's recent sender reports. It uses monotonic elapsed time minus the peer's processing delay; unrecognized report identifiers cannot create a measurement. This is the media-endpoint RTT, not telephone echo latency, audio-buffer delay, or AI response time. It remains `null` until enough report data is available. Metrics events are emitted once per second. Event handlers must return promptly and must not synchronously wait for protocol operations.

Each call reserves an even RTP port and the adjacent odd RTCP port, advertises its control endpoint in SDP, and accepts the remote `a=rtcp` address/port or the standard RTP-port-plus-one fallback. Point-to-point compound SR/RR reports include SDES/CNAME; teardown sends a bounded best-effort compound BYE. `RtcpReportInterval` defaults to five seconds (configurable from one to sixty), with randomized timing and a shorter initial interval. An unavailable RTCP port or malformed control packet does not interrupt RTP audio. RTCP multiplexing is not negotiated.

## VoiceAssistant adapter

```csharp
using Ai.Tlbx.VoiceAssistant.Interfaces;
using Ai.Tlbx.VoiceAssistant.Sip;

await using var hardware = new SipAudioHardwareAccess(call);
IAudioHardwareAccess audio = hardware;
// Supply audio to your application's VoiceAssistant composition.
```

Create one adapter per call. It converts PCM16 to/from the VoiceAssistant base64 interface and resamples received audio to the requested provider input rate. AI output may arrive faster than real time: the adapter retains accepted chunks in order and feeds small slices into the paced SIP queue without discarding their middle. `BufferedAudio` includes both queues. The default limit is one minute of unsent audio; pass `maxBufferedAudio` to configure 20 ms to five minutes. At the limit, `PlayAudio` rejects the entire new chunk and raises `AudioError`. The synchronous provider callback has no asynchronous backpressure contract, so the limit remains explicit. `ClearAudioQueueAsync` atomically clears both queues for interruption; drain waits include both queues. Disposing the adapter stops its reader and sender and clears pending audio; call ownership remains with the application.

## Transport and security

- SIP over UDP, TCP, or TLS. TLS uses normal certificate/hostname validation and allows TLS 1.2/1.3.
- Digest authentication: MD5 and SHA-256, including `-sess`, with `qop=auth` or legacy no-qop challenges.
- G.711 PCMA/PCMU and G.722, RTP/RTCP, bounded receive buffering, and 24-kHz PCM conversion.
- Optional SDES-SRTP/SRTCP using `AES_CM_128_HMAC_SHA1_80`, authenticated packets and independent replay windows. Control traffic uses its own derived keys and packet index; it is never sent in plaintext for an encrypted call. SDES is accepted only with TLS signalling; encryption downgrade is rejected.
- Credentials and SDP key material are not emitted in diagnostic events. Keep secrets out of source control and application logs.

Configure encrypted media explicitly:

```csharp
Transport = SipTransportProtocol.Tls,
MediaSecurity = SipMediaSecurity.SdesRequired
```

Currently unsupported: DTLS-SRTP, RTCP multiplexing, Opus, DNS NAPTR/SRV discovery, ICE/STUN/TURN, session timers, reliable provisional responses/PRACK, hold/re-INVITE, transfers, and forked-dialog handling. The endpoint targets direct PBX registration rather than implementing a SIP proxy or registrar. Plain RTP/SDES support does not imply WebRTC compatibility.

## Try the console

PowerShell:

```powershell
$env:SIP_REGISTRAR = 'fritz.box'
$env:SIP_USER = 'my-sip-user'
$env:SIP_AUTH_USER = 'my-auth-user' # optional if equal to SIP_USER
# Supply SIP_PASSWORD through your environment/secret manager.
dotnet run --project samples/SipConsole
```

Commands: `list`, `call <number>`, `answer <call-id>`, `hangup <call-id>`, `quit`.

Optional flags: `--probe` registers then disconnects; `--echo` echoes received audio; `--auto-answer` explicitly enables answering incoming calls; `--listen-seconds 300` listens for a bounded interval without console input; `--dial <destination>` explicitly starts an outgoing call after registration; `--srtp` requires SDES-SRTP. Set `SIP_TRANSPORT=Tls` for TLS. Outgoing calls require an explicit `call` command or `--dial` argument.

Alternatively, pass `--config /path/to/client.secrets.json`. It accepts the `SipClientConfig` JSON properties, with enum names such as `"Transport": "Udp"`. Keep credential files outside the checkout. Never commit real configuration or credentials.

FRITZ!Box: create an IP telephone in the router's telephony settings and use its dedicated credentials. Start on the same LAN. See [FRITZ!Box setup](https://fritz.com/apps/knowledge-base/FRITZ-Box-4050/42_ip-telefon-an-fritz-box-anmelden-und-einrichten).

easybell Cloud PBX is an intended interoperability target, using its endpoint credentials rather than SIP-trunk credentials. easybell documents `pbx.easybell.de` and TLS on port 5061, with SRTP for encrypted media. DNS-SRV discovery and real-provider acceptance remain open. See [easybell endpoint/security settings](https://www.easybell.de/hilfe/ergebnis/voip-experteneinstellungen/).

## Build and verify

```sh
dotnet build Ai.Tlbx.Sip.slnx -c Release
dotnet run --project tests/Ai.Tlbx.Sip.Tests -c Release
dotnet pack src/Ai.Tlbx.Sip -c Release -o artifacts
dotnet pack src/Ai.Tlbx.VoiceAssistant.Sip -c Release -o artifacts
```

The test runner requires no test framework and returns a nonzero exit code on failure. It covers framing, parser rejection, G.711 values, resampling continuity and anti-aliasing, RFC 3711 key-derivation vectors, SRTP tamper/replay rejection and rollover, registration/authentication, UDP retransmission, TCP stream fragmentation, contact selection, registration expiry/recovery, refresh/disconnect ordering, call setup/teardown, cancellation/acceptance races, late final responses, duplicate INVITEs, invalid destinations, progress-only timeouts and their final ACKs, early-media backlog, silence suppression, PCM flow, G.722, minimum-size transmit buffers and the VoiceAssistant adapter. TLS tests exchange SIP over real encrypted loopback connections and verify rejection of unknown certificate authorities and wrong hostnames, using an ephemeral test CA without changing machine trust stores. Builds and tests run on Windows and Debian Linux without PBX credentials or paid AI calls. The VoiceAssistant demo's additional local-peer tests verify complete ordered RTP sections for an AI burst longer than the SIP transmit buffer.

Run `pwsh ./verify-release.ps1` for the release gate: build, protocol/media checks, both packages, identity/license/dependency checks, and a fresh-cache consumer outside the repository without project references. Packages and SHA-256 verification metadata are written under `artifacts/release/<version>/`. GitHub `verify.yml` runs this gate on Windows and Linux.

## Publishing

`publish-nuget.yml` is manual (`workflow_dispatch`), accepts the exact committed stable version, and only runs from `main`. It requires the Windows/Linux release gates before the publishing job can obtain a short-lived NuGet credential. The `publish` input defaults to `false`: this verifies both platforms and the real NuGet OIDC login without submitting packages. Set it to `true` only for the actual publication. The GitHub environment is `nuget`; the NuGet Trusted Publishing policy must match owner `tlbx-ai`, repository `Ai.Tlbx.Sip`, workflow filename `publish-nuget.yml`, environment `nuget` and package owner `Ai.Tlbx`. A package glob `Ai.Tlbx.*` covers both packages. No long-lived NuGet API key is required. Preparing or verifying packages does not publish them.

RTCP/SRTCP coverage includes independent libSRTP numeric encryption fixtures, signed cumulative loss and sequence rollover, NTP/report fields, monotonic RTT excluding remote processing delay, explicit SDP control endpoints, UDP port-pair release, actual encrypted and plaintext loopback exchanges, malformed-control rejection, and uninterrupted RTP when the remote RTCP port is closed. Only numeric reference data is used from [libSRTP's interoperability tests](https://github.com/cisco/libsrtp/blob/main/test/srtp_driver.c); the implementation is written against the RFCs.

Implemented from protocol specifications: [SIP](https://www.rfc-editor.org/rfc/rfc3261), [transaction corrections](https://www.rfc-editor.org/rfc/rfc6026), [SDP offer/answer](https://www.rfc-editor.org/rfc/rfc3264), [RTP](https://www.rfc-editor.org/rfc/rfc3550), [SRTP](https://www.rfc-editor.org/rfc/rfc3711), and [SDES](https://www.rfc-editor.org/rfc/rfc4568).

## License

[MIT](LICENSE).
