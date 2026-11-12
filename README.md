# Ai.Tlbx.Sip

Managed SIP clients with observable connection state, call objects, and bidirectional PCM audio for Windows and Linux.

The SIP library handles telephony. Applications decide whether to connect a call to an audio device, a recorder, or an AI voice assistant. Multiple independently authenticated SIP identities can run in the same process.

> **Early development.** The current implementation passes local protocol and media tests against a simulated PBX. Real FRITZ!Box and easybell interoperability, security review, and broader failure-mode coverage are still pending. Do not treat this initial implementation as production-ready.

## Projects

| Project | Purpose |
| --- | --- |
| `Ai.Tlbx.Sip` | SIP registration, call control, RTP/SRTP, PCM audio, and live metrics. No AI or audio-device dependency. |
| `Ai.Tlbx.VoiceAssistant.Sip` | A per-call `IAudioHardwareAccess` adapter for [Ai.Tlbx.VoiceAssistant](https://github.com/tlbx-ai/Ai.Tlbx.VoiceAssistant). |
| `SipConsole` | Explicitly controlled registration, incoming/outgoing calls, and optional audio echo. |

Uses .NET 11 and C# 15. The current SIP core has no third-party package dependencies. The VoiceAssistant adapter references the published VoiceAssistant package. No native SIP/media binary, FFmpeg, ALSA, or Windows audio API is required by these libraries.

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

`TryWrite` copies/resamples accepted samples and returns `false` when the bounded transmit queue cannot accept the input. It never waits indefinitely for a slow peer. RTP transmission is paced at 20 ms; missing output is filled with silence. The streaming windowed-sinc resampler retains filter history and fractional phase across input chunks and supports upsampling, downsampling, and non-integer ratios.

Call metrics expose transmitted/received packets and bytes, playout loss, duplicate/late packets, estimated jitter, queue duration, and underruns. RTT is currently `null`: RTCP reporting is not implemented yet. Metrics events are emitted once per second. Event handlers must return promptly and must not synchronously wait for protocol operations.

## VoiceAssistant adapter

```csharp
using Ai.Tlbx.VoiceAssistant.Interfaces;
using Ai.Tlbx.VoiceAssistant.Sip;

await using var hardware = new SipAudioHardwareAccess(call);
IAudioHardwareAccess audio = hardware;
// Supply audio to your application's VoiceAssistant composition.
```

Create one adapter per call. It converts PCM16 to/from the VoiceAssistant base64 interface and resamples received audio to the requested provider input rate. Disposing the adapter stops its reader; call ownership remains with the application.

## Transport and security

- SIP over UDP, TCP, or TLS. TLS uses normal certificate/hostname validation and allows TLS 1.2/1.3.
- Digest authentication: MD5 and SHA-256, including `-sess`, with `qop=auth` or legacy no-qop challenges.
- G.711 PCMA/PCMU, RTP, bounded receive buffering, and 24-kHz PCM conversion.
- Optional SDES-SRTP using `AES_CM_128_HMAC_SHA1_80`, authenticated packets and a replay window. SDES is accepted only with TLS signalling; encryption downgrade is rejected.
- Credentials and SDP key material are not emitted in diagnostic events. Keep secrets out of source control and application logs.

Configure encrypted media explicitly:

```csharp
Transport = SipTransportProtocol.Tls,
MediaSecurity = SipMediaSecurity.SdesRequired
```

Currently unsupported: DTLS-SRTP, SRTCP, G.722/Opus, DNS NAPTR/SRV discovery, ICE/STUN/TURN, session timers, reliable provisional responses/PRACK, hold/re-INVITE, transfers, and forked-dialog handling. The endpoint targets direct PBX registration rather than implementing a SIP proxy or registrar. Plain RTP/SDES support does not imply WebRTC compatibility.

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

Optional flags: `--probe` registers then disconnects; `--echo` echoes received audio; `--auto-answer` explicitly enables answering incoming calls; `--srtp` requires SDES-SRTP. Set `SIP_TRANSPORT=Tls` for TLS. No outbound call is made automatically.

FRITZ!Box: create an IP telephone in the router's telephony settings and use its dedicated credentials. Start on the same LAN. See [FRITZ!Box setup](https://fritz.com/apps/knowledge-base/FRITZ-Box-4050/42_ip-telefon-an-fritz-box-anmelden-und-einrichten).

easybell Cloud PBX is an intended interoperability target, using its endpoint credentials rather than SIP-trunk credentials. easybell documents `pbx.easybell.de` and TLS on port 5061, with SRTP for encrypted media. DNS-SRV discovery and real-provider acceptance remain open. See [easybell endpoint/security settings](https://www.easybell.de/hilfe/ergebnis/voip-experteneinstellungen/).

## Build and verify

```sh
dotnet build Ai.Tlbx.Sip.slnx -c Release
dotnet run --project tests/Ai.Tlbx.Sip.Tests -c Release
dotnet pack src/Ai.Tlbx.Sip -c Release -o artifacts
dotnet pack src/Ai.Tlbx.VoiceAssistant.Sip -c Release -o artifacts
```

The dependency-free test runner returns a nonzero exit code on failure. It covers framing, parser rejection, G.711 values, resampling continuity and anti-aliasing, RFC 3711 key-derivation vectors, SRTP tamper/replay rejection and rollover, registration/authentication, UDP retransmission, call setup/teardown, duplicate INVITEs, PCM flow, and the VoiceAssistant adapter. Windows builds and tests have been run locally. A Windows/Linux CI template is provided in `.github/verify-workflow.template.yml`; enabling it requires moving it into `.github/workflows/verify.yml` with a GitHub credential authorized to write workflows. Linux execution is not yet verified. No PBX credentials or paid AI calls are needed.

Implemented from protocol specifications: [SIP](https://www.rfc-editor.org/rfc/rfc3261), [transaction corrections](https://www.rfc-editor.org/rfc/rfc6026), [SDP offer/answer](https://www.rfc-editor.org/rfc/rfc3264), [RTP](https://www.rfc-editor.org/rfc/rfc3550), [SRTP](https://www.rfc-editor.org/rfc/rfc3711), and [SDES](https://www.rfc-editor.org/rfc/rfc4568).

## License

[MIT](LICENSE).
