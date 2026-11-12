# Ai.Tlbx.Sip

Build with the .NET 11 SDK / C# 15. Both libraries, protocol tests and console target net10.0 and net11.0; run verification on both targets. Keep `Ai.Tlbx.Sip` independent of AI providers and audio-device APIs; the VoiceAssistant adapter is a separate project.

Implement protocol behavior from the RFCs. Preserve native SIP status codes alongside application-level states. `Connected` means authenticated registration and incoming-call readiness, maintained by monitoring and renewal.

Keep all audio, jitter and transaction buffers bounded. Preserve resampler/codec state across frames. Use platform cryptographic primitives and verify protocol-level encryption against independent vectors. Never disable TLS hostname or certificate validation.

Run the executable protocol/media tests on Windows and Linux after relevant changes. Keep mock tests, real PBX registration, real call/audio acceptance, GitHub publication and NuGet publication distinct in reports and the README.
Media regressions must cover early RTP before the final answer, bounded recovery from bursts, and speech resuming after silence suppression. RTP sequence numbers advance per transmitted packet, never per playout tick.
AI playback regressions must burst more audio than the SIP transmit queue can hold and verify every section in order in received RTP. A short tone or nonzero packet count does not prove a complete response. Interruption and drain checks must include adapter and SIP queues.
Call cancellation must complete the remote protocol cleanup, including a racing answer and repeated final responses. A completed readiness task from an earlier connection must never satisfy ConnectAsync while reconnecting or after registration expiry.
Hangup waits must terminate when answer/ACK processing times out or the call ends. Caller cancellation must not abandon call-owned wire cleanup, and teardown must prevent a later Established transition.
Call setup checks must cover native invalid-destination replies and progress-only deadlines. Timeout cleanup must ACK the final non-2xx INVITE response while preserving Timeout as the public outcome; demo teardown must retain the original call error.

Never commit credentials, live phone numbers, private PBX traces or audio recordings. Test configuration belongs outside the checkout. Public documentation is English. Update `Agents.md` and `CLAUDE.md` together.
