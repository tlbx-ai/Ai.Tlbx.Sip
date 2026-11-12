using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Ai.Tlbx.Sip;
using Ai.Tlbx.Sip.Media;
using Ai.Tlbx.Sip.Protocol;
using Ai.Tlbx.VoiceAssistant.Sip;

var cases = new (string Name, Func<Task> Run)[]
{
    ("SIP framing, UTF-8, compact and repeated headers", () =>
    {
        var m = new SipMessage { StartLine = "MESSAGE sip:x@example.test SIP/2.0", Body = Encoding.UTF8.GetBytes("Grüße") };
        m.Add("Via", "a"); m.Add("Via", "b");
        byte[] bytes = m.Serialize(); var parsed = SipMessage.Parse(bytes);
        Check.That(parsed.GetAll("Via").SequenceEqual(["a", "b"]));
        Check.That(parsed.Body.SequenceEqual(m.Body));
        Check.That(SipMessage.TryGetLength(bytes.AsSpan(0, bytes.Length - 1), out int length, out _) && length == bytes.Length);
        var compact = SipMessage.Parse("OPTIONS sip:x@example.test SIP/2.0\r\nv: SIP/2.0/UDP host;branch=z9hG4bKx\r\ni: call\r\nCSeq: 1 OPTIONS\r\nl: 0\r\n\r\n"u8);
        Check.That(compact.Get("Call-ID") == "call" && compact.TransactionKey == "z9hG4bKx:1 OPTIONS");
        Check.Throws<InvalidDataException>(() => SipMessage.Parse("OPTIONS sip:x SIP/2.0\r\nContent-Length: 0\r\nl: 3\r\n\r\n"u8));
        Check.Throws<ArgumentException>(() => m.Add("From", "x\r\nInjected: yes"));
        return Task.CompletedTask;
    }),
    ("G.711 published silence and endpoint values", () =>
    {
        Check.That(G711.Decode(0xFF, false) == 0 && G711.Decode(0x7F, false) == 0);
        Check.That(G711.Decode(0x00, false) == -32124 && G711.Decode(0x80, false) == 32124);
        Check.That(G711.Decode(0xD5, true) == 8 && G711.Decode(0x55, true) == -8);
        Check.That(G711.Encode(0, true) == 0xD5 && G711.Encode(0, false) == 0xFF);
        return Task.CompletedTask;
    }),
    ("Resampling preserves stream length and packet-boundary continuity", () =>
    {
        foreach (var rates in new[] { (24000, 8000), (8000, 24000), (16000, 24000), (24000, 48000), (44100, 24000) })
        {
            var input = Enumerable.Range(0, rates.Item1).Select(i => (short)(10000 * Math.Sin(2 * Math.PI * 997 * i / rates.Item1))).ToArray();
            var whole = new PcmResampler(rates.Item1, rates.Item2).Process(input, true);
            var chunked = new PcmResampler(rates.Item1, rates.Item2); var result = new List<short>();
            for (int i = 0; i < input.Length; i += 137) result.AddRange(chunked.Process(input.AsSpan(i, Math.Min(137, input.Length - i))));
            result.AddRange(chunked.Process([], true));
            Check.That(whole.Length == rates.Item2 && result.SequenceEqual(whole), $"{rates} chunk continuity");
        }
        return Task.CompletedTask;
    }),
    ("Downsampling rejects out-of-band energy", () =>
    {
        static double Rms(int frequency)
        {
            var input = Enumerable.Range(0, 24000).Select(i => (short)(12000 * Math.Sin(2 * Math.PI * frequency * i / 24000))).ToArray();
            var output = new PcmResampler(24000, 8000).Process(input, true);
            return Math.Sqrt(output.Skip(100).Take(7800).Average(s => (double)s * s));
        }
        Check.That(Rms(1000) > 8000); Check.That(Rms(6000) < 50, "alias rejection"); return Task.CompletedTask;
    }),
    ("RFC 3711 key-derivation vectors and SRTP replay/authentication", () =>
    {
        byte[] key = Convert.FromHexString("E1F97A0D3E018BE0D64FA32C06DE4139"), salt = Convert.FromHexString("0EC675AD498AFEEBB6960B3AABE6");
        Check.That(Convert.ToHexString(SrtpContext.Derive(key, salt, 0, 16)) == "C61E7A93744F39EE10734AFE3FF7A087");
        Check.That(Convert.ToHexString(SrtpContext.Derive(key, salt, 1, 20)) == "CEBE321F6FF7716B6FD4AB49AF256A156D38BAA4");
        Check.That(Convert.ToHexString(SrtpContext.Derive(key, salt, 2, 14)) == "30CBBC08863D8C85D49DB34A9AE1");
        using var tx = new SrtpContext([..key, ..salt]); using var rx = new SrtpContext([..key, ..salt]);
        foreach (ushort sequence in new ushort[] { 65534, 65535, 0, 1 })
        {
            byte[] packet = Check.Rtp(sequence, (uint)sequence * 160, [1, 2, 3, 4]);
            var encrypted = tx.Protect(packet, 12);
            var corrupt = encrypted.ToArray(); corrupt[^1] ^= 1;
            Check.That(rx.Unprotect(corrupt, 12) is null, "reject tampering");
            Check.That(rx.Unprotect(encrypted, 12)!.SequenceEqual(packet), "rollover/decryption");
            Check.That(rx.Unprotect(encrypted, 12) is null, "reject replay");
        }
        return Task.CompletedTask;
    }),
    ("SDP media selection and encryption downgrade rejection", () =>
    {
        var sdp = Encoding.UTF8.GetBytes(SdpSession.Offer(IPAddress.Loopback, 4000, null, 1));
        var parsed = SdpSession.Parse(sdp, SipMediaSecurity.Unencrypted);
        Check.That(parsed.Codec == "G722" && parsed.SampleRate == 16000 && parsed.Port == 4000);
        Check.Throws<InvalidDataException>(() => SdpSession.Parse(sdp, SipMediaSecurity.SdesRequired));
        Check.That(SipCallAudio.RtpHeaderLength([0x80, 8]) == -1);
        return Task.CompletedTask;
    }),
    ("Manager configuration loading is atomic and credentials redact", async () =>
    {
        await using var manager = new SipClientManager();
        var config = Check.Config(5060); manager.CreateClient(config);
        Check.Throws<ArgumentException>(() => manager.LoadClients([config, config]));
        Check.That(manager.Clients.Count == 1 && !config.Credentials.ToString().Contains("test-password"));
        Check.That(await manager.RemoveClientAsync(config.Id)); Check.That(manager.Clients.Count == 0);
    }),
    ("Multiple identities and concurrent call limits stay isolated", async () =>
    {
        await using var alicePbx = new TestPbx { Username = "alice", Password = "alice-test-password" };
        await using var bobPbx = new TestPbx { Username = "bob", Password = "bob-test-password" };
        await using var manager = new SipClientManager();
        var alice = manager.CreateClient(Check.Config(alicePbx.Port, id: "alice", credentials: new() { Username = "alice", Password = "alice-test-password" }));
        var bob = manager.CreateClient(Check.Config(bobPbx.Port, id: "bob", credentials: new() { Username = "bob", Password = "bob-test-password" }));
        await Task.WhenAll(alice.ConnectAsync(), bob.ConnectAsync());
        var aliceCall = alice.CreateCall("123"); var bobCall = bob.CreateCall("123");
        await Task.WhenAll(aliceCall.StartAsync(), bobCall.StartAsync());
        await manager.RemoveClientAsync("alice");
        Check.That(alicePbx.Unregistered && bob.Status.State == SipClientState.Connected && bobCall.Status.State == SipCallState.Established);
        await bobCall.HangupAsync();
        var attempts = await Task.WhenAll(Enumerable.Range(0, 16).Select(_ => Task.Run(() =>
        {
            try { return bob.CreateCall("123"); } catch (InvalidOperationException) { return null; }
        })));
        Check.That(attempts.Count(c => c is not null) == 4 && bob.Calls.Count == 4);
        await bob.DisconnectAsync(); Check.That(bob.Calls.Count == 0);
    }),
    ("UDP retransmission, SHA-256 authentication and unregister", async () =>
    {
        await using var pbx = new TestPbx { DropFirstRegister = true };
        await using var manager = new SipClientManager(); var client = manager.CreateClient(Check.Config(pbx.Port));
        await client.ConnectAsync().WaitAsync(TimeSpan.FromSeconds(5));
        Check.That(client.Status.State == SipClientState.Connected && pbx.RegisterRequests >= 3 && pbx.AuthenticatedRegistrations > 0);
        await client.DisconnectAsync();
        Check.That(client.Status.State == SipClientState.Disconnected && pbx.Unregistered);
    }),
    ("Registration selects its own contact and disconnect does not renew", async () =>
    {
        await using var pbx = new TestPbx { IncludeExpiredContact = true }; await using var manager = new SipClientManager();
        var client = manager.CreateClient(Check.Config(pbx.Port, keepAlive: TimeSpan.FromMilliseconds(60)));
        await client.ConnectAsync(); await Task.Delay(180);
        Check.That(client.Status.State == SipClientState.Connected && pbx.AuthenticatedRegistrations >= 2);
        await client.DisconnectAsync(); int registrations = pbx.AuthenticatedRegistrations;
        await Task.Delay(150);
        Check.That(pbx.Unregistered && pbx.AuthenticatedRegistrations == registrations);
    }),
    ("Expired registration cannot retain Connected while refresh hangs", async () =>
    {
        await using var pbx = new TestPbx { GrantedExpirySeconds = 1 }; await using var manager = new SipClientManager();
        var client = manager.CreateClient(Check.Config(pbx.Port, keepAlive: TimeSpan.FromMilliseconds(50)));
        await client.ConnectAsync(); var expires = client.Status.RegistrationExpiresAt;
        pbx.DropRegistrationResponses = true;
        await Check.EventuallyAsync(() => client.Status.State == SipClientState.Failed);
        Check.That(DateTimeOffset.UtcNow >= expires && client.Status.Error!.Contains("expired"));
        Check.Throws<InvalidOperationException>(() => client.CreateCall("123"));
        await client.DisconnectAsync();
    }),
    ("ConnectAsync during recovery waits for fresh registration", async () =>
    {
        await using var pbx = new TestPbx(); await using var manager = new SipClientManager();
        var client = manager.CreateClient(Check.Config(pbx.Port, keepAlive: TimeSpan.FromMilliseconds(40), autoReconnect: true,
            transactionTimeout: TimeSpan.FromMilliseconds(200)));
        await client.ConnectAsync(); pbx.DropRegistrationResponses = true;
        await Check.EventuallyAsync(() => client.Status.State == SipClientState.Reconnecting);
        var reconnecting = client.ConnectAsync(); await Task.Delay(70);
        Check.That(!reconnecting.IsCompleted, "Old readiness must not satisfy a new connection wait.");
        pbx.DropRegistrationResponses = false;
        await reconnecting.WaitAsync(TimeSpan.FromSeconds(3)); Check.That(client.Status.State == SipClientState.Connected);
        await client.DisconnectAsync();
    }),
    ("TCP registration survives fragmented stream messages", async () =>
    {
        await using var pbx = new TcpTestPbx(); await using var manager = new SipClientManager();
        var client = manager.CreateClient(Check.Config(pbx.Port, SipTransportProtocol.Tcp));
        await client.ConnectAsync(); Check.That(client.Status.State == SipClientState.Connected);
        await client.DisconnectAsync(); Check.That(pbx.Unregistered);
    }),
    ("TLS carries SIP and rejects untrusted chains and wrong hostnames", async () =>
    {
        foreach (var mode in new[] { "trusted", "untrusted", "wrong-host" })
        {
            await using var peer = new TlsTestPeer();
            var config = new SipClientConfig
            {
                Id = "tls", Registrar = mode == "wrong-host" ? "127.0.0.1" : "localhost", Port = peer.Port,
                User = "test", Credentials = new() { Username = "test", Password = "test" }, Transport = SipTransportProtocol.Tls
            };
            await using var transport = new SipTransport(config, mode == "untrusted" ? null : peer.TrustRoots);
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            if (mode != "trusted")
            {
                try { await transport.OpenAsync(deadline.Token); throw new Exception($"TLS accepted {mode}."); }
                catch (System.Security.Authentication.AuthenticationException) { }
                continue;
            }
            await transport.OpenAsync(deadline.Token);
            var request = new SipMessage { StartLine = "OPTIONS sip:test@localhost SIP/2.0" };
            request.Add("Via", "SIP/2.0/TLS localhost;branch=z9hG4bKtls"); request.Add("From", "<sip:test@localhost>;tag=tls");
            request.Add("To", "<sip:peer@localhost>"); request.Add("Call-ID", "tls-test"); request.Add("CSeq", "1 OPTIONS");
            var received = new TaskCompletionSource<SipMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
            var reading = transport.ReceiveAsync(m => { received.TrySetResult(m); return Task.CompletedTask; }, deadline.Token);
            await transport.SendAsync(request, deadline.Token);
            Check.That((await received.Task.WaitAsync(deadline.Token)).StatusCode == 200);
            try { await reading; } catch (IOException) { }
        }
    }),
    ("Wrong credentials cannot establish Connected", async () =>
    {
        await using var pbx = new TestPbx { RejectCredentials = true };
        await using var manager = new SipClientManager(); var client = manager.CreateClient(Check.Config(pbx.Port));
        try { await client.ConnectAsync().WaitAsync(TimeSpan.FromSeconds(5)); throw new Exception("Expected rejection."); }
        catch (SipException e) { Check.That(e.StatusCode == 403); }
        Check.That(client.Status.State == SipClientState.Failed);
    }),
    ("Outgoing call, bidirectional paced PCM and VoiceAssistant adapter", async () =>
    {
        await using var pbx = new TestPbx(); await using var manager = new SipClientManager();
        var client = manager.CreateClient(Check.Config(pbx.Port)); await client.ConnectAsync();
        var call = client.CreateCall("123");
        await call.StartAsync().WaitAsync(TimeSpan.FromSeconds(5));
        Check.That(call.Status.State == SipCallState.Established);
        await using var adapter = new SipAudioHardwareAccess(call);
        var pcm = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
        await adapter.StartRecordingAudio((_, e) => pcm.TrySetResult(Convert.FromBase64String(e.Base64EncodedPcm16Audio).Length));
        Check.That(adapter.PlayAudio(Convert.ToBase64String(new byte[4800]), 24000));
        await pbx.SendAudioAsync();
        Check.That(await pcm.Task.WaitAsync(TimeSpan.FromSeconds(3)) > 0);
        Check.That(await adapter.WaitForPlaybackDrainAsync(TimeSpan.FromSeconds(3)));
        Check.That(call.Metrics.ReceivedPackets >= 3 && call.Metrics.TransmittedPackets >= 3);
        // AI producers run faster than playback. An interruption must clear both
        // the adapter backlog and the SIP queue, including a blocked sender slice.
        Check.That(adapter.PlayAudio(Convert.ToBase64String(new byte[24000 * 8]), 24000));
        Check.That(!await adapter.WaitForPlaybackDrainAsync(TimeSpan.FromMilliseconds(40)));
        await adapter.ClearAudioQueueAsync();
        await Task.Delay(80);
        Check.That(adapter.BufferedAudio == TimeSpan.Zero && call.Audio.QueuedAudio == TimeSpan.Zero, "Interrupted audio was reintroduced by the adapter.");
        await using (var limited = new SipAudioHardwareAccess(call, TimeSpan.FromMilliseconds(700)))
        {
            int errors = 0; limited.AudioError += (_, _) => errors++;
            Check.That(limited.PlayAudio(Convert.ToBase64String(new byte[24000]), 24000));
            Check.That(!limited.PlayAudio(Convert.ToBase64String(new byte[24000]), 24000));
            Check.That(errors == 1 && limited.BufferedAudio <= TimeSpan.FromMilliseconds(700), "Adapter limit must reject visibly without exceeding its bound.");
            await limited.ClearAudioQueueAsync();
            Check.That(limited.PlayAudio(Convert.ToBase64String(new byte[4800]), 24000));
            Check.That(await limited.WaitForPlaybackDrainAsync(TimeSpan.FromSeconds(2)));
        }
        await adapter.StopRecordingAudio();
        await call.HangupAsync(); Check.That(call.Status.EndReason == SipCallEndReason.LocalHangup && client.Calls.Count == 0);
        Check.That(!call.Audio.TryWrite(new short[480], 24000), "A closing audio producer must safely reject a trailing frame.");
        await client.DisconnectAsync();
    }),
    ("Minimum 20-ms transmit queue accepts and drains a complete resampled frame", async () =>
    {
        await using var pbx = new TestPbx(); await using var manager = new SipClientManager();
        var client = manager.CreateClient(Check.Config(pbx.Port, maxQueuedAudio: TimeSpan.FromMilliseconds(20)));
        await client.ConnectAsync(); var call = client.CreateCall("123"); await call.StartAsync();
        await using var adapter = new SipAudioHardwareAccess(call);
        Check.That(adapter.PlayAudio(Convert.ToBase64String(new byte[960]), 24000));
        Check.That(await adapter.WaitForPlaybackDrainAsync(TimeSpan.FromSeconds(1)), "Minimum queue permanently rejected sender slices.");
        Check.That(call.Metrics.TransmittedPackets > 0);
        await call.HangupAsync(); await client.DisconnectAsync();
    }),
    ("Invalid destinations and busy replies preserve native SIP errors and ACK cleanup", async () =>
    {
        foreach (int code in new[] { 404, 484, 604, 486 })
        {
            await using var pbx = new TestPbx { RejectCallWith = code }; await using var manager = new SipClientManager();
            var client = manager.CreateClient(Check.Config(pbx.Port)); await client.ConnectAsync(); var call = client.CreateCall("123");
            try { await call.StartAsync().WaitAsync(TimeSpan.FromSeconds(3)); throw new Exception("Expected SIP rejection."); }
            catch (SipException e) { Check.That(e.StatusCode == code && e.Message.Contains(code.ToString())); }
            Check.That(call.Status.EndReason == (code == 486 ? SipCallEndReason.Busy : SipCallEndReason.Rejected));
            Check.That(call.Status.SipStatusCode == code && !string.IsNullOrEmpty(call.Status.SipReasonPhrase) && call.Status.Error!.Contains(call.Status.SipReasonPhrase));
            Check.That(call.Completion.IsCompletedSuccessfully && client.Calls.Count == 0);
            await Check.EventuallyAsync(() => pbx.AckRequests > 0);
            await call.HangupAsync().WaitAsync(TimeSpan.FromSeconds(1));
            await client.DisconnectAsync();
        }
    }),
    ("Trying and early-media-only calls terminate at the configured answer deadline", async () =>
    {
        foreach (int provisional in new[] { 100, 183 })
        {
            await using var pbx = new TestPbx { WaitForCancel = true, ProvisionalCode = provisional };
            await using var manager = new SipClientManager();
            var client = manager.CreateClient(Check.Config(pbx.Port, answerTimeout: TimeSpan.FromMilliseconds(200)));
            await client.ConnectAsync(); var call = client.CreateCall("123"); var starting = call.StartAsync();
            await Check.EventuallyAsync(() => call.Status.SipStatusCode == provisional);
            Check.That(call.Status.State == SipCallState.Calling && !string.IsNullOrEmpty(call.Status.SipReasonPhrase));
            await pbx.SendProvisionalAsync(); // Repeated progress must not reset the answer deadline.
            try { await starting.WaitAsync(TimeSpan.FromSeconds(3)); throw new Exception("Expected answer timeout."); }
            catch (TimeoutException e) { Check.That(e.Message.Contains("No final SIP answer")); }
            Check.That(call.Status.EndReason == SipCallEndReason.Timeout && call.Completion.IsCompletedSuccessfully);
            Check.That(pbx.CancelRequests == 1 && pbx.CancelMatchesInvite && client.Calls.Count == 0);
            await Check.EventuallyAsync(() => pbx.AckRequests > 0);
            await client.DisconnectAsync();
        }
    }),
    ("Provisional response replaces transaction timeout with answer timeout", async () =>
    {
        await using var pbx = new TestPbx { WaitForCancel = true }; await using var manager = new SipClientManager();
        var client = manager.CreateClient(Check.Config(pbx.Port, transactionTimeout: TimeSpan.FromMilliseconds(300)));
        await client.ConnectAsync(); var call = client.CreateCall("123"); var starting = call.StartAsync();
        await Check.EventuallyAsync(() => call.Status.State == SipCallState.Ringing); await Task.Delay(450);
        Check.That(!starting.IsCompleted && pbx.CancelRequests == 0);
        await pbx.AnswerOutgoingAsync(); await starting; await call.HangupAsync(); await client.DisconnectAsync();
    }),
    ("Cancelling StartAsync cancels the remote ringing transaction", async () =>
    {
        await using var pbx = new TestPbx { WaitForCancel = true }; await using var manager = new SipClientManager();
        var client = manager.CreateClient(Check.Config(pbx.Port)); await client.ConnectAsync();
        using var cancelled = new CancellationTokenSource(); var call = client.CreateCall("123"); var starting = call.StartAsync(cancelled.Token);
        await Check.EventuallyAsync(() => call.Status.State == SipCallState.Ringing);
        cancelled.Cancel();
        try { await starting; throw new Exception("Expected cancellation."); } catch (OperationCanceledException) { }
        await Check.EventuallyAsync(() => pbx.CancelRequests == 1 && pbx.AckRequests >= 1);
        Check.That(pbx.CancelMatchesInvite && call.Status.EndReason == SipCallEndReason.Cancelled);
        await client.DisconnectAsync();
    }),
    ("Hangup waits for provisional response; late final retransmits are ACKed", async () =>
    {
        await using var pbx = new TestPbx { WaitForCancel = true, HoldProvisional = true }; await using var manager = new SipClientManager();
        var client = manager.CreateClient(Check.Config(pbx.Port)); await client.ConnectAsync();
        var call = client.CreateCall("123"); var starting = call.StartAsync(); await pbx.InviteReceived.Task;
        var hanging = call.HangupAsync(); await Task.Delay(80);
        Check.That(pbx.CancelRequests == 0, "CANCEL must wait for a provisional response.");
        await pbx.SendProvisionalAsync(); await hanging.WaitAsync(TimeSpan.FromSeconds(3));
        try { await starting; } catch (OperationCanceledException) { } catch (SipException e) when (e.StatusCode == 487) { }
        await Check.EventuallyAsync(() => pbx.AckRequests == 1);
        await pbx.RepeatFinalAsync(); await Check.EventuallyAsync(() => pbx.AckRequests == 2);
        Check.That(pbx.CancelRequests == 1 && pbx.CancelMatchesInvite);
        await client.DisconnectAsync();
    }),
    ("An answer racing cancellation is ACKed and closed with BYE", async () =>
    {
        await using var pbx = new TestPbx { WaitForCancel = true, AnswerOnCancel = true }; await using var manager = new SipClientManager();
        var client = manager.CreateClient(Check.Config(pbx.Port)); await client.ConnectAsync();
        using var cancelled = new CancellationTokenSource(); var call = client.CreateCall("123"); var starting = call.StartAsync(cancelled.Token);
        await Check.EventuallyAsync(() => call.Status.State == SipCallState.Ringing); cancelled.Cancel();
        try { await starting; throw new Exception("Expected cancellation."); } catch (OperationCanceledException) { }
        await Check.EventuallyAsync(() => pbx.AckRequests >= 1 && pbx.ByeRequests == 1);
        await pbx.RepeatFinalAsync(); await Check.EventuallyAsync(() => pbx.AckRequests >= 2);
        Check.That(pbx.ByeRequests == 1, "Repeated acceptance must not create duplicate BYE transactions.");
        Check.That(call.Status.State == SipCallState.Ended && client.Calls.Count == 0);
        await client.DisconnectAsync();
    }),
    ("Early RTP is discarded and speech resumes after silence suppression", async () =>
    {
        await using var pbx = new TestPbx { EarlyMediaPackets = 150 }; await using var manager = new SipClientManager();
        var client = manager.CreateClient(Check.Config(pbx.Port)); await client.ConnectAsync();
        var call = client.CreateCall("123"); await call.StartAsync();
        Check.That(call.Metrics.ReceivedPackets == 0 && call.Metrics.LatePackets > 0, "Early media must not enter established playout.");
        var first = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var resumed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        int phase = 0;
        var reader = Task.Run(async () =>
        {
            await foreach (var frame in call.Audio.ReadFramesAsync())
                if (frame.Samples.ToArray().Any(s => Math.Abs((int)s) > 500))
                { if (Volatile.Read(ref phase) == 0) first.TrySetResult(); else resumed.TrySetResult(); }
        });
        await pbx.SendAudioAsync(); await first.Task.WaitAsync(TimeSpan.FromSeconds(3));
        await Task.Delay(400); Check.That(call.Metrics.LostPackets == 0, "Silence is not packet loss.");
        Volatile.Write(ref phase, 1); pbx.AdvanceMediaClock(400);
        await pbx.SendAudioAsync(); await resumed.Task.WaitAsync(TimeSpan.FromSeconds(3));
        Check.That(call.Metrics.ReceivedPackets == 16, "Packets after DTX must still be accepted.");
        await call.HangupAsync(); await reader; await client.DisconnectAsync();
    }),
    ("Managed G.722 wideband and variable packet duration", async () =>
    {
        foreach (int milliseconds in new[] { 10, 30 })
        {
            await using var pbx = new TestPbx { UseG722 = true }; await using var manager = new SipClientManager();
            var client = manager.CreateClient(Check.Config(pbx.Port)); await client.ConnectAsync();
            var call = client.CreateCall("123"); await call.StartAsync();
            Check.That(call.Metrics.Codec == "G722");
            var reading = Task.Run(async () =>
            {
                await foreach (var frame in call.Audio.ReadFramesAsync())
                    if (frame.Samples.Length > 0) { Check.That(frame.SampleRate == 24000 && frame.Samples.Length <= 480); return; }
            });
            Check.That(call.Audio.TryWrite(new short[2400], 24000));
            await pbx.SendAudioAsync(milliseconds); await reading.WaitAsync(TimeSpan.FromSeconds(3));
            await call.HangupAsync(); await client.DisconnectAsync();
        }
    }),
    ("Hangup finishes when an incoming answer receives no ACK", async () =>
    {
        await using var pbx = new TestPbx(); await using var manager = new SipClientManager();
        var client = manager.CreateClient(Check.Config(pbx.Port, transactionTimeout: TimeSpan.FromMilliseconds(400)));
        await client.ConnectAsync();
        var incoming = new TaskCompletionSource<SipCall>(TaskCreationOptions.RunContinuationsAsynchronously);
        client.IncomingCall += (_, call) => incoming.TrySetResult(call);
        await pbx.InviteAsync(); var call = await incoming.Task.WaitAsync(TimeSpan.FromSeconds(3));
        var answering = call.AnswerAsync(); await pbx.WaitResponseAsync("INVITE", 200);
        var hanging = call.HangupAsync(); var secondHangup = call.HangupAsync();
        try { await answering; throw new Exception("Missing ACK did not time out."); }
        catch (OperationCanceledException) { }
        await Task.WhenAll(hanging, secondHangup).WaitAsync(TimeSpan.FromSeconds(2));
        Check.That(call.Completion.IsCompletedSuccessfully && call.Status.EndReason == SipCallEndReason.Timeout);
        Check.That(client.Calls.Count == 0 && !call.Audio.TryWrite(new short[480], 24000));
        await client.DisconnectAsync();
    }),
    ("Cancelling a hangup waiter preserves ACK/BYE cleanup", async () =>
    {
        await using var pbx = new TestPbx(); await using var manager = new SipClientManager();
        var client = manager.CreateClient(Check.Config(pbx.Port)); await client.ConnectAsync();
        var incoming = new TaskCompletionSource<SipCall>(TaskCreationOptions.RunContinuationsAsynchronously);
        client.IncomingCall += (_, call) => incoming.TrySetResult(call);
        var invite = await pbx.InviteAsync(); var call = await incoming.Task.WaitAsync(TimeSpan.FromSeconds(3));
        var answering = call.AnswerAsync(); var answer = await pbx.WaitResponseAsync("INVITE", 200);
        using var cancellation = new CancellationTokenSource();
        var hanging = call.HangupAsync(cancellation.Token); cancellation.Cancel();
        try { await hanging; throw new Exception("Hangup waiter ignored cancellation."); }
        catch (OperationCanceledException) { }
        await pbx.AckAsync(invite, answer);
        await Task.WhenAll(answering, call.HangupAsync()).WaitAsync(TimeSpan.FromSeconds(3));
        Check.That(call.Completion.IsCompletedSuccessfully && call.Status.EndReason == SipCallEndReason.LocalHangup);
        Check.That(pbx.ByeRequests == 1 && !call.Audio.TryWrite(new short[480], 24000));
        await client.DisconnectAsync();
    }),
    ("Incoming call event, duplicate INVITE, answer, ACK and remote BYE", async () =>
    {
        await using var pbx = new TestPbx(); await using var manager = new SipClientManager();
        var client = manager.CreateClient(Check.Config(pbx.Port)); await client.ConnectAsync();
        var incoming = new TaskCompletionSource<SipCall>(TaskCreationOptions.RunContinuationsAsynchronously); int events = 0;
        client.IncomingCall += (_, call) => { Interlocked.Increment(ref events); incoming.TrySetResult(call); };
        var invite = await pbx.InviteAsync();
        var call = await incoming.Task.WaitAsync(TimeSpan.FromSeconds(3));
        await pbx.SendAsync(invite); await Task.Delay(50);
        Check.That(events == 1 && client.Calls.Count == 1);
        var answering = call.AnswerAsync();
        var answer = await pbx.WaitResponseAsync("INVITE", 200);
        await pbx.AckAsync(invite, answer); await answering.WaitAsync(TimeSpan.FromSeconds(3));
        Check.That(call.Status.State == SipCallState.Established);
        await pbx.ByeAsync(invite, answer); await call.Completion.WaitAsync(TimeSpan.FromSeconds(3));
        Check.That(call.Status.EndReason == SipCallEndReason.RemoteHangup);
        await client.DisconnectAsync();
    })
};
int failed = 0;
var allCases = cases.Concat(RtcpTests.Cases).ToArray();
foreach (var test in allCases)
{
    try { await test.Run().WaitAsync(TimeSpan.FromSeconds(15)); Console.WriteLine($"PASS {test.Name}"); }
    catch (Exception error) { failed++; Console.WriteLine($"FAIL {test.Name}: {error}"); }
}
Console.WriteLine($"{allCases.Length - failed}/{allCases.Length} passed");
Environment.ExitCode = failed == 0 ? 0 : 1;

internal static class Check
{
    public static async Task EventuallyAsync(Func<bool> condition)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        while (!condition()) await Task.Delay(10, deadline.Token);
    }
    public static void That(bool condition, string? message = null) { if (!condition) throw new Exception(message ?? "Assertion failed."); }
    public static void Throws<T>(Action action) where T : Exception
    { try { action(); } catch (T) { return; } throw new Exception($"Expected {typeof(T).Name}"); }
    public static SipClientConfig Config(int port, SipTransportProtocol transport = SipTransportProtocol.Udp, TimeSpan? keepAlive = null,
        bool autoReconnect = false, TimeSpan? transactionTimeout = null, string id = "test", SipCredentials? credentials = null,
        TimeSpan? answerTimeout = null, TimeSpan? maxQueuedAudio = null) => new()
    {
        Id = id, Registrar = "127.0.0.1", Port = port, User = credentials?.Username ?? "test-user", Domain = "example.test", Transport = transport,
        Credentials = credentials ?? new() { Username = "test-user", Password = "test-password" }, LocalAddress = IPAddress.Loopback,
        AutoReconnect = autoReconnect, TransactionTimeout = transactionTimeout ?? TimeSpan.FromSeconds(2), InitialRetransmitInterval = TimeSpan.FromMilliseconds(50),
        KeepAliveInterval = keepAlive ?? TimeSpan.FromSeconds(25), ReconnectDelay = TimeSpan.FromMilliseconds(50),
        CallAnswerTimeout = answerTimeout ?? TimeSpan.FromSeconds(45), MaxQueuedAudio = maxQueuedAudio ?? TimeSpan.FromSeconds(3)
    };
    public static byte[] Rtp(ushort sequence, uint timestamp, byte[] payload)
    {
        byte[] data = new byte[12 + payload.Length]; data[0] = 0x80; data[1] = 8;
        BinaryPrimitives.WriteUInt16BigEndian(data.AsSpan(2), sequence); BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(4), timestamp);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(8), 42); payload.CopyTo(data, 12); return data;
    }
}
