using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.Json.Serialization;
using Ai.Tlbx.Sip;

static string Required(string name) => Environment.GetEnvironmentVariable(name) is { Length: > 0 } value ? value : throw new ArgumentException($"Set {name} before starting the sample.");
using var stop = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; stop.Cancel(); };
try
{
    var transport = Enum.Parse<SipTransportProtocol>(Environment.GetEnvironmentVariable("SIP_TRANSPORT") ?? "Udp", ignoreCase: true);
    int configIndex = Array.IndexOf(args, "--config");
    var config = configIndex >= 0
        ? JsonSerializer.Deserialize<SipClientConfig>(await File.ReadAllTextAsync(args[configIndex + 1], stop.Token),
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true, Converters = { new JsonStringEnumConverter() } })
            ?? throw new ArgumentException("Configuration is empty.")
        : new SipClientConfig
    {
        Id = "console", Registrar = Required("SIP_REGISTRAR"), User = Required("SIP_USER"),
        Domain = Environment.GetEnvironmentVariable("SIP_DOMAIN"),
        Credentials = new() { Username = Environment.GetEnvironmentVariable("SIP_AUTH_USER") ?? Required("SIP_USER"), Password = Required("SIP_PASSWORD") },
        Transport = transport,
        MediaSecurity = args.Contains("--srtp") ? SipMediaSecurity.SdesRequired : SipMediaSecurity.Unencrypted,
        AdvertisedAddress = Environment.GetEnvironmentVariable("SIP_ADVERTISED_ADDRESS")
    };
    await using var manager = new SipClientManager();
    var client = manager.CreateClient(config);
    var operations = new ConcurrentBag<Task>();
    async Task ObserveAsync(Func<Task> work)
    { try { await work(); } catch (OperationCanceledException) { } catch (Exception e) { Console.WriteLine(e.Message); } }
    void Attach(SipCall call)
    {
        call.StatusChanged += (_, status) => Console.WriteLine($"Call {call.Id}: {status.State} {status.EndReason}");
        call.MediaChanged += (_, remote) => Console.WriteLine($"Call {call.Id}: media renegotiated, remote={remote} local={call.Audio.Direction}");
        call.Audio.MetricsChanged += (_, m) =>
        {
            string rtt = m.RoundTripMilliseconds.HasValue ? m.RoundTripMilliseconds.Value.ToString("F1", System.Globalization.CultureInfo.InvariantCulture) + "ms" : "unknown";
            Console.WriteLine($"Call {call.Id}: codec={m.Codec} TX={m.TransmittedPackets} RX={m.ReceivedPackets} lost={m.LostPackets} jitter={m.JitterMilliseconds:F1}ms queue={m.QueuedAudio.TotalMilliseconds:F0}ms rtt={rtt} RTCP={m.Control?.TransmittedPackets}/{m.Control?.ReceivedPackets}");
        };
        if (args.Contains("--hold-test")) operations.Add(ObserveAsync(async () =>
        {
            // Five seconds after establishment: hold, play a 440 Hz waiting tone for six seconds, resume.
            while (call.Status.State is not (SipCallState.Established or SipCallState.Ended)) await Task.Delay(50, stop.Token);
            if (call.Status.State == SipCallState.Ended) return;
            await Task.Delay(TimeSpan.FromSeconds(5), stop.Token);
            Console.WriteLine($"Call {call.Id}: holding"); await call.HoldAsync(stop.Token);
            Console.WriteLine($"Call {call.Id}: on hold, local={call.Audio.Direction} remote={call.RemoteMediaDirection}");
            var tone = Enumerable.Range(0, 480).Select(i => (short)(6000 * Math.Sin(2 * Math.PI * 440 * i / 24000))).ToArray();
            for (int i = 0; i < 300 && call.Status.State == SipCallState.Established; i++)
            { while (!call.Audio.TryWrite(tone, 24000)) await Task.Delay(10, stop.Token); }
            await call.Audio.WaitForDrainAsync(TimeSpan.FromSeconds(10), stop.Token);
            Console.WriteLine($"Call {call.Id}: resuming"); await call.ResumeAsync(stop.Token);
            Console.WriteLine($"Call {call.Id}: resumed, local={call.Audio.Direction} remote={call.RemoteMediaDirection}");
        }));
        int attendedIndex = Array.IndexOf(args, "--attended-test");
        if (attendedIndex >= 0 && call.Direction == SipCallDirection.Incoming) operations.Add(ObserveAsync(async () =>
        {
            // Attended transfer demo: hold the caller with a tone, call the target, announce with a tone, then
            // join both. If the target does not answer within 20 seconds, the caller is taken back.
            while (call.Status.State is not (SipCallState.Established or SipCallState.Ended)) await Task.Delay(50, stop.Token);
            if (call.Status.State == SipCallState.Ended) return;
            await Task.Delay(TimeSpan.FromSeconds(5), stop.Token);
            static short[] Tone(int hz) => Enumerable.Range(0, 480).Select(i => (short)(6000 * Math.Sin(2 * Math.PI * hz * i / 24000))).ToArray();
            using var holdMusic = CancellationTokenSource.CreateLinkedTokenSource(stop.Token);
            Console.WriteLine($"Call {call.Id}: holding caller"); await call.HoldAsync(stop.Token);
            var music = Task.Run(async () =>
            {
                var tone = Tone(440); var pause = new short[480];
                // Keep only a small lead in the transmit queue so the caller is not resumed behind seconds of tone.
                try { for (int i = 0; !holdMusic.IsCancellationRequested; i++) { var frame = i % 50 < 25 ? tone : pause; while (call.Audio.QueuedAudio > TimeSpan.FromMilliseconds(100) || !call.Audio.TryWrite(frame, 24000)) await Task.Delay(10, holdMusic.Token); } }
                catch (OperationCanceledException) { }
            });
            // If the caller hangs up during a consultation, stop ringing the target at once.
            using var callerGone = CancellationTokenSource.CreateLinkedTokenSource(stop.Token);
            call.StatusChanged += (_, s) => { if (s.State == SipCallState.Ended) try { callerGone.Cancel(); } catch (ObjectDisposedException) { } };
            // A comma-separated list is tried in order: the next target is consulted when one does not answer.
            foreach (string target in args[attendedIndex + 1].Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (call.Status.State != SipCallState.Established) break;
                var consultation = client.CreateCall(target); Attach(consultation);
                Console.WriteLine($"Call {call.Id}: consulting {target} as {consultation.Id}");
                using var ring = CancellationTokenSource.CreateLinkedTokenSource(callerGone.Token); ring.CancelAfter(TimeSpan.FromSeconds(20));
                bool answered;
                try { await consultation.StartAsync(ring.Token); answered = true; }
                catch (Exception error) { answered = false; Console.WriteLine($"Call {call.Id}: consultation failed: {error.Message}"); }
                if (!answered) continue;
                var announce = Tone(660);
                for (int i = 0; i < 150; i++) while (!consultation.Audio.TryWrite(announce, 24000)) await Task.Delay(10, stop.Token);
                await consultation.Audio.WaitForDrainAsync(TimeSpan.FromSeconds(5), stop.Token);
                Console.WriteLine($"Call {call.Id}: transferring to consultation {consultation.Id}");
                holdMusic.Cancel(); await music;
                var result = await call.TransferToCallAsync(consultation, stop.Token);
                Console.WriteLine($"Call {call.Id}: attended transfer {result.Outcome} {result.StatusCode} {result.ReasonPhrase}");
                if (result.Outcome == SipTransferOutcome.Succeeded) return;
                await consultation.HangupAsync(stop.Token);
                break;
            }
            holdMusic.Cancel(); await music;
            if (call.Status.State != SipCallState.Established) { Console.WriteLine($"Call {call.Id}: caller gone, nothing to take back"); return; }
            // Drop the remaining hold tone; otherwise everything sent after resuming lags behind it.
            call.Audio.ClearOutput();
            Console.WriteLine($"Call {call.Id}: taking caller back"); await call.ResumeAsync(stop.Token);
            Console.WriteLine($"Call {call.Id}: caller back, local={call.Audio.Direction}");
        }));
        int twiceIndex = Array.IndexOf(args, "--refer-twice");
        if (twiceIndex >= 0 && call.Direction == SipCallDirection.Incoming) operations.Add(ObserveAsync(async () =>
        {
            // Two REFERs in one dialog: the first target is expected to fail (for example a Replaces URI that
            // matches no dialog), the second is a normal blind transfer. Shows whether the PBX NOTIFYs for the
            // second subscription carry Event: refer;id=<CSeq> (RFC 3515 section 2.4.6).
            while (call.Status.State is not (SipCallState.Established or SipCallState.Ended)) await Task.Delay(50, stop.Token);
            if (call.Status.State == SipCallState.Ended) return;
            await Task.Delay(TimeSpan.FromSeconds(5), stop.Token);
            Console.WriteLine($"Call {call.Id}: first REFER to {args[twiceIndex + 1]}");
            var first = await call.TransferAsync(args[twiceIndex + 1], stop.Token);
            Console.WriteLine($"Call {call.Id}: first transfer {first.Outcome} {first.StatusCode} {first.ReasonPhrase}");
            if (first.Outcome == SipTransferOutcome.Succeeded || call.Status.State != SipCallState.Established)
            { Console.WriteLine($"Call {call.Id}: first transfer did not leave the call in place, test inconclusive"); return; }
            await Task.Delay(TimeSpan.FromSeconds(3), stop.Token);
            Console.WriteLine($"Call {call.Id}: second REFER to {args[twiceIndex + 2]}");
            var watch = System.Diagnostics.Stopwatch.StartNew();
            var second = await call.TransferAsync(args[twiceIndex + 2], stop.Token);
            Console.WriteLine($"Call {call.Id}: second transfer {second.Outcome} {second.StatusCode} {second.ReasonPhrase} after {watch.Elapsed.TotalSeconds:F1}s");
        }));
        int transferIndex = Array.IndexOf(args, "--transfer-test");
        if (transferIndex >= 0) operations.Add(ObserveAsync(async () =>
        {
            // Five seconds after establishment: blind transfer to the given extension, number or sip: URI.
            while (call.Status.State is not (SipCallState.Established or SipCallState.Ended)) await Task.Delay(50, stop.Token);
            if (call.Status.State == SipCallState.Ended) return;
            await Task.Delay(TimeSpan.FromSeconds(5), stop.Token);
            Console.WriteLine($"Call {call.Id}: transferring to {args[transferIndex + 1]}");
            var result = await call.TransferAsync(args[transferIndex + 1], stop.Token);
            Console.WriteLine($"Call {call.Id}: transfer {result.Outcome} {result.StatusCode} {result.ReasonPhrase}");
        }));
        if (args.Contains("--echo")) operations.Add(ObserveAsync(async () =>
        {
            await foreach (var frame in call.Audio.ReadFramesAsync(stop.Token))
            {
                if (call.Status.State == SipCallState.Ended) break;
                if (call.IsOnHold) continue;
                if (!call.Audio.TryWrite(frame.Samples.Span, frame.SampleRate) && call.Status.State != SipCallState.Ended)
                    Console.WriteLine("Echo transmit queue full.");
            }
        }));
    }
    client.StatusChanged += (_, status) => Console.WriteLine($"Client: {status.State} {status.Error}");
    client.Diagnostic += (_, d) => Console.WriteLine($"{d.Category}: {d.Message}");
    client.IncomingCall += (_, call) =>
    {
        Attach(call); Console.WriteLine($"Incoming call {call.Id} from {call.RemoteUri}. Use: answer {call.Id}");
        if (args.Contains("--show-identity"))
        {
            Console.WriteLine($"Call {call.Id}: caller number={call.RemoteIdentity.Number ?? "-"} name={call.RemoteIdentity.DisplayName ?? "-"} anonymous={call.RemoteIdentity.Anonymous}");
            Console.WriteLine($"Call {call.Id}: dialled number={call.CalledIdentity?.Number ?? "-"} diversions={string.Join(" <- ", call.Diversions.Select(d => d.Number ?? d.Uri))}");
            foreach (var header in call.InitialHeaders) Console.WriteLine($"Call {call.Id}: header {header.Key}: {header.Value}");
        }
        if (args.Contains("--auto-answer")) operations.Add(ObserveAsync(() => call.AnswerAsync(stop.Token)));
    };
    await client.ConnectAsync(stop.Token);
    int dialIndex = Array.IndexOf(args, "--dial");
    if (dialIndex >= 0)
    {
        var outgoing = client.CreateCall(args[dialIndex + 1]);
        Attach(outgoing);
        operations.Add(ObserveAsync(() => outgoing.StartAsync(stop.Token)));
    }
    int listenIndex = Array.IndexOf(args, "--listen-seconds");
    if (listenIndex >= 0)
    {
        int seconds = int.Parse(args[listenIndex + 1], System.Globalization.CultureInfo.InvariantCulture);
        if (seconds is < 1 or > 3600) throw new ArgumentOutOfRangeException(nameof(seconds));
        Console.WriteLine($"Listening for {seconds} seconds.");
        await Task.Delay(TimeSpan.FromSeconds(seconds), stop.Token);
    }
    else if (!args.Contains("--probe"))
    {
        Console.WriteLine("Commands: call <number>, answer <id>, hangup <id>, list, quit. No outgoing call is made automatically.");
        while (!stop.IsCancellationRequested)
        {
            string? line = await Console.In.ReadLineAsync(stop.Token); if (line is null || line == "quit") break;
            var parts = line.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 0) continue;
            try
            {
                if (parts[0] == "list") foreach (var c in client.Calls) Console.WriteLine($"{c.Id} {c.Status.State} {c.RemoteUri}");
                else if (parts is ["call", var number]) { var call = client.CreateCall(number); Attach(call); operations.Add(ObserveAsync(() => call.StartAsync(stop.Token))); }
                else if (parts is ["answer", var id]) { var call = client.Calls.Single(c => c.Id == id); operations.Add(ObserveAsync(() => call.AnswerAsync(stop.Token))); }
                else if (parts is ["hangup", var hangupId]) { var call = client.Calls.Single(c => c.Id == hangupId); operations.Add(ObserveAsync(() => call.HangupAsync(stop.Token))); }
            }
            catch (Exception error) { Console.WriteLine(error.Message); }
        }
    }
    stop.Cancel(); await client.DisconnectAsync(); await Task.WhenAll(operations);
}
catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
catch (Exception error) { Console.Error.WriteLine(error.Message); Environment.ExitCode = 1; }
