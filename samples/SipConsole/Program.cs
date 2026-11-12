using System.Collections.Concurrent;
using Ai.Tlbx.Sip;

static string Required(string name) => Environment.GetEnvironmentVariable(name) is { Length: > 0 } value ? value : throw new ArgumentException($"Set {name} before starting the sample.");
using var stop = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; stop.Cancel(); };
try
{
    var transport = Enum.Parse<SipTransportProtocol>(Environment.GetEnvironmentVariable("SIP_TRANSPORT") ?? "Udp", ignoreCase: true);
    var config = new SipClientConfig
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
        call.Audio.MetricsChanged += (_, m) => Console.WriteLine($"Call {call.Id}: TX={m.TransmittedPackets} RX={m.ReceivedPackets} lost={m.LostPackets} jitter={m.JitterMilliseconds:F1}ms queue={m.QueuedAudio.TotalMilliseconds:F0}ms");
        if (args.Contains("--echo")) operations.Add(ObserveAsync(async () =>
        {
            await foreach (var frame in call.Audio.ReadFramesAsync(stop.Token))
                if (!call.Audio.TryWrite(frame.Samples.Span, frame.SampleRate)) Console.WriteLine("Echo transmit queue full.");
        }));
    }
    client.StatusChanged += (_, status) => Console.WriteLine($"Client: {status.State} {status.Error}");
    client.Diagnostic += (_, d) => Console.WriteLine($"{d.Category}: {d.Message}");
    client.IncomingCall += (_, call) =>
    {
        Attach(call); Console.WriteLine($"Incoming call {call.Id} from {call.RemoteUri}. Use: answer {call.Id}");
        if (args.Contains("--auto-answer")) operations.Add(ObserveAsync(() => call.AnswerAsync(stop.Token)));
    };
    await client.ConnectAsync(stop.Token);
    if (!args.Contains("--probe"))
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
