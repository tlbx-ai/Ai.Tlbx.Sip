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
        call.Audio.MetricsChanged += (_, m) => Console.WriteLine($"Call {call.Id}: codec={m.Codec} TX={m.TransmittedPackets} RX={m.ReceivedPackets} lost={m.LostPackets} jitter={m.JitterMilliseconds:F1}ms queue={m.QueuedAudio.TotalMilliseconds:F0}ms");
        if (args.Contains("--echo")) operations.Add(ObserveAsync(async () =>
        {
            await foreach (var frame in call.Audio.ReadFramesAsync(stop.Token))
            {
                if (call.Status.State == SipCallState.Ended) break;
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
