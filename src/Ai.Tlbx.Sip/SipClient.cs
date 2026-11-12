using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using Ai.Tlbx.Sip.Protocol;

namespace Ai.Tlbx.Sip;

public sealed class SipException(int statusCode, string message) : Exception(message)
{
    public int StatusCode { get; } = statusCode;
}

/// <summary>An independently registered identity. Connected means authenticated, registered and monitored for reachability.</summary>
public sealed class SipClient : IAsyncDisposable
{
    private readonly SipClientConfig _config;
    private readonly TimeProvider _time;
    private readonly SemaphoreSlim _lifecycle = new(1, 1);
    private readonly SemaphoreSlim _registration = new(1, 1);
    private readonly object _readinessGate = new();
    private readonly object _callsGate = new();
    private readonly ConcurrentDictionary<string, SipCall> _calls = new();
    private readonly ConcurrentDictionary<string, (SipCall Call, DateTimeOffset Expires)> _retiredCalls = new();
    private readonly ConcurrentDictionary<string, (SipMessage Request, DateTimeOffset Expires)> _inviteRequests = new();
    private readonly ConcurrentDictionary<string, (SipMessage Response, DateTimeOffset Expires)> _responses = new();
    private readonly DigestAuthentication _digest = new();
    private readonly SemaphoreSlim _authLock = new(1, 1);
    private readonly SipTransactions _transactions;
    private SipTransport? _transport;
    private CancellationTokenSource? _stop;
    private Task? _connection;
    private TaskCompletionSource _firstConnection = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly string _registrationCallId = NewId();
    private readonly string _registrationTag = NewId();
    private int _sequence = RandomNumberGenerator.GetInt32(1, 1000000);
    private bool _disposed;
    private bool _disconnecting;
    private SipClientStatus _status;
    internal SipClient(SipClientConfig config, TimeProvider time)
    {
        _config = config; _time = time; _transactions = new(config, time);
        _status = new(SipClientState.Disconnected, time.GetUtcNow());
    }
    public string Id => _config.Id;
    public SipClientStatus Status => Volatile.Read(ref _status);
    public IReadOnlyCollection<SipCall> Calls => _calls.Values.ToArray();
    public event EventHandler<SipClientStatus>? StatusChanged;
    public event EventHandler<SipCall>? IncomingCall;
    public event EventHandler<SipDiagnostic>? Diagnostic;
    internal SipClientConfig Config => _config;
    internal TimeProvider Time => _time;
    internal string Contact => $"<sip:{Uri.EscapeDataString(_config.User)}@{HostPort(AdvertisedAddress, Transport.LocalEndPoint.Port)};transport={_config.Transport.ToString().ToLowerInvariant()}>";
    internal IPAddress MediaAddress => IPAddress.TryParse(AdvertisedAddress, out var ip) ? ip : Transport.LocalEndPoint.Address;
    private string AdvertisedAddress => _config.AdvertisedAddress ?? Transport.LocalEndPoint.Address.ToString();
    private SipTransport Transport => _transport ?? throw new InvalidOperationException("Client transport is not open.");
    public async Task ConnectAsync(CancellationToken cancellationToken = default)
    {
        Task ready;
        await _lifecycle.WaitAsync(cancellationToken);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_connection is null || _connection.IsCompleted)
            {
                _stop?.Dispose(); _stop = new();
                _disconnecting = false;
                _firstConnection = new(TaskCreationOptions.RunContinuationsAsynchronously);
                _connection = ConnectionLoopAsync(_stop.Token);
            }
            lock (_readinessGate) ready = _firstConnection.Task;
        }
        finally { _lifecycle.Release(); }
        await ready.WaitAsync(cancellationToken);
    }
    private async Task ConnectionLoopAsync(CancellationToken stop)
    {
        bool previouslyConnected = false;
        while (!stop.IsCancellationRequested)
        {
            SetStatus(previouslyConnected ? SipClientState.Reconnecting : SipClientState.Connecting);
            using var generation = CancellationTokenSource.CreateLinkedTokenSource(stop);
            Task? receiver = null;
            var transport = new SipTransport(_config); _transport = transport;
            try
            {
                await transport.OpenAsync(generation.Token);
                receiver = ReceiveLoopAsync(transport, generation);
                DateTimeOffset expires = await RegisterAsync(_config.RegistrationLifetimeSeconds, generation.Token);
                if (Volatile.Read(ref _disconnecting)) await Task.Delay(Timeout.InfiniteTimeSpan, _time, generation.Token);
                SetStatus(SipClientState.Connected, expires: expires);
                previouslyConnected = true;
                while (!generation.IsCancellationRequested)
                {
                    TimeSpan untilRefresh = TimeSpan.FromTicks((expires - _time.GetUtcNow()).Ticks * 2 / 3);
                    var delay = untilRefresh < _config.KeepAliveInterval ? untilRefresh : _config.KeepAliveInterval;
                    await Task.Delay(delay > TimeSpan.Zero ? delay : TimeSpan.Zero, _time, generation.Token);
                    if (Volatile.Read(ref _disconnecting)) await Task.Delay(Timeout.InfiniteTimeSpan, _time, generation.Token);
                    // Authenticated REGISTER refresh both checks credentials and keeps the incoming route alive.
                    TimeSpan remaining = expires - _time.GetUtcNow();
                    using var validity = new CancellationTokenSource(remaining > TimeSpan.Zero ? remaining : TimeSpan.Zero, _time);
                    using var refresh = CancellationTokenSource.CreateLinkedTokenSource(generation.Token, validity.Token);
                    try { expires = await RegisterAsync(_config.RegistrationLifetimeSeconds, refresh.Token); }
                    catch (OperationCanceledException) when (validity.IsCancellationRequested && !generation.IsCancellationRequested)
                    { throw new IOException("SIP registration expired before its refresh completed."); }
                    if (Volatile.Read(ref _disconnecting)) await Task.Delay(Timeout.InfiniteTimeSpan, _time, generation.Token);
                    SetStatus(SipClientState.Connected, expires: expires);
                    foreach (var pair in _responses.Where(p => p.Value.Expires <= _time.GetUtcNow()).ToArray()) _responses.TryRemove(pair.Key, out _);
                    foreach (var pair in _retiredCalls.Where(p => p.Value.Expires <= _time.GetUtcNow()).ToArray()) _retiredCalls.TryRemove(pair.Key, out _);
                    foreach (var pair in _inviteRequests.Where(p => p.Value.Expires <= _time.GetUtcNow()).ToArray()) _inviteRequests.TryRemove(pair.Key, out _);
                }
                stop.ThrowIfCancellationRequested();
                throw new IOException("SIP receive loop stopped.");
            }
            catch (Exception error) when (!stop.IsCancellationRequested)
            {
                bool terminal = error is SipException { StatusCode: 401 or 403 or 404 or 407 };
                SetStatus(terminal || !_config.AutoReconnect ? SipClientState.Failed : SipClientState.Reconnecting,
                    error: error.Message, code: (error as SipException)?.StatusCode);
                if (terminal || !_config.AutoReconnect) { _firstConnection.TrySetException(error); break; }
                Report("connection", error.Message);
            }
            catch (OperationCanceledException) when (stop.IsCancellationRequested) { break; }
            finally
            {
                generation.Cancel(); _transactions.Fail(new IOException("SIP transport generation ended."));
                await transport.DisposeAsync();
                if (receiver is not null) try { await receiver; } catch (Exception error) when (error is OperationCanceledException or IOException or System.Net.Sockets.SocketException or ObjectDisposedException) { }
                foreach (var call in Calls) await call.EndAsync(SipCallEndReason.ConnectionLost);
                _transport = null; _responses.Clear(); _retiredCalls.Clear(); _inviteRequests.Clear();
            }
            try { await Task.Delay(_config.ReconnectDelay, _time, stop); } catch (OperationCanceledException) { break; }
        }
        _firstConnection.TrySetCanceled(stop.IsCancellationRequested ? stop : new CancellationToken(true));
    }
    private async Task ReceiveLoopAsync(SipTransport transport, CancellationTokenSource generation)
    {
        try { await transport.ReceiveAsync(OnMessageAsync, generation.Token); }
        catch (Exception error) when (!generation.IsCancellationRequested)
        { Report("transport", error.Message); _transactions.Fail(new IOException("SIP receive failed.", error)); generation.Cancel(); }
    }
    private async Task<DateTimeOffset> RegisterAsync(int expiry, CancellationToken cancellationToken)
    {
        await _registration.WaitAsync(cancellationToken);
        try
        {
            if (expiry > 0 && Volatile.Read(ref _disconnecting)) return Status.RegistrationExpiresAt ?? _time.GetUtcNow();
            return await RegisterCoreAsync(expiry, cancellationToken);
        }
        finally { _registration.Release(); }
    }
    private async Task<DateTimeOffset> RegisterCoreAsync(int expiry, CancellationToken cancellationToken)
    {
        var request = Request("REGISTER", $"sip:{_config.SipDomain}", _registrationCallId, _registrationTag);
        request.Add("Expires", expiry.ToString(System.Globalization.CultureInfo.InvariantCulture));
        var response = await RequestAuthenticatedAsync(request, null, cancellationToken);
        if (response.StatusCode == 423 && int.TryParse(response.Get("Min-Expires"), out int minimum) && minimum is >= 30 and <= 86400)
        {
            request.Set("Expires", minimum.ToString(System.Globalization.CultureInfo.InvariantCulture));
            request.Set("CSeq", NextSequence() + " REGISTER"); SetNewBranch(request);
            response = await RequestAuthenticatedAsync(request, null, cancellationToken); expiry = minimum;
        }
        EnsureSuccess(response);
        // A registrar can return several bindings for the same username, including
        // expired contacts from an earlier socket. Match this binding's URI.
        string requestedContact = SipMessage.UriFromHeader(request.Get("Contact")).Split(';')[0];
        string contactExpiry = SipMessage.Parameter(response.GetAll("Contact").FirstOrDefault(c =>
            SipMessage.UriFromHeader(c).Split(';')[0].Equals(requestedContact, StringComparison.OrdinalIgnoreCase)) ?? "", "expires");
        if (int.TryParse(contactExpiry.Length > 0 ? contactExpiry : response.Get("Expires"), out int granted)) expiry = granted;
        if (expiry <= 0 && request.Get("Expires") != "0") throw new InvalidDataException("Registrar granted an expired registration.");
        return _time.GetUtcNow().AddSeconds(Math.Min(expiry, 86400));
    }
    internal SipMessage Request(string method, string uri, string callId, string tag, string? to = null, int? sequence = null)
    {
        if (uri.Any(char.IsControl) || uri.Contains(' ')) throw new ArgumentException("Invalid SIP URI.");
        var request = new SipMessage { StartLine = $"{method} {uri} SIP/2.0" };
        request.Add("Via", $"SIP/2.0/{_config.Transport.ToString().ToUpperInvariant()} {HostPort(AdvertisedAddress, Transport.LocalEndPoint.Port)};branch=z9hG4bK{NewId()};rport");
        request.Add("Max-Forwards", "70");
        request.Add("From", $"<sip:{Uri.EscapeDataString(_config.User)}@{_config.SipDomain}>;tag={tag}");
        request.Add("To", to ?? $"<sip:{Uri.EscapeDataString(_config.User)}@{_config.SipDomain}>");
        request.Add("Call-ID", callId); request.Add("CSeq", $"{sequence ?? NextSequence()} {method}");
        request.Add("Contact", Contact); request.Add("User-Agent", "Ai.Tlbx.Sip/0.1");
        return request;
    }
    internal int NextSequence() => Interlocked.Increment(ref _sequence);
    internal void SetNewBranch(SipMessage message)
    {
        string via = message.Get("Via");
        string old = SipMessage.Parameter(via, "branch");
        message.Set("Via", via.Replace("branch=" + old, "branch=z9hG4bK" + NewId(), StringComparison.Ordinal));
    }
    internal async Task<SipMessage> RequestAuthenticatedAsync(SipMessage request, Action<SipMessage>? progress, CancellationToken cancellationToken)
    {
        for (int attempt = 0; attempt < 3; attempt++)
        {
            if (request.Method == "INVITE")
            {
                var headers = new SipMessage { StartLine = request.StartLine };
                foreach (string name in new[] { "Via", "From", "To", "Call-ID", "CSeq", "Max-Forwards", "Route" })
                    foreach (string value in request.GetAll(name)) headers.Add(name, value);
                TrimCache(_inviteRequests, 1024, x => x.Expires);
                _inviteRequests[request.TransactionKey] = (headers, _time.GetUtcNow().AddMinutes(4));
            }
            var response = await _transactions.SendAsync(request, Transport, progress, cancellationToken);
            if (request.Method == "INVITE" && response.StatusCode >= 300) await SendFailureAckAsync(request, response, _stop?.Token ?? default);
            if (cancellationToken.IsCancellationRequested || request.Method == "CANCEL") return response;
            if (response.StatusCode is not (401 or 407) || attempt == 2) return response;
            bool proxy = response.StatusCode == 407;
            await _authLock.WaitAsync(cancellationToken);
            try { request.Set(proxy ? "Proxy-Authorization" : "Authorization", _digest.Authorize(response.Get(proxy ? "Proxy-Authenticate" : "WWW-Authenticate"), _config.Credentials, request.Method, request.RequestUri)); }
            finally { _authLock.Release(); }
            request.Set("CSeq", NextSequence() + " " + request.Method); SetNewBranch(request);
        }
        throw new InvalidOperationException();
    }
    internal Task SendAsync(SipMessage message, CancellationToken cancellationToken = default) => Transport.SendAsync(message, cancellationToken);
    private async Task SendFailureAckAsync(SipMessage invite, SipMessage response, CancellationToken cancellationToken)
    {
        var ack = new SipMessage { StartLine = $"ACK {invite.RequestUri} SIP/2.0" };
        foreach (string name in new[] { "Via", "From", "Call-ID", "Max-Forwards", "Route" })
            foreach (string value in invite.GetAll(name)) ack.Add(name, value);
        ack.Add("To", response.Get("To")); ack.Add("CSeq", invite.CSeqNumber + " ACK");
        await SendAsync(ack, cancellationToken);
    }
    internal async Task ReplyAsync(SipMessage request, SipMessage response, CancellationToken cancellationToken = default)
    {
        TrimCache(_responses, 1024, x => x.Expires);
        _responses[request.TransactionKey + ":" + request.Get("Call-ID")] = (response, _time.GetUtcNow().AddSeconds(64));
        await SendAsync(response, cancellationToken);
    }
    private async Task OnMessageAsync(SipMessage message)
    {
        if (message.IsResponse)
        {
            if (_transactions.Receive(message)) return;
            if (message.CSeqMethod == "INVITE" && message.StatusCode >= 300 &&
                _inviteRequests.TryGetValue(message.TransactionKey, out var prior) && prior.Expires > _time.GetUtcNow() &&
                message.Get("Call-ID") == prior.Request.Get("Call-ID") && message.Get("From") == prior.Request.Get("From"))
                await SendFailureAckAsync(prior.Request, message, _stop?.Token ?? default);
            else if (_calls.TryGetValue(message.Get("Call-ID"), out var call)) await call.OnResponseAsync(message);
            else if (_retiredCalls.TryGetValue(message.Get("Call-ID"), out var retired) && retired.Expires > _time.GetUtcNow())
                await retired.Call.OnResponseAsync(message);
            return;
        }
        if (_responses.TryGetValue(message.TransactionKey + ":" + message.Get("Call-ID"), out var cached) && cached.Expires > _time.GetUtcNow())
        { await SendAsync(cached.Response); return; }
        if (_calls.TryGetValue(message.Get("Call-ID"), out var existing)) { await existing.OnRequestAsync(message); return; }
        if (message.Method == "OPTIONS") { await ReplyAsync(message, SipMessage.Response(message, 200, "OK")); return; }
        if (message.Method == "ACK") return;
        if (message.Method != "INVITE") { await ReplyAsync(message, SipMessage.Response(message, 481, "Call/Transaction Does Not Exist")); return; }
        if (message.Get("Require").Length > 0) { await ReplyAsync(message, SipMessage.Response(message, 420, "Bad Extension")); return; }
        SipCall? incoming = null;
        lock (_callsGate)
        {
            if (Status.State == SipClientState.Connected && _calls.Count < _config.MaxConcurrentCalls)
            { incoming = SipCall.Incoming(this, message); _calls[incoming.Id] = incoming; }
        }
        if (incoming is null) { await ReplyAsync(message, SipMessage.Response(message, 486, "Busy Here")); return; }
        await incoming.RingAsync();
        Publish(IncomingCall, incoming);
    }
    public SipCall CreateCall(string destination)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(destination);
        lock (_callsGate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (Status.State != SipClientState.Connected) throw new InvalidOperationException("Client is not Connected.");
            if (_calls.Count >= _config.MaxConcurrentCalls) throw new InvalidOperationException("Concurrent call limit reached.");
            string uri = destination.StartsWith("sip:", StringComparison.OrdinalIgnoreCase) ? destination : $"sip:{Uri.EscapeDataString(destination)}@{_config.SipDomain}";
            var call = SipCall.Outgoing(this, uri); _calls[call.Id] = call; return call;
        }
    }
    internal void Forget(SipCall call)
    {
        TrimCache(_retiredCalls, 256, x => x.Expires);
        lock (_callsGate)
        {
            _retiredCalls[call.Id] = (call, _time.GetUtcNow().AddSeconds(64));
            _calls.TryRemove(call.Id, out _);
        }
    }
    private void TrimCache<T>(ConcurrentDictionary<string, T> cache, int capacity, Func<T, DateTimeOffset> expires)
    {
        foreach (var entry in cache.Where(e => expires(e.Value) <= _time.GetUtcNow()).ToArray()) cache.TryRemove(entry.Key, out _);
        while (cache.Count >= capacity)
        {
            var entries = cache.ToArray();
            if (entries.Length == 0) break;
            var oldest = entries.MinBy(e => expires(e.Value)); cache.TryRemove(oldest.Key, out _);
        }
    }
    public async Task DisconnectAsync(CancellationToken cancellationToken = default)
    {
        await _lifecycle.WaitAsync(cancellationToken);
        try
        {
            if (_connection is null) return;
            Volatile.Write(ref _disconnecting, true);
            SetStatus(SipClientState.Disconnecting);
            foreach (var call in Calls) try { await call.HangupAsync(cancellationToken); } catch (Exception error) { Report("hangup", error.Message); }
            if (_transport is not null)
            {
                using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(3), _time);
                using var linked = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token, cancellationToken);
                try { await RegisterAsync(0, linked.Token); } catch (Exception error) { Report("unregister", error.Message); }
            }
            _stop?.Cancel(); await _connection; _connection = null;
            SetStatus(SipClientState.Disconnected);
        }
        finally { _lifecycle.Release(); }
    }
    private void SetStatus(SipClientState state, DateTimeOffset? expires = null, string? error = null, int? code = null)
    {
        var status = new SipClientStatus(state, _time.GetUtcNow(), expires, error, code);
        lock (_callsGate)
        {
            lock (_readinessGate)
            {
                if (state != SipClientState.Connected && _status.State == SipClientState.Connected)
                    _firstConnection = new(TaskCreationOptions.RunContinuationsAsynchronously);
                Volatile.Write(ref _status, status);
                if (state == SipClientState.Connected) _firstConnection.TrySetResult();
            }
        }
        Publish(StatusChanged, status);
    }
    internal void Report(string category, string message) => Publish(Diagnostic, new SipDiagnostic(_time.GetUtcNow(), category, message));
    internal void Publish<T>(EventHandler<T>? handlers, T value)
    {
        if (handlers is null) return;
        foreach (EventHandler<T> handler in handlers.GetInvocationList())
            try { handler(this, value); } catch { /* An observer must not break protocol state or other observers. */ }
    }
    internal static void EnsureSuccess(SipMessage message)
    { if (message.StatusCode is < 200 or >= 300) throw new SipException(message.StatusCode, $"SIP request failed with status {message.StatusCode}."); }
    internal static string NewId() => Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(12));
    private static string HostPort(string host, int port) => (host.Contains(':') ? $"[{host}]" : host) + ":" + port;
    public async ValueTask DisposeAsync()
    {
        if (_disposed) return; _disposed = true;
        await DisconnectAsync(); _stop?.Dispose();
    }
}
