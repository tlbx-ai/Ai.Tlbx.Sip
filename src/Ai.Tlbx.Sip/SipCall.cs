using System.Text;
using Ai.Tlbx.Sip.Protocol;

namespace Ai.Tlbx.Sip;

public sealed class SipCall : IAsyncDisposable
{
    private readonly SipClient _client;
    private readonly object _gate = new();
    private readonly string _localTag = SipClient.NewId();
    private readonly CancellationTokenSource _stop = new();
    private readonly CancellationTokenSource _dialCancellation = new();
    private readonly TaskCompletionSource _ack = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource<SipCallStatus> _completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private SipCallStatus _status;
    private SipMessage? _invite, _answer;
    private SipMessage? _lastResponse;
    private string _localHeader = "", _remoteHeader, _remoteTarget;
    private string[] _routes = [];
    private int _remoteSequence = -1;
    private Task? _dialTask;
    private Task? _hangupTask;
    private bool _ending;
    private readonly Dictionary<string, Task> _closingDialogs = [];
    private SipCall(SipClient client, string id, SipCallDirection direction, string remote)
    {
        _client = client; Id = id; Direction = direction; _remoteTarget = remote; _remoteHeader = "<" + remote + ">";
        _status = new(direction == SipCallDirection.Incoming ? SipCallState.Incoming : SipCallState.Created, client.Time.GetUtcNow());
        Audio = new(client.Config, client.Time, client.MediaAddress, error => client.Report("media", error));
    }
    public string Id { get; }
    public SipCallDirection Direction { get; }
    public string RemoteUri => SipMessage.UriFromHeader(_remoteHeader);
    public SipCallStatus Status => Volatile.Read(ref _status);
    public SipCallAudio Audio { get; }
    public SipMediaMetrics Metrics => Audio.Metrics;
    public Task<SipCallStatus> Completion => _completion.Task;
    public event EventHandler<SipCallStatus>? StatusChanged;
    public event EventHandler<SipCallStatus>? Ended;
    internal static SipCall Outgoing(SipClient client, string uri) => new(client, SipClient.NewId(), SipCallDirection.Outgoing, uri);
    internal static SipCall Incoming(SipClient client, SipMessage invite)
    {
        var call = new SipCall(client, invite.Get("Call-ID"), SipCallDirection.Incoming, SipMessage.UriFromHeader(invite.Get("Contact")));
        call._invite = invite; call._remoteHeader = invite.Get("From");
        call._localHeader = invite.Get("To") + ";tag=" + call._localTag;
        call._routes = invite.GetAll("Record-Route").ToArray(); call._remoteSequence = invite.CSeqNumber;
        return call;
    }
    internal async Task RingAsync()
    {
        await _client.ReplyAsync(_invite!, SipMessage.Response(_invite!, 100, "Trying"));
        await _client.ReplyAsync(_invite!, SipMessage.Response(_invite!, 180, "Ringing", _localTag));
    }
    public Task StartAsync(CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            if (Direction != SipCallDirection.Outgoing || Status.State != SipCallState.Created) throw new InvalidOperationException("Only a new outgoing call can be started.");
            SetStatus(SipCallState.Calling);
            return _dialTask = DialAsync(cancellationToken);
        }
    }
    private async Task DialAsync(CancellationToken cancellationToken)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _dialCancellation.Token, _stop.Token);
        try
        {
            _invite = _client.Request("INVITE", _remoteTarget, Id, _localTag, _remoteHeader);
            _localHeader = _invite.Get("From");
            _invite.Add("Content-Type", "application/sdp");
            _invite.Body = Encoding.UTF8.GetBytes(SdpSession.Offer(_client.MediaAddress, Audio.Port, Audio.MasterKey, _client.Time.GetUtcNow().ToUnixTimeMilliseconds()));
            var response = await _client.RequestAuthenticatedAsync(_invite, p =>
            {
                if (p.StatusCode >= 200) _lastResponse = p;
                lock (_gate)
                    if (p.StatusCode is >= 100 and < 200 && !_ending && Status.State is SipCallState.Calling or SipCallState.Ringing)
                        SetStatus(p.StatusCode == 180 ? SipCallState.Ringing : Status.State, p.StatusCode, phrase: p.ReasonPhrase);
            }, linked.Token);
            if (response.StatusCode >= 300)
            {
                bool wasCancelled = cancellationToken.IsCancellationRequested || _dialCancellation.IsCancellationRequested;
                string error = response.StatusCode switch
                {
                    404 or 604 => $"Destination not found (SIP {response.StatusCode} {response.ReasonPhrase}).",
                    484 => $"Destination number is incomplete (SIP 484 {response.ReasonPhrase}).",
                    _ => $"Call rejected (SIP {response.StatusCode} {response.ReasonPhrase})."
                };
                await EndAsync(wasCancelled ? SipCallEndReason.Cancelled : response.StatusCode is 486 or 600 ? SipCallEndReason.Busy : response.StatusCode == 487 ? SipCallEndReason.Cancelled : SipCallEndReason.Rejected, response.StatusCode, error, response.ReasonPhrase);
                if (wasCancelled) throw new OperationCanceledException(linked.Token);
                throw new SipException(response.StatusCode, error);
            }
            SetRemoteDialog(response);
            await AckAsync(response);
            var session = SdpSession.Parse(response.Body, _client.Config.MediaSecurity);
            bool cancel;
            lock (_gate)
            {
                if (Status.State == SipCallState.Ended) return;
                cancel = _ending || linked.IsCancellationRequested;
                if (!cancel) { Audio.Start(session); SetStatus(SipCallState.Established, response.StatusCode, phrase: response.ReasonPhrase); }
            }
            if (cancel)
            {
                await SendByeAsync(CancellationToken.None); await EndAsync(SipCallEndReason.Cancelled);
                throw new OperationCanceledException(linked.Token);
            }
        }
        catch (OperationCanceledException)
        {
            if (Status.State != SipCallState.Ended)
            {
                if (_lastResponse is { StatusCode: >= 200 and < 300 } accepted) await CloseAcceptedDialogAsync(accepted);
                await EndAsync(SipCallEndReason.Cancelled);
            }
            throw;
        }
        catch (Exception error)
        {
            if (Status.State != SipCallState.Ended && _lastResponse is { StatusCode: >= 200 and < 300 } accepted)
                await CloseAcceptedDialogAsync(accepted);
            if (Status.State != SipCallState.Ended) await EndAsync(error is TimeoutException ? SipCallEndReason.Timeout : SipCallEndReason.ProtocolError, error: error.Message);
            throw;
        }
    }
    public async Task AnswerAsync(CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            if (Direction != SipCallDirection.Incoming || Status.State != SipCallState.Incoming) throw new InvalidOperationException("Call is not awaiting an answer.");
            SetStatus(SipCallState.Answering);
        }
        try
        {
            var remote = SdpSession.Parse(_invite!.Body, _client.Config.MediaSecurity);
            _answer = SipMessage.Response(_invite, 200, "OK", _localTag);
            _answer.Add("Contact", _client.Contact); _answer.Add("Content-Type", "application/sdp");
            _answer.Body = Encoding.UTF8.GetBytes(SdpSession.Answer(_client.MediaAddress, Audio.Port, Audio.MasterKey,
                _client.Time.GetUtcNow().ToUnixTimeMilliseconds(), remote));
            using var deadline = new CancellationTokenSource(_client.Config.TransactionTimeout, _client.Time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token, cancellationToken, _stop.Token);
            TimeSpan interval = _client.Config.InitialRetransmitInterval;
            await _client.ReplyAsync(_invite, _answer, linked.Token);
            while (!_ack.Task.IsCompleted)
            {
                using var tick = CancellationTokenSource.CreateLinkedTokenSource(linked.Token);
                var delay = Task.Delay(interval, _client.Time, tick.Token);
                var done = await Task.WhenAny(_ack.Task, delay);
                if (done == _ack.Task) { tick.Cancel(); break; }
                await delay;
                await _client.SendAsync(_answer, linked.Token);
                interval = TimeSpan.FromMilliseconds(Math.Min(interval.TotalMilliseconds * 2, 4000));
            }
            lock (_gate)
            {
                if (_stop.IsCancellationRequested || _ending) return;
                Audio.Start(remote); SetStatus(SipCallState.Established, 200);
            }
        }
        catch (Exception error)
        {
            if (_answer is null && Status.State != SipCallState.Ended)
                await _client.ReplyAsync(_invite!, SipMessage.Response(_invite!, 488, "Not Acceptable Here", _localTag));
            await EndAsync(error is OperationCanceledException ? SipCallEndReason.Timeout : SipCallEndReason.ProtocolError, error: error.Message);
            throw;
        }
    }
    public async Task RejectAsync(int statusCode = 486, CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            if (Direction != SipCallDirection.Incoming || Status.State != SipCallState.Incoming) throw new InvalidOperationException("Call cannot be rejected in its current state.");
            if (statusCode is < 400 or > 699) throw new ArgumentOutOfRangeException(nameof(statusCode));
            SetStatus(SipCallState.Ending);
        }
        try { await _client.ReplyAsync(_invite!, SipMessage.Response(_invite!, statusCode, statusCode == 486 ? "Busy Here" : "Decline", _localTag), cancellationToken); }
        finally { await EndAsync(SipCallEndReason.Rejected, statusCode); }
    }
    public Task HangupAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        // Caller cancellation only stops waiting; the call still owns bounded wire cleanup.
        lock (_gate) return (_hangupTask ??= HangupCoreAsync()).WaitAsync(cancellationToken);
    }
    private async Task HangupCoreAsync()
    {
        SipCallState state;
        bool alreadyEnding;
        lock (_gate)
        {
            state = Status.State; alreadyEnding = state is SipCallState.Ended or SipCallState.Ending || _ending;
            _ending = true;
        }
        if (alreadyEnding) { await Completion; return; }
        if (state == SipCallState.Created) { await EndAsync(SipCallEndReason.Cancelled); return; }
        if (state == SipCallState.Incoming) { await RejectAsync(603); return; }
        if (state is SipCallState.Calling or SipCallState.Ringing)
        {
            _dialCancellation.Cancel();
            if (_dialTask is not null) try { await _dialTask; }
                catch (OperationCanceledException) { }
                catch (SipException e) when (e.StatusCode == 487) { }
            return;
        }
        if (state == SipCallState.Answering) await Task.WhenAny(_ack.Task, Completion);
        lock (_gate)
        {
            if (Status.State != SipCallState.Ended) SetStatus(SipCallState.Ending);
        }
        if (Status.State == SipCallState.Ended) { await Completion; return; }
        try { await SendByeAsync(CancellationToken.None); }
        finally { await EndAsync(SipCallEndReason.LocalHangup); }
    }
    private Task SendByeAsync(CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            string tag = SipMessage.Parameter(_remoteHeader, "tag");
            if (_closingDialogs.TryGetValue(tag, out var existing)) return existing;
            return _closingDialogs[tag] = SendByeCoreAsync(DialogRequest("BYE"), cancellationToken);
        }
    }
    private async Task SendByeCoreAsync(SipMessage request, CancellationToken cancellationToken)
    { var response = await _client.RequestAuthenticatedAsync(request, null, cancellationToken); SipClient.EnsureSuccess(response); }
    private SipMessage DialogRequest(string method, int? sequence = null)
    {
        var request = _client.Request(method, _remoteTarget, Id, _localTag, _remoteHeader, sequence);
        request.Set("From", _localHeader);
        foreach (string route in _routes) request.Add("Route", route);
        return request;
    }
    private Task AckAsync(SipMessage response)
    {
        var ack = DialogRequest("ACK", response.CSeqNumber);
        return _client.SendAsync(ack);
    }
    private void SetRemoteDialog(SipMessage response)
    {
        _remoteHeader = response.Get("To");
        _remoteTarget = SipMessage.UriFromHeader(response.Get("Contact"));
        _routes = response.GetAll("Record-Route").Reverse().ToArray();
    }
    private async Task CloseAcceptedDialogAsync(SipMessage response)
    {
        SetRemoteDialog(response);
        try { await AckAsync(response); await SendByeAsync(CancellationToken.None); }
        catch (Exception error) { _client.Report("call-cleanup", error.Message); }
    }
    internal async Task OnResponseAsync(SipMessage response)
    {
        if (_invite is null || response.CSeqMethod != "INVITE" || response.CSeqNumber != _invite.CSeqNumber ||
            SipMessage.Parameter(response.Get("From"), "tag") != _localTag ||
            SipMessage.Parameter(response.Get("Via"), "branch") != SipMessage.Parameter(_invite.Get("Via"), "branch")) return;
        if (response.StatusCode is >= 200 and < 300)
        {
            if (Status.State == SipCallState.Ended)
            {
                SetRemoteDialog(response); await AckAsync(response);
                _ = CloseLateDialogAsync();
            }
            else await AckAsync(response);
        }
    }
    private async Task CloseLateDialogAsync()
    {
        // Never wait for a BYE transaction on the SIP receive loop itself.
        try { await SendByeAsync(CancellationToken.None); }
        catch (Exception error) { _client.Report("late-dialog", error.Message); }
    }
    internal async Task OnRequestAsync(SipMessage request)
    {
        bool matches = SipMessage.Parameter(request.Get("To"), "tag") == _localTag &&
            SipMessage.Parameter(request.Get("From"), "tag") == SipMessage.Parameter(_remoteHeader, "tag");
        if (request.Method == "CANCEL" && _invite is not null && request.CSeqNumber == _invite.CSeqNumber &&
            SipMessage.Parameter(request.Get("Via"), "branch") == SipMessage.Parameter(_invite.Get("Via"), "branch"))
        {
            await _client.ReplyAsync(request, SipMessage.Response(request, 200, "OK"));
            if (Status.State == SipCallState.Incoming)
            {
                await _client.ReplyAsync(_invite, SipMessage.Response(_invite, 487, "Request Terminated", _localTag));
                await EndAsync(SipCallEndReason.Cancelled, 487);
            }
            return;
        }
        if (!matches)
        { if (request.Method != "ACK") await _client.ReplyAsync(request, SipMessage.Response(request, 481, "Call/Transaction Does Not Exist")); return; }
        if (request.Method == "ACK") { if (_invite?.CSeqNumber == request.CSeqNumber) _ack.TrySetResult(); return; }
        if (request.CSeqNumber <= _remoteSequence)
        { await _client.ReplyAsync(request, SipMessage.Response(request, 500, "CSeq Out of Order")); return; }
        _remoteSequence = request.CSeqNumber;
        if (request.Method == "BYE")
        { await _client.ReplyAsync(request, SipMessage.Response(request, 200, "OK")); await EndAsync(SipCallEndReason.RemoteHangup); }
        else if (request.Method == "OPTIONS") await _client.ReplyAsync(request, SipMessage.Response(request, 200, "OK"));
        else await _client.ReplyAsync(request, SipMessage.Response(request, request.Method == "INVITE" ? 488 : 405, "Not Supported", _localTag));
    }
    internal async Task EndAsync(SipCallEndReason reason, int? code = null, string? error = null, string? phrase = null)
    {
        bool ownsCleanup;
        lock (_gate)
        {
            ownsCleanup = Status.State != SipCallState.Ended;
            if (ownsCleanup)
            {
                _stop.Cancel(); SetStatus(SipCallState.Ended, code, reason, error, phrase); _client.Forget(this);
            }
        }
        if (!ownsCleanup) { await Completion; return; }
        await Audio.DisposeAsync(); _completion.TrySetResult(Status); Publish(Ended, Status);
    }
    private void SetStatus(SipCallState state, int? code = null, SipCallEndReason? reason = null, string? error = null, string? phrase = null)
    {
        var status = new SipCallStatus(state, _client.Time.GetUtcNow(), reason, code, error, phrase);
        Volatile.Write(ref _status, status); Publish(StatusChanged, status);
    }
    private void Publish(EventHandler<SipCallStatus>? handlers, SipCallStatus status)
    { foreach (EventHandler<SipCallStatus> h in handlers?.GetInvocationList() ?? []) try { h(this, status); } catch { } }
    public async ValueTask DisposeAsync()
    { if (Status.State != SipCallState.Ended) await HangupAsync(); await Audio.DisposeAsync(); }
}
