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
    // RFC 3264 section 8: one SDP origin per call; the version increases with every new description.
    private long _sdpId, _sdpVersion;
    private SipMediaDirection _localDirection = SipMediaDirection.SendReceive;
    private SipMediaDirection _remoteDirection = SipMediaDirection.SendReceive;
    private (int Sequence, TaskCompletionSource<SipMessage> Ack, bool OfferInAck)? _pendingRefresh;
    private readonly SemaphoreSlim _renegotiation = new(1, 1);
    private bool _outgoingRefresh;
    private int _lastRefreshSequence = -1;
    private SipMessage? _lastRefreshAck;
    private TaskCompletionSource<(int Code, string Phrase)>? _transferResult;
    private SipMessage? _transferRequest;
    private bool _earlierReferSubscriptionUnresolved;
    private bool _transferSubscriptionTerminated;
    private SipPartyIdentity _remoteIdentity;
    /// <summary>RFC 3261 section 14.1: after 491 Request Pending the re-INVITE is retried after a random 2.1 to 4 seconds.</summary>
    internal static TimeSpan GlareRetryMinimum = TimeSpan.FromMilliseconds(2100), GlareRetryMaximum = TimeSpan.FromMilliseconds(4000);
    private SipCall(SipClient client, string id, SipCallDirection direction, string remote)
    {
        _client = client; Id = id; Direction = direction; _remoteTarget = remote; _remoteHeader = "<" + remote + ">";
        _status = new(direction == SipCallDirection.Incoming ? SipCallState.Incoming : SipCallState.Created, client.Time.GetUtcNow());
        _remoteIdentity = SipPartyIdentity.Parse("<" + remote + ">") ?? new(remote, null, null, false);
        Audio = new(client.Config, client.Time, client.MediaAddress, error => client.Report("media", error));
    }
    public string Id { get; }
    public SipCallDirection Direction { get; }
    public string RemoteUri => SipMessage.UriFromHeader(_remoteHeader);
    /// <summary>
    /// The remote party: for incoming calls the caller, preferring the PBX-asserted identity
    /// (P-Asserted-Identity, RFC 3325; then Remote-Party-ID) over the From header; for outgoing calls the
    /// called party, updated from P-Asserted-Identity or To of the answer.
    /// </summary>
    public SipPartyIdentity RemoteIdentity { get { lock (_gate) return _remoteIdentity; } }
    /// <summary>
    /// Incoming calls: the number originally dialled, before any forwarding. Taken from the oldest Diversion
    /// entry (RFC 5806), else the first History-Info entry (RFC 7044), else the To header. Null for outgoing calls.
    /// </summary>
    public SipPartyIdentity? CalledIdentity { get; private set; }
    /// <summary>Incoming calls: forwarding steps from Diversion, most recent first (RFC 5806). Empty if the call was not forwarded or the PBX does not signal it.</summary>
    public IReadOnlyList<SipPartyIdentity> Diversions { get; private set; } = [];
    /// <summary>Incoming calls: the headers of the initial INVITE in received order, without authorization headers, for PBX-specific information.</summary>
    public IReadOnlyList<KeyValuePair<string, string>> InitialHeaders { get; private set; } = [];
    private static SipPartyIdentity? FirstIdentity(IEnumerable<string> headerValues)
    {
        var parties = headerValues.SelectMany(SipPartyIdentity.SplitEntries).Select(SipPartyIdentity.Parse).OfType<SipPartyIdentity>().ToList();
        // RFC 3325 allows one sip: and one tel: identity; prefer an entry that carries a number.
        return parties.FirstOrDefault(p => p.Number is not null || p.Anonymous) ?? parties.FirstOrDefault();
    }
    private static SipPartyIdentity? OriginalCalled(SipMessage invite, IReadOnlyList<SipPartyIdentity> diversions, string ownUser)
    {
        if (diversions.Count > 0) return diversions[^1];
        var history = invite.GetAll("History-Info").SelectMany(SipPartyIdentity.SplitEntries)
            .Select(e => (Key: SipPartyIdentity.IndexKey(SipPartyIdentity.HeaderParameter(e, "index") is { Length: > 0 } i ? i : "999"), Party: SipPartyIdentity.Parse(e)))
            .Where(e => e.Party is not null).ToList();
        if (history.Count > 0)
        {
            history.Sort((a, b) => SipPartyIdentity.CompareIndex(a.Key, b.Key));
            return history[0].Party;
        }
        // Many PBXs address the endpoint by its own registration (for example its account name) and send the
        // dialled number nowhere else; that is not the dialled number, so report it as unknown.
        var to = SipPartyIdentity.Parse(invite.Get("To")) ?? SipPartyIdentity.Parse("<" + invite.RequestUri + ">");
        return to is null || string.Equals(to.Number, ownUser, StringComparison.OrdinalIgnoreCase) ? null : to;
    }
    public SipCallStatus Status => Volatile.Read(ref _status);
    public SipCallAudio Audio { get; }
    public SipMediaMetrics Metrics => Audio.Metrics;
    public Task<SipCallStatus> Completion => _completion.Task;
    /// <summary>Direction the remote side last declared in its SDP. SendOnly or Inactive means the remote side holds the call.</summary>
    public SipMediaDirection RemoteMediaDirection { get { lock (_gate) return _remoteDirection; } }
    /// <summary>Raised after a re-INVITE or UPDATE changed the session, for example when the PBX holds or resumes the call.</summary>
    public event EventHandler<SipMediaDirection>? MediaChanged;
    /// <summary>True while this side holds the call (it offered sendonly or inactive).</summary>
    public bool IsOnHold { get { lock (_gate) return _localDirection is SipMediaDirection.SendOnly or SipMediaDirection.Inactive; } }
    /// <summary>
    /// Holds the call with a re-INVITE that offers <c>sendonly</c> (RFC 3264 section 8.4, RFC 6337 section 5.3).
    /// The remote party stops sending, while this side may still play hold music or announcements through
    /// <see cref="Audio"/>. Completes after the remote answer is applied; if the remote side rejects the
    /// re-INVITE the call continues unchanged and a <see cref="SipException"/> carries the SIP status.
    /// </summary>
    public Task HoldAsync(CancellationToken cancellationToken = default) => RenegotiateAsync(SipMediaDirection.SendOnly, cancellationToken);
    /// <summary>Resumes a held call with a re-INVITE that offers <c>sendrecv</c>.</summary>
    public Task ResumeAsync(CancellationToken cancellationToken = default) => RenegotiateAsync(SipMediaDirection.SendReceive, cancellationToken);
    public event EventHandler<SipCallStatus>? StatusChanged;
    public event EventHandler<SipCallStatus>? Ended;
    internal static SipCall Outgoing(SipClient client, string uri) => new(client, SipClient.NewId(), SipCallDirection.Outgoing, uri);
    internal static SipCall Incoming(SipClient client, SipMessage invite)
    {
        var call = new SipCall(client, invite.Get("Call-ID"), SipCallDirection.Incoming, SipMessage.UriFromHeader(invite.Get("Contact")));
        call._invite = invite; call._remoteHeader = invite.Get("From");
        call._localHeader = invite.Get("To") + ";tag=" + call._localTag;
        call._routes = invite.GetAll("Record-Route").ToArray(); call._remoteSequence = invite.CSeqNumber;
        call._remoteIdentity = FirstIdentity(invite.GetAll("P-Asserted-Identity")) ?? FirstIdentity(invite.GetAll("Remote-Party-ID")) ??
            SipPartyIdentity.Parse(invite.Get("From")) ?? call._remoteIdentity;
        call.Diversions = invite.GetAll("Diversion").SelectMany(SipPartyIdentity.SplitEntries).Select(SipPartyIdentity.Parse).OfType<SipPartyIdentity>().ToArray();
        call.CalledIdentity = OriginalCalled(invite, call.Diversions, client.Config.User);
        call.InitialHeaders = invite.Headers.Where(h => !h.Key.Equals("Authorization", StringComparison.OrdinalIgnoreCase) &&
            !h.Key.Equals("Proxy-Authorization", StringComparison.OrdinalIgnoreCase)).ToArray();
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
            _invite.Body = Encoding.UTF8.GetBytes(SdpSession.Offer(_client.MediaAddress, Audio.Port, Audio.MasterKey, NewSdpOrigin(), version: _sdpVersion));
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
            var answered = FirstIdentity(response.GetAll("P-Asserted-Identity")) ?? SipPartyIdentity.Parse(response.Get("To"));
            if (answered is not null) lock (_gate) _remoteIdentity = answered;
            var session = SdpSession.Parse(response.Body, _client.Config.MediaSecurity);
            bool cancel;
            lock (_gate)
            {
                if (Status.State == SipCallState.Ended) return;
                cancel = _ending || linked.IsCancellationRequested;
                if (!cancel)
                {
                    _remoteDirection = session.Direction;
                    Audio.Start(session, SdpSession.AnswerDirection(session, _localDirection));
                    SetStatus(SipCallState.Established, response.StatusCode, phrase: response.ReasonPhrase);
                }
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
                NewSdpOrigin(), remote, _localDirection, _sdpVersion));
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
                _remoteDirection = remote.Direction;
                Audio.Start(remote, SdpSession.AnswerDirection(remote, _localDirection)); SetStatus(SipCallState.Established, 200);
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
        SipMessage? refreshAck;
        lock (_gate) refreshAck = response.CSeqMethod == "INVITE" && response.StatusCode is >= 200 and < 300 &&
            response.CSeqNumber == _lastRefreshSequence ? _lastRefreshAck : null;
        if (refreshAck is not null) { await _client.SendAsync(refreshAck); return; }
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
        if (request.Method == "ACK")
        {
            if (_invite?.CSeqNumber == request.CSeqNumber) _ack.TrySetResult();
            else lock (_gate) if (_pendingRefresh is { } pending && pending.Sequence == request.CSeqNumber) pending.Ack.TrySetResult(request);
            return;
        }
        if (request.CSeqNumber <= _remoteSequence)
        { await _client.ReplyAsync(request, SipMessage.Response(request, 500, "CSeq Out of Order")); return; }
        _remoteSequence = request.CSeqNumber;
        if (request.Method == "BYE")
        { await _client.ReplyAsync(request, SipMessage.Response(request, 200, "OK")); await EndAsync(SipCallEndReason.RemoteHangup); }
        else if (request.Method == "OPTIONS") await _client.ReplyAsync(request, SipMessage.Response(request, 200, "OK"));
        else if (request.Method is "INVITE" or "UPDATE") await OnSessionRefreshAsync(request);
        else if (request.Method == "NOTIFY") await OnNotifyAsync(request);
        else await _client.ReplyAsync(request, SipMessage.Response(request, 405, "Method Not Allowed", _localTag));
    }
    /// <summary>
    /// Sends a re-INVITE with a new offer for the given local direction (RFC 3261 section 14.1).
    /// Only one re-INVITE runs at a time. 491 is retried after a random delay; 408 and 481 end the
    /// dialog with BYE (RFC 3261 section 12.2.1.2); any other failure leaves the session unchanged.
    /// </summary>
    private async Task RenegotiateAsync(SipMediaDirection local, CancellationToken cancellationToken)
    {
        await _renegotiation.WaitAsync(cancellationToken);
        try
        {
            for (int attempt = 0; ; attempt++)
            {
                SipMessage request;
                lock (_gate)
                {
                    if (Status.State != SipCallState.Established || _ending) throw new InvalidOperationException("Only an established call can be held or resumed.");
                    if (_pendingRefresh is not null) throw new InvalidOperationException("A remote re-INVITE is still in progress.");
                    _outgoingRefresh = true;
                    request = DialogRequest("INVITE");
                    request.Add("Content-Type", "application/sdp");
                    request.Body = Encoding.UTF8.GetBytes(SdpSession.Offer(_client.MediaAddress, Audio.Port, Audio.MasterKey,
                        NewSdpOrigin(), Audio.ControlPort, local, ++_sdpVersion));
                }
                SipMessage response;
                try
                {
                    using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _stop.Token);
                    response = await _client.RequestAuthenticatedAsync(request, null, linked.Token);
                }
                catch (TimeoutException error)
                {
                    lock (_gate) _outgoingRefresh = false;
                    await TerminateDialogAsync("re-INVITE timed out: " + error.Message);
                    throw new SipException(408, "The remote side did not answer the re-INVITE; the call was ended.");
                }
                catch { lock (_gate) _outgoingRefresh = false; throw; }
                if (response.StatusCode is >= 200 and < 300)
                {
                    SdpSession answer;
                    lock (_gate)
                    {
                        _lastRefreshSequence = response.CSeqNumber;
                        string contact = response.Get("Contact");
                        if (contact.Length > 0) _remoteTarget = SipMessage.UriFromHeader(contact);
                        _lastRefreshAck = DialogRequest("ACK", response.CSeqNumber);
                    }
                    await _client.SendAsync(_lastRefreshAck);
                    try { answer = SdpSession.Parse(response.Body, _client.Config.MediaSecurity); }
                    catch (Exception error) when (error is InvalidDataException or NotSupportedException or FormatException)
                    {
                        lock (_gate) _outgoingRefresh = false;
                        // RFC 3261 section 14.1: an unusable answer after the ACK ends the session.
                        await TerminateDialogAsync("Unusable re-INVITE answer: " + error.Message);
                        throw new SipException(488, "The remote answer to the re-INVITE was not usable; the call was ended.");
                    }
                    lock (_gate)
                    {
                        _localDirection = local; _remoteDirection = answer.Direction; _outgoingRefresh = false;
                        Audio.Update(answer, SdpSession.AnswerDirection(answer, local));
                    }
                    Publish(MediaChanged, answer.Direction);
                    return;
                }
                lock (_gate) _outgoingRefresh = false;
                if (response.StatusCode == 491 && attempt < 2)
                {
                    double wait = GlareRetryMinimum.TotalMilliseconds + Random.Shared.NextDouble() * (GlareRetryMaximum - GlareRetryMinimum).TotalMilliseconds;
                    await Task.Delay(TimeSpan.FromMilliseconds(wait), _client.Time, cancellationToken);
                    continue;
                }
                if (response.StatusCode is 408 or 481)
                {
                    await TerminateDialogAsync($"re-INVITE answered {response.StatusCode} {response.ReasonPhrase}");
                    throw new SipException(response.StatusCode, $"The dialog no longer exists (SIP {response.StatusCode}); the call was ended.");
                }
                throw new SipException(response.StatusCode, $"Re-INVITE rejected (SIP {response.StatusCode} {response.ReasonPhrase}); the call continues unchanged.");
            }
        }
        finally { _renegotiation.Release(); }
    }
    /// <summary>
    /// Blind transfer (RFC 3515, RFC 5589 section 6): asks the PBX with REFER to connect the remote party
    /// to <paramref name="target"/>, an extension or number in the registrar's domain or a full sip:/sips: URI.
    /// The PBX reports progress with NOTIFY (message/sipfrag). On a 2xx result this side ends its leg with BYE
    /// and the call ends as <see cref="SipCallEndReason.Transferred"/>. If the REFER or the target fails, the
    /// call stays with this side; hold it first with <see cref="HoldAsync"/> if the caller should hear hold audio.
    /// Some PBXs report success when the target starts ringing, so success does not establish that the target answered.
    /// </summary>
    public Task<SipTransferResult> TransferAsync(string target, CancellationToken cancellationToken = default) =>
        TransferCoreAsync(TransferTargetUri(target), null, cancellationToken);
    /// <summary>
    /// Attended transfer (RFC 5589 section 7, RFC 3891): connects the remote party of this call with the remote
    /// party of <paramref name="consultation"/>, an established call of the same client in which this side has
    /// announced the caller. This call should be held during the consultation (<see cref="HoldAsync"/>). The REFER
    /// carries a Replaces header for the consultation dialog, so the PBX joins both remote parties and this side
    /// leaves both calls. On a 2xx result this call ends as <see cref="SipCallEndReason.Transferred"/>; the
    /// consultation call is ended by the PBX, or by this side if the PBX leaves it open. If the transfer fails,
    /// both calls stay as they are and the application decides (resume this call, end the consultation).
    /// </summary>
    public Task<SipTransferResult> TransferToCallAsync(SipCall consultation, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(consultation);
        if (ReferenceEquals(consultation, this)) throw new ArgumentException("A call cannot be transferred to itself.", nameof(consultation));
        if (!ReferenceEquals(consultation._client, _client)) throw new ArgumentException("Both calls must belong to the same SIP client.", nameof(consultation));
        if (consultation.Status.State != SipCallState.Established) throw new InvalidOperationException("The consultation call is not established.");
        return TransferCoreAsync(consultation.ReplacesUri(), consultation, cancellationToken);
    }
    /// <summary>Target URI of this dialog with an RFC 3891 Replaces header, as seen from the remote side's dialog state.</summary>
    internal string ReplacesUri()
    {
        lock (_gate)
        {
            string remoteTag = SipMessage.Parameter(_remoteHeader, "tag");
            if (remoteTag.Length == 0) throw new InvalidOperationException("The consultation dialog has no remote tag.");
            string uri = SipMessage.UriFromHeader(_remoteHeader).Split('?')[0];
            // RFC 3891 section 3: to-tag matches the local tag and from-tag the remote tag of the dialog at the UA that receives the INVITE with Replaces.
            return $"{uri}?Replaces={Uri.EscapeDataString(Id)}%3Bto-tag%3D{Uri.EscapeDataString(remoteTag)}%3Bfrom-tag%3D{Uri.EscapeDataString(_localTag)}";
        }
    }
    private async Task<SipTransferResult> TransferCoreAsync(string targetUri, SipCall? consultation, CancellationToken cancellationToken)
    {
        await _renegotiation.WaitAsync(cancellationToken);
        try
        {
            SipMessage request; TaskCompletionSource<(int Code, string Phrase)> result;
            lock (_gate)
            {
                if (Status.State != SipCallState.Established || _ending) throw new InvalidOperationException("Only an established call can be transferred.");
                result = _transferResult = new(TaskCreationOptions.RunContinuationsAsynchronously);
                request = _transferRequest = DialogRequest("REFER");
                _transferSubscriptionTerminated = false;
                request.Add("Refer-To", "<" + targetUri + ">");
                request.Add("Referred-By", $"<sip:{Uri.EscapeDataString(_client.Config.User)}@{_client.Config.SipDomain}>");
            }
            bool referRejected = false;
            try
            {
                SipMessage response;
                using (var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _stop.Token))
                {
                    try { response = await _client.RequestAuthenticatedAsync(request, null, linked.Token); }
                    catch (TimeoutException) { return new(SipTransferOutcome.Failed, 408, "The PBX did not answer the REFER."); }
                }
                if (response.StatusCode >= 300)
                {
                    // An intermediary can report a timeout after the peer accepted the REFER.
                    referRejected = response.StatusCode is not (408 or 504);
                    return new(SipTransferOutcome.Failed, response.StatusCode, response.ReasonPhrase);
                }
                // The target may ring for up to the call answer timeout before the PBX sends the final NOTIFY.
                using var deadline = new CancellationTokenSource(_client.Config.CallAnswerTimeout + _client.Config.TransactionTimeout, _client.Time);
                using var wait = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token, _stop.Token);
                (int Code, string Phrase) final;
                try { final = await result.Task.WaitAsync(wait.Token); }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                {
                    return new(SipTransferOutcome.Unknown, null, Status.State == SipCallState.Ended
                        ? "The call ended before the PBX reported the transfer result."
                        : "The PBX accepted the transfer but reported no final result.");
                }
                if (final.Code == 0) return new(SipTransferOutcome.Unknown, null, final.Phrase);
                if (final.Code is < 200 or >= 300) return new(SipTransferOutcome.Failed, final.Code, final.Phrase);
                // RFC 5589 section 6: after a successful transfer the transferor ends its dialog.
                bool established;
                lock (_gate) { established = Status.State == SipCallState.Established && !_ending; if (established) { _ending = true; SetStatus(SipCallState.Ending); } }
                if (established)
                {
                    try { await SendByeAsync(CancellationToken.None); }
                    catch (Exception error) { _client.Report("transfer", error.Message); }
                    finally { await EndAsync(SipCallEndReason.Transferred, final.Code, phrase: final.Phrase); }
                }
                if (consultation is not null)
                {
                    // The PBX normally ends the replaced consultation dialog itself; do not leave it open.
                    using var grace = new CancellationTokenSource(_client.Config.TransactionTimeout, _client.Time);
                    try { await consultation.Completion.WaitAsync(grace.Token); }
                    catch (OperationCanceledException)
                    {
                        try { await consultation.HangupAsync(CancellationToken.None); }
                        catch (Exception error) { _client.Report("transfer", error.Message); }
                    }
                }
                return new(SipTransferOutcome.Succeeded, final.Code, final.Phrase);
            }
            finally
            {
                lock (_gate)
                {
                    if (!referRejected && !_transferSubscriptionTerminated)
                        _earlierReferSubscriptionUnresolved = true;
                    _transferResult = null;
                    _transferRequest = null;
                }
            }
        }
        finally { _renegotiation.Release(); }
    }
    private string TransferTargetUri(string target)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(target);
        if (target.Any(c => char.IsControl(c) || char.IsWhiteSpace(c) || c is '<' or '>' or '"'))
            throw new ArgumentException("Invalid transfer target.", nameof(target));
        if (target.StartsWith("sip:", StringComparison.OrdinalIgnoreCase) || target.StartsWith("sips:", StringComparison.OrdinalIgnoreCase))
            return target;
        if (target.Contains('@') || target.Contains(':')) throw new ArgumentException("Use an extension, a number or a full sip: URI.", nameof(target));
        return $"sip:{Uri.EscapeDataString(target)}@{_client.Config.SipDomain}";
    }
    /// <summary>
    /// NOTIFY for the implicit REFER subscription (RFC 3515 section 2.4.4, RFC 6665). The body is a
    /// message/sipfrag status line; a final status or a terminated subscription completes the transfer wait.
    /// </summary>
    private async Task OnNotifyAsync(SipMessage request)
    {
        string eventPackage = request.Get("Event").Split(';')[0].Trim();
        if (!eventPackage.Equals("refer", StringComparison.OrdinalIgnoreCase))
        { await _client.ReplyAsync(request, SipMessage.Response(request, 489, "Bad Event", _localTag)); return; }
        // RFC 3515 section 2.4.6 requires the REFER CSeq on later subscriptions.
        // For PBXs that always omit it, accept bare events only while this subscription is unambiguous.
        TaskCompletionSource<(int Code, string Phrase)>? pending;
        string id = SipMessage.Parameter(request.Get("Event"), "id");
        lock (_gate)
        {
            pending = _transferRequest is not null &&
                (id.Length == 0 ? !_earlierReferSubscriptionUnresolved :
                    id == _transferRequest.CSeqNumber.ToString(System.Globalization.CultureInfo.InvariantCulture))
                ? _transferResult : null;
        }
        if (pending is null)
        { await _client.ReplyAsync(request, SipMessage.Response(request, 481, "Subscription Does Not Exist", _localTag)); return; }
        if (!request.Get("Content-Type").Split(';')[0].Trim().Equals("message/sipfrag", StringComparison.OrdinalIgnoreCase))
        { await _client.ReplyAsync(request, SipMessage.Response(request, 415, "Unsupported Media Type", _localTag)); return; }
        await _client.ReplyAsync(request, SipMessage.Response(request, 200, "OK", _localTag));
        int code = 0; string phrase = "";
        string fragment = Encoding.UTF8.GetString(request.Body).Split('\n')[0].Trim();
        var parts = fragment.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length >= 2 && parts[0].StartsWith("SIP/", StringComparison.OrdinalIgnoreCase) &&
            int.TryParse(parts[1], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out int parsed))
        { code = parsed; phrase = parts.Length > 2 ? parts[2] : ""; }
        bool terminated = request.Get("Subscription-State").Split(';')[0].Trim()
            .Equals("terminated", StringComparison.OrdinalIgnoreCase);
        lock (_gate)
        {
            if (!ReferenceEquals(_transferResult, pending)) return;
            if (terminated) _transferSubscriptionTerminated = true;
            if (code is >= 200 and <= 699) pending.TrySetResult((code, phrase));
            else if (terminated) pending.TrySetResult((0, "The PBX ended the transfer subscription without a final result."));
        }
    }
    private async Task TerminateDialogAsync(string reason)
    {
        _client.Report("re-invite", reason);
        try { await SendByeAsync(CancellationToken.None); } catch (Exception error) { _client.Report("re-invite", error.Message); }
        await EndAsync(SipCallEndReason.ProtocolError, error: reason);
    }
    private long NewSdpOrigin()
    {
        lock (_gate)
        {
            if (_sdpId == 0) _sdpId = _client.Time.GetUtcNow().ToUnixTimeMilliseconds();
            return _sdpId;
        }
    }
    /// <summary>
    /// Handles a re-INVITE (RFC 3261 section 14.2) or UPDATE (RFC 3311) inside the dialog. PBXs send
    /// these to hold, resume, park or re-route a call and as session refreshes; rejecting them can drop
    /// the call. The body is an RFC 3264 offer; a re-INVITE without a body asks this side to offer and
    /// receives the answer in the ACK.
    /// </summary>
    private async Task OnSessionRefreshAsync(SipMessage request)
    {
        bool invite = request.Method == "INVITE";
        SipMessage response = BuildSessionRefreshResponse(request, invite, out bool changed);
        // Handlers run outside the call lock so they may query or control the call.
        if (changed) Publish(MediaChanged, RemoteMediaDirection);
        await _client.ReplyAsync(request, response);
        if (invite && response.StatusCode == 200) _ = AwaitRefreshAckAsync(response);
    }
    private SipMessage BuildSessionRefreshResponse(SipMessage request, bool invite, out bool changed)
    {
        changed = false;
        lock (_gate)
        {
            SipMessage response;
            if (invite && _outgoingRefresh)
                return SipMessage.Response(request, 491, "Request Pending", _localTag);
            if (Status.State != SipCallState.Established || (invite && _pendingRefresh is not null))
            {
                // RFC 3261 section 14.2: an INVITE that overlaps an unfinished INVITE transaction is retried later.
                response = SipMessage.Response(request, 500, "Server Internal Error", _localTag);
                response.Add("Retry-After", "1");
                return response;
            }
            if (request.Get("Require").Length > 0)
            {
                response = SipMessage.Response(request, 420, "Bad Extension", _localTag);
                response.Add("Unsupported", request.Get("Require"));
                return response;
            }
            SdpSession? offer = null;
            if (request.Body.Length > 0)
            {
                try { offer = SdpSession.Parse(request.Body, _client.Config.MediaSecurity); }
                catch (Exception error) when (error is InvalidDataException or NotSupportedException or FormatException)
                {
                    _client.Report("session-refresh", error.Message);
                    return SipMessage.Response(request, 488, "Not Acceptable Here", _localTag);
                }
            }
            string contact = request.Get("Contact");
            if (contact.Length > 0) _remoteTarget = SipMessage.UriFromHeader(contact);
            response = SipMessage.Response(request, 200, "OK", _localTag);
            response.Add("Contact", _client.Contact);
            if (offer is not null)
            {
                var direction = SdpSession.AnswerDirection(offer, _localDirection);
                response.Add("Content-Type", "application/sdp");
                response.Body = Encoding.UTF8.GetBytes(SdpSession.Answer(_client.MediaAddress, Audio.Port, Audio.MasterKey,
                    NewSdpOrigin(), offer, _localDirection, ++_sdpVersion, Audio.ControlPort));
                Audio.Update(offer, direction); _remoteDirection = offer.Direction; changed = true;
            }
            else if (invite)
            {
                response.Add("Content-Type", "application/sdp");
                response.Body = Encoding.UTF8.GetBytes(SdpSession.Offer(_client.MediaAddress, Audio.Port, Audio.MasterKey,
                    NewSdpOrigin(), Audio.ControlPort, _localDirection, ++_sdpVersion));
            }
            if (invite) _pendingRefresh = (request.CSeqNumber, new(TaskCreationOptions.RunContinuationsAsynchronously), offer is null);
            return response;
        }
    }
    private async Task AwaitRefreshAckAsync(SipMessage response)
    {
        // RFC 3261 section 13.3.1.4: retransmit the 2xx until the ACK arrives; without an ACK the dialog ends.
        (int Sequence, TaskCompletionSource<SipMessage> Ack, bool OfferInAck) pending;
        lock (_gate)
        {
            if (_pendingRefresh is null) return;
            pending = _pendingRefresh.Value;
        }
        try
        {
            using var deadline = new CancellationTokenSource(_client.Config.TransactionTimeout, _client.Time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token, _stop.Token);
            TimeSpan interval = _client.Config.InitialRetransmitInterval;
            while (!pending.Ack.Task.IsCompleted)
            {
                using var tick = CancellationTokenSource.CreateLinkedTokenSource(linked.Token);
                var delay = Task.Delay(interval, _client.Time, tick.Token);
                if (await Task.WhenAny(pending.Ack.Task, delay) == pending.Ack.Task) { tick.Cancel(); break; }
                await delay;
                await _client.SendAsync(response, linked.Token);
                interval = TimeSpan.FromMilliseconds(Math.Min(interval.TotalMilliseconds * 2, 4000));
            }
            var ack = await pending.Ack.Task;
            if (pending.OfferInAck)
            {
                var answer = SdpSession.Parse(ack.Body, _client.Config.MediaSecurity);
                lock (_gate) { Audio.Update(answer, SdpSession.AnswerDirection(answer, _localDirection)); _remoteDirection = answer.Direction; }
                Publish(MediaChanged, answer.Direction);
            }
        }
        catch (OperationCanceledException) when (_stop.IsCancellationRequested) { }
        catch (Exception error)
        {
            _client.Report("session-refresh", error.Message);
            if (Status.State == SipCallState.Established)
            {
                try { await SendByeAsync(CancellationToken.None); } catch (Exception bye) { _client.Report("session-refresh", bye.Message); }
                await EndAsync(SipCallEndReason.ProtocolError, error: error.Message);
            }
        }
        finally { lock (_gate) if (_pendingRefresh?.Sequence == pending.Sequence) _pendingRefresh = null; }
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
    private void Publish<T>(EventHandler<T>? handlers, T value)
    { foreach (EventHandler<T> h in handlers?.GetInvocationList() ?? []) try { h(this, value); } catch { } }
    public async ValueTask DisposeAsync()
    { if (Status.State != SipCallState.Ended) await HangupAsync(); await Audio.DisposeAsync(); }
}
