using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Channels;
using Ai.Tlbx.Sip.Protocol;

internal sealed class TestPbx : IAsyncDisposable
{
    private readonly UdpClient _sip = new(new IPEndPoint(IPAddress.Loopback, 0));
    private readonly UdpClient _rtp = new(new IPEndPoint(IPAddress.Loopback, 0));
    private readonly UdpClient _rtcp = new(new IPEndPoint(IPAddress.Loopback, 0));
    private readonly CancellationTokenSource _stop = new();
    private readonly Channel<SipMessage> _responses = Channel.CreateUnbounded<SipMessage>();
    private readonly Task _loop;
    private readonly Task _controlLoop;
    private IPEndPoint? _client, _clientMedia;
    private ushort _mediaSequence;
    private uint _mediaTimestamp;
    private SipMessage? _outgoingInvite, _lastInviteAnswer;
    public int Port => ((IPEndPoint)_sip.Client.LocalEndPoint!).Port;
    public int MediaPort => ((IPEndPoint)_rtp.Client.LocalEndPoint!).Port;
    public bool DropFirstRegister { get; init; }
    public bool RejectCredentials { get; init; }
    public bool UseG722 { get; init; }
    public int EarlyMediaPackets { get; init; }
    public bool IncludeExpiredContact { get; init; }
    public string Username { get; init; } = "test-user";
    public string Password { get; init; } = "test-password";
    public bool WaitForCancel { get; init; }
    public bool HoldProvisional { get; init; }
    public bool AnswerOnCancel { get; init; }
    public int RejectCallWith { get; init; }
    public int ProvisionalCode { get; init; } = 180;
    public int? GrantedExpirySeconds { get; init; }
    public volatile bool DropRegistrationResponses;
    public int AckRequests { get; private set; }
    private readonly System.Collections.Concurrent.ConcurrentDictionary<(string CallId, int Sequence), byte> _acknowledged = new();
    public bool HasAcknowledged(SipMessage request) => _acknowledged.ContainsKey((request.Get("Call-ID"), request.CSeqNumber));
    public SipMessage? LastRefer { get; private set; }
    public bool InjectStaleReferNotify { get; set; }
    public bool OmitReferEventId { get; set; }
    public bool KeepReferSubscriptionActive { get; set; }
    public bool NotifyBeforeReferResponse { get; set; }
    public bool ChallengeRefer { get; set; }
    public int RejectReferWith { get; set; }
    public int TransferFinalCode { get; set; } = 200;
    public bool EndReplacedDialog { get; set; } = true;
    private readonly Dictionary<string, (SipMessage Invite, SipMessage Answer)> _answered = [];
    private int _notifySequence = 100;
    private SipMessage ReferNotify(SipMessage refer, string fragment, string state)
    {
        var notify = new SipMessage { StartLine = $"NOTIFY {SipMessage.UriFromHeader(refer.Get("Contact"))} SIP/2.0" };
        notify.Add("Via", $"SIP/2.0/UDP 127.0.0.1:{Port};branch=z9hG4bK{Guid.NewGuid():N}");
        notify.Add("From", refer.Get("To")); notify.Add("To", refer.Get("From")); notify.Add("Call-ID", refer.Get("Call-ID"));
        notify.Add("CSeq", $"{++_notifySequence} NOTIFY");
        notify.Add("Event", OmitReferEventId ? "refer" : "refer;id=" + refer.CSeqNumber); notify.Add("Subscription-State", state);
        notify.Add("Content-Type", "message/sipfrag"); notify.Body = Encoding.UTF8.GetBytes(fragment + "\r\n");
        return notify;
    }
    public int ReinviteRequests { get; private set; }
    public SipMessage? LastReinvite { get; private set; }
    /// <summary>Final status codes for the next client re-INVITEs, consumed in order.</summary>
    public System.Collections.Concurrent.ConcurrentQueue<int> RejectReinvites { get; } = new();
    public int CancelRequests { get; private set; }
    public int ByeRequests { get; private set; }
    public bool CancelMatchesInvite { get; private set; }
    public TaskCompletionSource InviteReceived { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public int RegisterRequests { get; private set; }
    public int AuthenticatedRegistrations { get; private set; }
    public bool Unregistered { get; private set; }
    public TestPbx() { _loop = RunAsync(); _controlLoop = DrainControlAsync(); }
    private async Task DrainControlAsync()
    {
        try { while (!_stop.IsCancellationRequested) await _rtcp.ReceiveAsync(_stop.Token); }
        catch (OperationCanceledException) when (_stop.IsCancellationRequested) { }
        catch (ObjectDisposedException) when (_stop.IsCancellationRequested) { }
    }
    private async Task RunAsync()
    {
        try
        {
            while (!_stop.IsCancellationRequested)
            {
                var data = await _sip.ReceiveAsync(_stop.Token); _client = data.RemoteEndPoint;
                var request = SipMessage.Parse(data.Buffer);
                if (request.IsResponse) { _responses.Writer.TryWrite(request); continue; }
                if (request.Method == "ACK") { AckRequests++; _acknowledged.TryAdd((request.Get("Call-ID"), request.CSeqNumber), 0); continue; }
                if (request.Method == "REGISTER")
                {
                    RegisterRequests++; if (DropFirstRegister && RegisterRequests == 1) continue;
                    if (DropRegistrationResponses) continue;
                    if (request.Get("Authorization").Length == 0)
                    {
                        var challenge = SipMessage.Response(request, 401, "Unauthorized");
                        challenge.Add("WWW-Authenticate", "Digest realm=\"test-realm\", nonce=\"test-nonce\", algorithm=SHA-256, qop=\"auth\"");
                        await SendAsync(challenge); continue;
                    }
                    bool valid = ValidateDigest(request);
                    var response = SipMessage.Response(request, RejectCredentials || !valid ? 403 : 200, RejectCredentials || !valid ? "Forbidden" : "OK");
                    if (valid && !RejectCredentials)
                    {
                        AuthenticatedRegistrations++; Unregistered = request.Get("Expires") == "0";
                        if (IncludeExpiredContact) response.Add("Contact", "<sip:test-user@127.0.0.1:1>;expires=0");
                        string expiry = Unregistered ? "0" : GrantedExpirySeconds?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? request.Get("Expires");
                        response.Add("Expires", expiry); response.Add("Contact", request.Get("Contact") + ";expires=" + expiry);
                    }
                    await SendAsync(response);
                }
                else if (request.Method == "REFER")
                {
                    // RFC 3515: accept, then report the target's progress and result as message/sipfrag NOTIFYs.
                    if (ChallengeRefer && request.Get("Authorization").Length == 0)
                    {
                        var challenge = SipMessage.Response(request, 401, "Unauthorized");
                        challenge.Add("WWW-Authenticate", "Digest realm=\"test-realm\", nonce=\"refer-nonce\", algorithm=SHA-256, qop=\"auth\"");
                        await SendAsync(challenge); continue;
                    }
                    var previousRefer = LastRefer; LastRefer = request;
                    if (RejectReferWith > 0) { await SendAsync(SipMessage.Response(request, RejectReferWith, "Forbidden")); continue; }
                    if (!NotifyBeforeReferResponse) await SendAsync(SipMessage.Response(request, 202, "Accepted"));
                    if (InjectStaleReferNotify && previousRefer is not null)
                    {
                        var stale = ReferNotify(previousRefer, "SIP/2.0 486 Busy Here", "terminated;reason=noresource");
                        stale.Set("Event", "refer;id=" + previousRefer.CSeqNumber);
                        await SendAsync(stale);
                    }
                    await SendAsync(ReferNotify(request, "SIP/2.0 100 Trying", "active;expires=60"));
                    string state = KeepReferSubscriptionActive ? "active;expires=60" : "terminated;reason=noresource";
                    string reason = TransferFinalCode switch { 100 => "Trying", 200 => "OK", 404 => "Not Found", _ => "Busy Here" };
                    await SendAsync(ReferNotify(request, $"SIP/2.0 {TransferFinalCode} {reason}", state));
                    if (NotifyBeforeReferResponse) await SendAsync(SipMessage.Response(request, 202, "Accepted"));
                    // RFC 3891: a successful INVITE with Replaces ends the replaced dialog; the PBX sends its BYE.
                    string referTo = Uri.UnescapeDataString(request.Get("Refer-To"));
                    int replaces = referTo.IndexOf("?Replaces=", StringComparison.Ordinal);
                    if (TransferFinalCode == 200 && EndReplacedDialog && replaces > 0 &&
                        _answered.TryGetValue(referTo[(replaces + 10)..].Split(';')[0], out var replaced))
                    {
                        var bye = new SipMessage { StartLine = $"BYE {SipMessage.UriFromHeader(replaced.Invite.Get("Contact"))} SIP/2.0" };
                        bye.Add("Via", $"SIP/2.0/UDP 127.0.0.1:{Port};branch=z9hG4bK{Guid.NewGuid():N}");
                        bye.Add("From", replaced.Answer.Get("To")); bye.Add("To", replaced.Invite.Get("From"));
                        bye.Add("Call-ID", replaced.Invite.Get("Call-ID")); bye.Add("CSeq", $"{++_notifySequence} BYE");
                        await SendAsync(bye);
                    }
                }
                else if (request.Method == "INVITE" && SipMessage.Parameter(request.Get("To"), "tag").Length > 0)
                {
                    // In-dialog re-INVITE from the client: answer with the RFC 3264 complementary direction.
                    ReinviteRequests++; LastReinvite = request;
                    var offer = SdpSession.Parse(request.Body, Ai.Tlbx.Sip.SipMediaSecurity.Unencrypted);
                    int reject = RejectReinvites.TryDequeue(out int code) ? code : 0;
                    if (reject > 0) { await SendAsync(SipMessage.Response(request, reject, reject == 491 ? "Request Pending" : "Not Acceptable Here")); continue; }
                    string answerDirection = SdpSession.Attribute(SdpSession.AnswerDirection(offer, Ai.Tlbx.Sip.SipMediaDirection.SendReceive));
                    var reply = SipMessage.Response(request, 200, "OK");
                    reply.Add("Contact", $"<sip:remote@127.0.0.1:{Port}>"); reply.Add("Content-Type", "application/sdp");
                    reply.Body = Encoding.UTF8.GetBytes(TestSdp().Replace("a=sendrecv\r\n", $"a={answerDirection}\r\n"));
                    await SendAsync(reply);
                }
                else if (request.Method == "INVITE")
                {
                    _outgoingInvite = request; InviteReceived.TrySetResult();
                    if (RejectCallWith > 0)
                    {
                        _lastInviteAnswer = SipMessage.Response(request, RejectCallWith, RejectCallWith switch
                        { 404 => "Not Found", 484 => "Address Incomplete", 604 => "Does Not Exist Anywhere", _ => "Busy Here" }, "remote-tag");
                        await SendAsync(_lastInviteAnswer); continue;
                    }
                    var offer = SdpSession.Parse(request.Body, Ai.Tlbx.Sip.SipMediaSecurity.Unencrypted); _clientMedia = new(offer.Address, offer.Port);
                    if (!HoldProvisional) await SendProvisionalAsync();
                    if (WaitForCancel || HoldProvisional) continue;
                    if (EarlyMediaPackets > 0)
                    {
                        var codec = new Ai.Tlbx.Sip.Media.AudioCodec(UseG722 ? "G722" : "PCMA");
                        for (int i = 0; i < EarlyMediaPackets; i++)
                        {
                            var packet = Check.Rtp(++_mediaSequence, _mediaTimestamp, codec.Encode(new short[codec.SampleRate / 50]));
                            packet[1] = UseG722 ? (byte)9 : (byte)8; _mediaTimestamp += 160;
                            await _rtp.SendAsync(packet, _clientMedia);
                        }
                    }
                    await AnswerOutgoingAsync();
                }
                else if (request.Method == "CANCEL")
                {
                    CancelRequests++;
                    CancelMatchesInvite = _outgoingInvite is not null && request.CSeqNumber == _outgoingInvite.CSeqNumber &&
                        request.Get("Via") == _outgoingInvite.Get("Via") && request.Get("To") == _outgoingInvite.Get("To") &&
                        request.Get("From") == _outgoingInvite.Get("From") && request.RequestUri == _outgoingInvite.RequestUri;
                    await SendAsync(SipMessage.Response(request, 200, "OK"));
                    if (AnswerOnCancel) await AnswerOutgoingAsync();
                    else
                    {
                        _lastInviteAnswer = SipMessage.Response(_outgoingInvite!, 487, "Request Terminated", "remote-tag");
                        await SendAsync(_lastInviteAnswer);
                    }
                }
                else { if (request.Method == "BYE") ByeRequests++; await SendAsync(SipMessage.Response(request, 200, "OK")); }
            }
        }
        catch (OperationCanceledException) when (_stop.IsCancellationRequested) { }
        catch (ObjectDisposedException) when (_stop.IsCancellationRequested) { }
    }
    private bool ValidateDigest(SipMessage request)
    {
        var fields = Regex.Matches(request.Get("Authorization"), "(\\w+)=(?:\"([^\"]*)\"|([^, ]+))").ToDictionary(m => m.Groups[1].Value, m => m.Groups[2].Success ? m.Groups[2].Value : m.Groups[3].Value);
        static string Hash(string value) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
        string expected = Hash($"{Hash(Username + ":test-realm:" + Password)}:test-nonce:{fields["nc"]}:{fields["cnonce"]}:auth:{Hash(request.Method + ":" + request.RequestUri)}");
        return fields["response"] == expected;
    }
    public async Task SendAsync(SipMessage message) => await _sip.SendAsync(message.Serialize(), _client!);
    public Task SendProvisionalAsync() => SendAsync(SipMessage.Response(_outgoingInvite!, ProvisionalCode,
        ProvisionalCode switch { 100 => "Trying", 183 => "Session Progress", _ => "Ringing" }, "remote-tag"));
    public async Task AnswerOutgoingAsync()
    {
        var answer = SipMessage.Response(_outgoingInvite!, 200, "OK", "remote-tag");
        answer.Add("Contact", $"<sip:remote@127.0.0.1:{Port}>"); answer.Add("Content-Type", "application/sdp");
        answer.Body = Encoding.UTF8.GetBytes(TestSdp()); _lastInviteAnswer = answer;
        _answered[_outgoingInvite!.Get("Call-ID")] = (_outgoingInvite, answer); await SendAsync(answer);
    }
    public Task RepeatFinalAsync() => SendAsync(_lastInviteAnswer!);
    public async Task<SipMessage> WaitResponseAsync(string method, int code)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        while (await _responses.Reader.WaitToReadAsync(timeout.Token))
            while (_responses.Reader.TryRead(out var message)) if (message.CSeqMethod == method && message.StatusCode == code) return message;
        throw new Exception("No matching response.");
    }
    public async Task<SipMessage> InviteAsync(string from = "<sip:remote@example.test>", params (string Name, string Value)[] extraHeaders)
    {
        var invite = new SipMessage { StartLine = "INVITE sip:test-user@example.test SIP/2.0" };
        invite.Add("Via", $"SIP/2.0/UDP 127.0.0.1:{Port};branch=z9hG4bKtestincoming");
        invite.Add("From", from + ";tag=remote-tag"); invite.Add("To", "<sip:test-user@example.test>");
        foreach (var (name, value) in extraHeaders) invite.Add(name, value);
        invite.Add("Call-ID", Guid.NewGuid().ToString("N")); invite.Add("CSeq", "1 INVITE");
        invite.Add("Contact", $"<sip:remote@127.0.0.1:{Port}>"); invite.Add("Content-Type", "application/sdp");
        invite.Body = Encoding.UTF8.GetBytes(TestSdp()); await SendAsync(invite); return invite;
    }
    public Task AckAsync(SipMessage invite, SipMessage answer) => SendAsync(DialogRequest("ACK", 1, invite, answer));
    public Task ByeAsync(SipMessage invite, SipMessage answer) => SendAsync(DialogRequest("BYE", 2, invite, answer));
    /// <summary>Sends an in-dialog re-INVITE or UPDATE whose SDP declares the given direction (null: no body).</summary>
    public async Task<SipMessage> SessionRefreshAsync(string method, int sequence, SipMessage invite, SipMessage answer, string? direction)
    {
        var request = DialogRequest(method, sequence, invite, answer);
        request.Add("Contact", $"<sip:remote@127.0.0.1:{Port}>");
        if (direction is not null)
        {
            request.Add("Content-Type", "application/sdp");
            request.Body = Encoding.UTF8.GetBytes(TestSdp().Replace("a=sendrecv\r\n", $"a={direction}\r\n"));
        }
        await SendAsync(request); return request;
    }
    public Task AckAsync(SipMessage invite, SipMessage answer, int sequence) => SendAsync(DialogRequest("ACK", sequence, invite, answer));
    public Task ByeAsync(SipMessage invite, SipMessage answer, int sequence) => SendAsync(DialogRequest("BYE", sequence, invite, answer));
    private SipMessage DialogRequest(string method, int sequence, SipMessage invite, SipMessage answer)
    {
        var request = new SipMessage { StartLine = $"{method} {SipMessage.UriFromHeader(answer.Get("Contact"))} SIP/2.0" };
        request.Add("Via", $"SIP/2.0/UDP 127.0.0.1:{Port};branch=z9hG4bK{Guid.NewGuid():N}");
        request.Add("From", invite.Get("From")); request.Add("To", answer.Get("To")); request.Add("Call-ID", invite.Get("Call-ID")); request.Add("CSeq", sequence + " " + method); return request;
    }
    public async Task SendAudioAsync(int packetMilliseconds = 20)
    {
        var codec = new Ai.Tlbx.Sip.Media.AudioCodec(UseG722 ? "G722" : "PCMA");
        for (int iPacket = 0; iPacket < 8; iPacket++)
        {
            short[] samples = Enumerable.Range(0, codec.SampleRate * packetMilliseconds / 1000)
                .Select(i => (short)(8000 * Math.Sin(2 * Math.PI * 500 * i / codec.SampleRate))).ToArray();
            var packet = Check.Rtp(++_mediaSequence, _mediaTimestamp, codec.Encode(samples));
            _mediaTimestamp += (uint)(packetMilliseconds * 8);
            packet[1] = UseG722 ? (byte)9 : (byte)8;
            await _rtp.SendAsync(packet, _clientMedia!); await Task.Delay(packetMilliseconds);
        }
    }
    public void AdvanceMediaClock(int milliseconds) => _mediaTimestamp += (uint)(milliseconds * 8);
    /// <summary>Restarts the PBX media stream like a PBX after hold, resume or transfer: new SSRC, new sequence.</summary>
    public async Task SendAudioFromNewSourceAsync(uint ssrc, ushort firstSequence)
    {
        var codec = new Ai.Tlbx.Sip.Media.AudioCodec(UseG722 ? "G722" : "PCMA");
        for (int i = 0; i < 8; i++)
        {
            var packet = Check.Rtp((ushort)(firstSequence + i), _mediaTimestamp, codec.Encode(new short[codec.SampleRate / 50]));
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(8), ssrc);
            packet[1] = UseG722 ? (byte)9 : (byte)8; _mediaTimestamp += 160;
            await _rtp.SendAsync(packet, _clientMedia!); await Task.Delay(20);
        }
    }
    private string TestSdp() => UseG722 ? SdpSession.Offer(IPAddress.Loopback, MediaPort, null, 1, ((IPEndPoint)_rtcp.Client.LocalEndPoint!).Port)
        : SdpSession.Offer(IPAddress.Loopback, MediaPort, null, 1, ((IPEndPoint)_rtcp.Client.LocalEndPoint!).Port).Replace(" 9 8 0\r\n", " 8 0\r\n").Replace("a=rtpmap:9 G722/8000\r\n", "");
    public async ValueTask DisposeAsync()
    { _stop.Cancel(); _sip.Dispose(); _rtp.Dispose(); _rtcp.Dispose(); await Task.WhenAll(_loop, _controlLoop); _responses.Writer.TryComplete(); _stop.Dispose(); }
}
