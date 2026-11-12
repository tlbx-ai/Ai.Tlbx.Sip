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
    private readonly CancellationTokenSource _stop = new();
    private readonly Channel<SipMessage> _responses = Channel.CreateUnbounded<SipMessage>();
    private readonly Task _loop;
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
    public int? GrantedExpirySeconds { get; init; }
    public volatile bool DropRegistrationResponses;
    public int AckRequests { get; private set; }
    public int CancelRequests { get; private set; }
    public int ByeRequests { get; private set; }
    public bool CancelMatchesInvite { get; private set; }
    public TaskCompletionSource InviteReceived { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public int RegisterRequests { get; private set; }
    public int AuthenticatedRegistrations { get; private set; }
    public bool Unregistered { get; private set; }
    public TestPbx() => _loop = RunAsync();
    private async Task RunAsync()
    {
        try
        {
            while (!_stop.IsCancellationRequested)
            {
                var data = await _sip.ReceiveAsync(_stop.Token); _client = data.RemoteEndPoint;
                var request = SipMessage.Parse(data.Buffer);
                if (request.IsResponse) { _responses.Writer.TryWrite(request); continue; }
                if (request.Method == "ACK") { AckRequests++; continue; }
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
                else if (request.Method == "INVITE")
                {
                    _outgoingInvite = request; InviteReceived.TrySetResult();
                    if (RejectCallWith > 0)
                    {
                        _lastInviteAnswer = SipMessage.Response(request, RejectCallWith, "Rejected", "remote-tag");
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
    public Task SendProvisionalAsync() => SendAsync(SipMessage.Response(_outgoingInvite!, 180, "Ringing", "remote-tag"));
    public async Task AnswerOutgoingAsync()
    {
        var answer = SipMessage.Response(_outgoingInvite!, 200, "OK", "remote-tag");
        answer.Add("Contact", $"<sip:remote@127.0.0.1:{Port}>"); answer.Add("Content-Type", "application/sdp");
        answer.Body = Encoding.UTF8.GetBytes(TestSdp()); _lastInviteAnswer = answer; await SendAsync(answer);
    }
    public Task RepeatFinalAsync() => SendAsync(_lastInviteAnswer!);
    public async Task<SipMessage> WaitResponseAsync(string method, int code)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        while (await _responses.Reader.WaitToReadAsync(timeout.Token))
            while (_responses.Reader.TryRead(out var message)) if (message.CSeqMethod == method && message.StatusCode == code) return message;
        throw new Exception("No matching response.");
    }
    public async Task<SipMessage> InviteAsync()
    {
        var invite = new SipMessage { StartLine = "INVITE sip:test-user@example.test SIP/2.0" };
        invite.Add("Via", $"SIP/2.0/UDP 127.0.0.1:{Port};branch=z9hG4bKtestincoming");
        invite.Add("From", "<sip:remote@example.test>;tag=remote-tag"); invite.Add("To", "<sip:test-user@example.test>");
        invite.Add("Call-ID", Guid.NewGuid().ToString("N")); invite.Add("CSeq", "1 INVITE");
        invite.Add("Contact", $"<sip:remote@127.0.0.1:{Port}>"); invite.Add("Content-Type", "application/sdp");
        invite.Body = Encoding.UTF8.GetBytes(TestSdp()); await SendAsync(invite); return invite;
    }
    public Task AckAsync(SipMessage invite, SipMessage answer) => SendAsync(DialogRequest("ACK", 1, invite, answer));
    public Task ByeAsync(SipMessage invite, SipMessage answer) => SendAsync(DialogRequest("BYE", 2, invite, answer));
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
    private string TestSdp() => UseG722 ? SdpSession.Offer(IPAddress.Loopback, MediaPort, null, 1)
        : SdpSession.Offer(IPAddress.Loopback, MediaPort, null, 1).Replace(" 9 8 0\r\n", " 8 0\r\n").Replace("a=rtpmap:9 G722/8000\r\n", "");
    public async ValueTask DisposeAsync()
    { _stop.Cancel(); _sip.Dispose(); _rtp.Dispose(); await _loop; _responses.Writer.TryComplete(); _stop.Dispose(); }
}
