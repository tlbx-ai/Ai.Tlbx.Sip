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
    public int Port => ((IPEndPoint)_sip.Client.LocalEndPoint!).Port;
    public int MediaPort => ((IPEndPoint)_rtp.Client.LocalEndPoint!).Port;
    public bool DropFirstRegister { get; init; }
    public bool RejectCredentials { get; init; }
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
                if (request.Method == "ACK") continue;
                if (request.Method == "REGISTER")
                {
                    RegisterRequests++; if (DropFirstRegister && RegisterRequests == 1) continue;
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
                        response.Add("Expires", request.Get("Expires")); response.Add("Contact", request.Get("Contact") + ";expires=" + request.Get("Expires"));
                    }
                    await SendAsync(response);
                }
                else if (request.Method == "INVITE")
                {
                    var offer = SdpSession.Parse(request.Body, Ai.Tlbx.Sip.SipMediaSecurity.Unencrypted); _clientMedia = new(offer.Address, offer.Port);
                    await SendAsync(SipMessage.Response(request, 180, "Ringing", "remote-tag"));
                    var answer = SipMessage.Response(request, 200, "OK", "remote-tag");
                    answer.Add("Contact", $"<sip:remote@127.0.0.1:{Port}>"); answer.Add("Content-Type", "application/sdp");
                    answer.Body = Encoding.UTF8.GetBytes(SdpSession.Offer(IPAddress.Loopback, MediaPort, null, 1)); await SendAsync(answer);
                }
                else await SendAsync(SipMessage.Response(request, 200, "OK"));
            }
        }
        catch (OperationCanceledException) when (_stop.IsCancellationRequested) { }
        catch (ObjectDisposedException) when (_stop.IsCancellationRequested) { }
    }
    private static bool ValidateDigest(SipMessage request)
    {
        var fields = Regex.Matches(request.Get("Authorization"), "(\\w+)=(?:\"([^\"]*)\"|([^, ]+))").ToDictionary(m => m.Groups[1].Value, m => m.Groups[2].Success ? m.Groups[2].Value : m.Groups[3].Value);
        static string Hash(string value) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
        string expected = Hash($"{Hash("test-user:test-realm:test-password")}:test-nonce:{fields["nc"]}:{fields["cnonce"]}:auth:{Hash(request.Method + ":" + request.RequestUri)}");
        return fields["response"] == expected;
    }
    public async Task SendAsync(SipMessage message) => await _sip.SendAsync(message.Serialize(), _client!);
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
        invite.Body = Encoding.UTF8.GetBytes(SdpSession.Offer(IPAddress.Loopback, MediaPort, null, 1)); await SendAsync(invite); return invite;
    }
    public Task AckAsync(SipMessage invite, SipMessage answer) => SendAsync(DialogRequest("ACK", 1, invite, answer));
    public Task ByeAsync(SipMessage invite, SipMessage answer) => SendAsync(DialogRequest("BYE", 2, invite, answer));
    private SipMessage DialogRequest(string method, int sequence, SipMessage invite, SipMessage answer)
    {
        var request = new SipMessage { StartLine = $"{method} {SipMessage.UriFromHeader(answer.Get("Contact"))} SIP/2.0" };
        request.Add("Via", $"SIP/2.0/UDP 127.0.0.1:{Port};branch=z9hG4bK{Guid.NewGuid():N}");
        request.Add("From", invite.Get("From")); request.Add("To", answer.Get("To")); request.Add("Call-ID", invite.Get("Call-ID")); request.Add("CSeq", sequence + " " + method); return request;
    }
    public async Task SendAudioAsync()
    {
        for (ushort sequence = 1; sequence <= 8; sequence++)
        { await _rtp.SendAsync(Check.Rtp(sequence, (uint)sequence * 160, Enumerable.Repeat((byte)0xD5, 160).ToArray()), _clientMedia!); await Task.Delay(20); }
    }
    public async ValueTask DisposeAsync()
    { _stop.Cancel(); _sip.Dispose(); _rtp.Dispose(); await _loop; _responses.Writer.TryComplete(); _stop.Dispose(); }
}
