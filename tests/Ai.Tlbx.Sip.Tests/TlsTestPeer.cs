using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Ai.Tlbx.Sip.Protocol;

/// <summary>An ephemeral CA and TLS SIP peer; never changes machine certificate stores.</summary>
internal sealed class TlsTestPeer : IAsyncDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource _stop = new();
    private readonly X509Certificate2 _root, _leaf;
    private readonly Task _server;
    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;
    public X509Certificate2Collection TrustRoots => [_root];
    public TlsTestPeer()
    {
        using var rootKey = RSA.Create(2048); using var leafKey = RSA.Create(2048);
        var rootRequest = new CertificateRequest("CN=SIP isolated test CA", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        _root = rootRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1));
        var leafRequest = new CertificateRequest("CN=localhost", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder(); san.AddDnsName("localhost");
        leafRequest.CertificateExtensions.Add(san.Build());
        leafRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        leafRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.1") }, true));
        using var issued = leafRequest.Create(_root, DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1), RandomNumberGenerator.GetBytes(16));
        using var keyed = issued.CopyWithPrivateKey(leafKey);
        _leaf = X509CertificateLoader.LoadPkcs12(keyed.Export(X509ContentType.Pfx), null);
        _listener.Start(); _server = RunAsync();
    }
    private async Task RunAsync()
    {
        try
        {
            using var client = await _listener.AcceptTcpClientAsync(_stop.Token);
            using var tls = new SslStream(client.GetStream());
            await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
            { ServerCertificate = _leaf, EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13 }, _stop.Token);
            byte[] bytes = new byte[65536]; int used = 0;
            while (!_stop.IsCancellationRequested)
            {
                int read = await tls.ReadAsync(bytes.AsMemory(used), _stop.Token); if (read == 0) return;
                used += read;
                if (!SipMessage.TryGetLength(bytes.AsSpan(0, used), out int total, out _) || used < total) continue;
                var request = SipMessage.Parse(bytes.AsSpan(0, total));
                await tls.WriteAsync(SipMessage.Response(request, 200, "OK").Serialize(), _stop.Token);
                return;
            }
        }
        catch (Exception e) when (e is OperationCanceledException or AuthenticationException or IOException or ObjectDisposedException) { }
    }
    public async ValueTask DisposeAsync()
    { _stop.Cancel(); _listener.Stop(); await _server; _root.Dispose(); _leaf.Dispose(); _stop.Dispose(); }
}
