using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace Ai.Tlbx.Sip.Protocol;

internal sealed class SipTransport : IAsyncDisposable
{
    private readonly SipClientConfig _config;
    private readonly X509Certificate2Collection? _testTrustRoots;
    private readonly SemaphoreSlim _sendLock = new(1, 1);
    private Socket? _socket;
    private Stream? _stream;
    public IPEndPoint LocalEndPoint => (IPEndPoint)(_socket?.LocalEndPoint ?? throw new InvalidOperationException("Transport is closed."));
    public IPEndPoint RemoteEndPoint => (IPEndPoint)(_socket?.RemoteEndPoint ?? throw new InvalidOperationException("Transport is closed."));
    public bool IsReliable => _config.Transport != SipTransportProtocol.Udp;
    public SipTransport(SipClientConfig config, X509Certificate2Collection? testTrustRoots = null)
    { _config = config; _testTrustRoots = testTrustRoots; }
    public async Task OpenAsync(CancellationToken cancellationToken)
    {
        string host = _config.OutboundProxy ?? _config.Registrar;
        var addresses = await Dns.GetHostAddressesAsync(host, cancellationToken);
        var address = addresses.FirstOrDefault(a => a.AddressFamily == _config.LocalAddress.AddressFamily)
            ?? throw new SocketException((int)SocketError.HostNotFound);
        bool udp = !IsReliable;
        _socket = new Socket(address.AddressFamily, udp ? SocketType.Dgram : SocketType.Stream, udp ? ProtocolType.Udp : ProtocolType.Tcp);
        _socket.Bind(new IPEndPoint(_config.LocalAddress, _config.LocalPort));
        await _socket.ConnectAsync(new IPEndPoint(address, _config.ServerPort), cancellationToken);
        if (!udp)
        {
            _socket.NoDelay = true;
            _stream = new NetworkStream(_socket, ownsSocket: false);
            if (_config.Transport == SipTransportProtocol.Tls)
            {
                var tls = new SslStream(_stream, leaveInnerStreamOpen: false);
                _stream = tls;
                var options = new SslClientAuthenticationOptions
                {
                    TargetHost = host, EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    CertificateRevocationCheckMode = X509RevocationMode.Online
                };
                // Internal loopback verification uses an ephemeral private CA.
                // Production clients always use the operating system trust store.
                if (_testTrustRoots is not null)
                {
                    options.CertificateChainPolicy = new X509ChainPolicy
                    { TrustMode = X509ChainTrustMode.CustomRootTrust, RevocationMode = X509RevocationMode.NoCheck };
                    options.CertificateChainPolicy.CustomTrustStore.AddRange(_testTrustRoots);
                }
                await tls.AuthenticateAsClientAsync(options, cancellationToken);
            }
        }
    }
    public async Task SendAsync(SipMessage message, CancellationToken cancellationToken) => await SendBytesAsync(message.Serialize(), cancellationToken);
    public async Task SendBytesAsync(ReadOnlyMemory<byte> bytes, CancellationToken cancellationToken)
    {
        await _sendLock.WaitAsync(cancellationToken);
        try
        {
            if (_stream is not null) await _stream.WriteAsync(bytes, cancellationToken);
            else if (_socket is not null) await _socket.SendAsync(bytes, SocketFlags.None, cancellationToken);
            else throw new IOException("SIP transport is closed.");
        }
        finally { _sendLock.Release(); }
    }
    public async Task ReceiveAsync(Func<SipMessage, Task> receive, CancellationToken cancellationToken)
    {
        byte[] buffer = new byte[SipMessage.MaxMessageBytes];
        int buffered = 0;
        while (!cancellationToken.IsCancellationRequested)
        {
            int count = _stream is not null
                ? await _stream.ReadAsync(buffer.AsMemory(buffered), cancellationToken)
                : await _socket!.ReceiveAsync(buffer.AsMemory(), SocketFlags.None, cancellationToken);
            if (count == 0) throw new IOException("SIP peer closed the transport.");
            if (_stream is null)
            {
                if (count <= 4 && buffer.AsSpan(0, count).Trim((byte)'\r').Trim((byte)'\n').IsEmpty) continue;
                await receive(SipMessage.Parse(buffer.AsSpan(0, count)));
                continue;
            }
            buffered += count;
            while (buffered >= 2)
            {
                if (buffer[0] == 13 && buffer[1] == 10)
                { Buffer.BlockCopy(buffer, 2, buffer, 0, buffered - 2); buffered -= 2; continue; }
                if (!SipMessage.TryGetLength(buffer.AsSpan(0, buffered), out int total, out _) || buffered < total) break;
                var message = SipMessage.Parse(buffer.AsSpan(0, total));
                Buffer.BlockCopy(buffer, total, buffer, 0, buffered - total); buffered -= total;
                await receive(message);
            }
            if (buffered == buffer.Length) throw new InvalidDataException("SIP message exceeded framing limit.");
        }
    }
    public async ValueTask DisposeAsync()
    {
        if (_stream is not null) await _stream.DisposeAsync();
        _socket?.Dispose(); _socket = null; _stream = null;
    }
}
