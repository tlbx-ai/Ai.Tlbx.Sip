using System.Net;

namespace Ai.Tlbx.Sip;

public enum SipTransportProtocol { Udp, Tcp, Tls }
public enum SipMediaSecurity { Unencrypted, SdesRequired }
public enum SipClientState { Disconnected, Connecting, Connected, Reconnecting, Failed, Disconnecting }
public enum SipCallState { Created, Calling, Ringing, Incoming, Answering, Established, Ending, Ended }
public enum SipCallDirection { Incoming, Outgoing }
public enum SipCallEndReason { LocalHangup, RemoteHangup, Rejected, Busy, Cancelled, Timeout, ConnectionLost, ProtocolError }

/// <summary>Secrets are never included in ToString or diagnostic events.</summary>
public sealed class SipCredentials
{
    public required string Username { get; init; }
    public required string Password { get; init; }
    public override string ToString() => "SipCredentials { [redacted] }";
}

public sealed class SipClientConfig
{
    public required string Id { get; init; }
    public required string Registrar { get; init; }
    public required string User { get; init; }
    public required SipCredentials Credentials { get; init; }
    public string? Domain { get; init; }
    public string? OutboundProxy { get; init; }
    public int? Port { get; init; }
    public SipTransportProtocol Transport { get; init; } = SipTransportProtocol.Udp;
    public SipMediaSecurity MediaSecurity { get; init; }
    public IPAddress LocalAddress { get; init; } = IPAddress.Any;
    public int LocalPort { get; init; }
    public string? AdvertisedAddress { get; init; }
    public int RegistrationLifetimeSeconds { get; init; } = 300;
    public TimeSpan KeepAliveInterval { get; init; } = TimeSpan.FromSeconds(25);
    public TimeSpan TransactionTimeout { get; init; } = TimeSpan.FromSeconds(32);
    public TimeSpan CallAnswerTimeout { get; init; } = TimeSpan.FromMinutes(2);
    public TimeSpan InitialRetransmitInterval { get; init; } = TimeSpan.FromMilliseconds(500);
    public TimeSpan ReconnectDelay { get; init; } = TimeSpan.FromSeconds(3);
    public bool AutoReconnect { get; init; } = true;
    public int MaxConcurrentCalls { get; init; } = 4;
    public int AudioSampleRate { get; init; } = 24000;
    public TimeSpan MaxQueuedAudio { get; init; } = TimeSpan.FromSeconds(3);
    public TimeSpan RtcpReportInterval { get; init; } = TimeSpan.FromSeconds(5);
    public bool AllowSymmetricRtp { get; init; }

    internal string SipDomain => Domain ?? Registrar;
    internal int ServerPort => Port ?? (Transport == SipTransportProtocol.Tls ? 5061 : 5060);
    internal void Validate()
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(Id);
        ArgumentException.ThrowIfNullOrWhiteSpace(Registrar);
        ArgumentException.ThrowIfNullOrWhiteSpace(User);
        ArgumentNullException.ThrowIfNull(Credentials);
        ArgumentException.ThrowIfNullOrWhiteSpace(Credentials.Username);
        ArgumentNullException.ThrowIfNull(Credentials.Password);
        foreach (var value in new[] { Id, Registrar, User, Domain, OutboundProxy, AdvertisedAddress, Credentials.Username })
            if (value?.Any(c => char.IsControl(c) || c is '<' or '>' or '"') == true)
                throw new ArgumentException("SIP configuration contains invalid characters.");
        if (ServerPort is < 1 or > 65535 || LocalPort is < 0 or > 65535 || MaxConcurrentCalls < 1 ||
            RegistrationLifetimeSeconds < 30 || AudioSampleRate is < 8000 or > 96000 ||
            KeepAliveInterval <= TimeSpan.Zero || TransactionTimeout <= TimeSpan.Zero || CallAnswerTimeout <= TimeSpan.Zero ||
            InitialRetransmitInterval <= TimeSpan.Zero || ReconnectDelay <= TimeSpan.Zero ||
            MaxQueuedAudio < TimeSpan.FromMilliseconds(20) || MaxQueuedAudio > TimeSpan.FromMinutes(1))
            throw new ArgumentOutOfRangeException(nameof(SipClientConfig));
        if (RtcpReportInterval < TimeSpan.FromSeconds(1) || RtcpReportInterval > TimeSpan.FromMinutes(1))
            throw new ArgumentOutOfRangeException(nameof(RtcpReportInterval));
        if (MediaSecurity == SipMediaSecurity.SdesRequired && Transport != SipTransportProtocol.Tls)
            throw new ArgumentException("SDES key exchange requires TLS-protected signalling.");
    }
    public override string ToString() => $"SipClientConfig {{ Id = {Id}, Transport = {Transport} }}";
}

public sealed record SipClientStatus(SipClientState State, DateTimeOffset ChangedAt,
    DateTimeOffset? RegistrationExpiresAt = null, string? Error = null, int? SipStatusCode = null);
public sealed record SipCallStatus(SipCallState State, DateTimeOffset ChangedAt,
    SipCallEndReason? EndReason = null, int? SipStatusCode = null, string? Error = null);
public sealed record SipMediaMetrics(long TransmittedPackets, long ReceivedPackets, long TransmittedBytes,
    long ReceivedBytes, long LostPackets, long DuplicatePackets, long LatePackets,
    double JitterMilliseconds, double? RoundTripMilliseconds, TimeSpan QueuedAudio,
    long PlaybackUnderruns, string? Codec, SipRtcpMetrics? Control = null);
public sealed record SipRtcpMetrics(long TransmittedPackets, long ReceivedPackets, long RejectedPackets,
    long? RemoteLostPackets, double? RemoteLossFraction, double? RemoteJitterMilliseconds, DateTimeOffset? LastReportAt,
    long TransportErrors = 0);
public sealed record SipDiagnostic(DateTimeOffset At, string Category, string Message);
