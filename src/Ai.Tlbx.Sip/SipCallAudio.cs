using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading.Channels;
using Ai.Tlbx.Sip.Media;
using Ai.Tlbx.Sip.Protocol;

namespace Ai.Tlbx.Sip;

/// <summary>Owned immutable PCM16 mono samples. The receiver may retain a frame after reading it.</summary>
public sealed record PcmAudioFrame(ReadOnlyMemory<short> Samples, int SampleRate, long SamplePosition);

/// <summary>A single call's bounded PCM media stream. No audio device or AI dependency.</summary>
public sealed class SipCallAudio : IAsyncDisposable
{
    private readonly SipClientConfig _config;
    private readonly TimeProvider _time;
    private readonly Action<string> _failure;
    private readonly object _gate = new();
    private readonly UdpClient _rtp;
    private readonly UdpClient _rtcp;
    private readonly RtcpSession _control;
    private readonly TaskCompletionSource _disposedCompletion = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly Channel<PcmAudioFrame> _received = Channel.CreateBounded<PcmAudioFrame>(new BoundedChannelOptions(100)
    { SingleReader = false, SingleWriter = true, FullMode = BoundedChannelFullMode.DropOldest });
    private readonly Queue<short> _outbound = new();
    private readonly Queue<short> _decoded = new();
    private readonly SortedDictionary<long, (uint Timestamp, byte[] Payload)> _jitter = [];
    private readonly CancellationTokenSource _stop = new();
    private PcmResampler? _rxResampler;
    private AudioCodec? _codec;
    private PcmResampler? _txResampler;
    private int _txInputRate;
    private IPEndPoint? _remote;
    private IPEndPoint? _remoteControl;
    private SdpSession? _session;
    private SrtpContext? _txCrypto, _rxCrypto;
    private SrtcpContext? _txControlCrypto, _rxControlCrypto;
    private readonly byte[]? _masterKey;
    private Task[] _tasks = [];
    private long _txPackets, _rxPackets, _txBytes, _rxBytes, _lost, _duplicate, _late, _underruns;
    private long _highestSequence = -1, _playSequence = -1, _samplePosition;
    private bool _playing, _disposed, _started;
    private readonly uint _ssrc = (uint)RandomNumberGenerator.GetInt32(1, int.MaxValue);
    private uint? _remoteSsrc;
    private ushort _sequence = (ushort)RandomNumberGenerator.GetInt32(ushort.MaxValue);
    private uint _timestamp = (uint)RandomNumberGenerator.GetInt32(int.MaxValue);
    internal SipCallAudio(SipClientConfig config, TimeProvider time, IPAddress localAddress, Action<string> failure)
    {
        _config = config; _time = time; _failure = failure;
        (_rtp, _rtcp) = BindMediaPair(localAddress);
        _control = new(_ssrc, time);
        _masterKey = config.MediaSecurity == SipMediaSecurity.SdesRequired ? SdpSession.NewMasterKey() : null;
    }
    private static (UdpClient Rtp, UdpClient Rtcp) BindMediaPair(IPAddress address)
    {
        for (int attempt = 0; attempt < 64; attempt++)
        {
            var rtp = new UdpClient(new IPEndPoint(address, 0));
            int port = ((IPEndPoint)rtp.Client.LocalEndPoint!).Port;
            if ((port & 1) != 0) { rtp.Dispose(); continue; }
            try { return (rtp, new UdpClient(new IPEndPoint(address, port + 1))); }
            // Windows can assign the RTP port beside an excluded/reserved UDP
            // port. Discard that pair and retry without changing OS reservations.
            catch (SocketException e) when (e.SocketErrorCode is SocketError.AddressAlreadyInUse or SocketError.AccessDenied) { rtp.Dispose(); }
            catch { rtp.Dispose(); throw; }
        }
        throw new IOException("Could not reserve an adjacent RTP/RTCP UDP port pair.");
    }
    internal int Port => ((IPEndPoint)_rtp.Client.LocalEndPoint!).Port;
    internal int ControlPort => ((IPEndPoint)_rtcp.Client.LocalEndPoint!).Port;
    internal byte[]? MasterKey => _masterKey;
    public int SampleRate => _config.AudioSampleRate;
    private int CodecSampleRate => _codec?.SampleRate ?? 8000;
    public TimeSpan QueuedAudio { get { lock (_gate) return TimeSpan.FromSeconds((double)_outbound.Count / CodecSampleRate); } }
    public SipMediaMetrics Metrics
    {
        get { lock (_gate) return new(_txPackets, _rxPackets, _txBytes, _rxBytes, _lost, _duplicate, _late,
            _control.JitterSamples / 8.0, _control.RoundTripMilliseconds, TimeSpan.FromSeconds((double)_outbound.Count / CodecSampleRate),
            _underruns, _session?.Codec, _control.Metrics); }
    }
    public event EventHandler<SipMediaMetrics>? MetricsChanged;
    public IAsyncEnumerable<PcmAudioFrame> ReadFramesAsync(CancellationToken cancellationToken = default) => _received.Reader.ReadAllAsync(cancellationToken);
    /// <summary>Copies samples. Returns false without consuming input when the bounded transmit queue is full.</summary>
    public bool TryWrite(ReadOnlySpan<short> samples, int sampleRate)
    {
        if (sampleRate is < 8000 or > 96000) throw new ArgumentOutOfRangeException(nameof(sampleRate));
        lock (_gate)
        {
            if (_disposed || _stop.IsCancellationRequested || !_started) return false;
            bool change = _txResampler is null || _txInputRate != sampleRate;
            var resampler = change ? new PcmResampler(sampleRate, CodecSampleRate) : _txResampler!;
            // Reserve the exact eventual output, including the filter tail. A
            // fixed safety margin can reject every slice of a valid 20-ms queue.
            long estimate = resampler.OutputLength(samples.Length, endOfStream: true) +
                (change ? _txResampler?.OutputLength(0, endOfStream: true) ?? 0 : 0);
            if (_outbound.Count + estimate > _config.MaxQueuedAudio.TotalSeconds * CodecSampleRate) return false;
            if (change)
            {
                if (_txResampler is not null)
                    foreach (short s in _txResampler.Process([], endOfStream: true)) _outbound.Enqueue(s);
                _txResampler = resampler; _txInputRate = sampleRate;
            }
            foreach (short s in resampler.Process(samples)) _outbound.Enqueue(s);
            return true;
        }
    }
    public void FlushInput()
    {
        lock (_gate)
        {
            if (_disposed || _txResampler is null) return;
            foreach (short s in _txResampler.Process([], endOfStream: true)) _outbound.Enqueue(s);
            _txResampler = null;
        }
    }
    public void ClearOutput()
    { lock (_gate) { _outbound.Clear(); _txResampler?.Reset(); } }
    public async Task<bool> WaitForDrainAsync(TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        FlushInput();
        var start = _time.GetTimestamp();
        while (QueuedAudio > TimeSpan.Zero)
        {
            if (_stop.IsCancellationRequested || _time.GetElapsedTime(start) >= timeout) return false;
            await Task.Delay(TimeSpan.FromMilliseconds(20), _time, cancellationToken);
        }
        return true;
    }
    internal void Start(SdpSession session)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_started) throw new InvalidOperationException("Call media already started.");
            _session = session; _remote = new(session.Address, session.Port);
            _remoteControl = new(session.RtcpAddress, session.RtcpPort);
            _codec = new(session.Codec); _rxResampler = new(session.SampleRate, _config.AudioSampleRate);
            // A PBX can send ringback/early media before the final answer. Those
            // datagrams must not become seconds of stale audio at establishment.
            byte[] discard = new byte[4096];
            for (int i = 0; i < 512 && _rtp.Client.Available > 0; i++)
            { _rtp.Client.Receive(discard); _late++; }
            if (session.Secure)
            {
                _txCrypto = new(_masterKey!); _rxCrypto = new(session.MasterKey!);
                _txControlCrypto = new(_masterKey!); _rxControlCrypto = new(session.MasterKey!);
            }
            _started = true;
            _tasks = [GuardAsync(ReceiveAsync), GuardAsync(SendAsync), GuardAsync(PlayoutAsync), GuardAsync(MetricsAsync),
                GuardAsync(ReceiveControlAsync), GuardAsync(SendControlAsync)];
        }
    }
    private async Task GuardAsync(Func<CancellationToken, Task> action)
    {
        try { await action(_stop.Token); }
        catch (OperationCanceledException) when (_stop.IsCancellationRequested) { }
        catch (ObjectDisposedException) when (_stop.IsCancellationRequested) { }
        catch (SocketException) when (_stop.IsCancellationRequested) { }
        catch (Exception error) { _failure(error.Message); _stop.Cancel(); _received.Writer.TryComplete(error); }
    }
    private async Task SendAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(20), _time);
        while (await timer.WaitForNextTickAsync(cancellationToken))
        {
            byte[] packet;
            lock (_gate)
            {
                int count = CodecSampleRate / 50;
                if (_outbound.Count < count) _underruns++;
                var samples = new short[count];
                for (int i = 0; i < count; i++) samples[i] = _outbound.Count > 0 ? _outbound.Dequeue() : (short)0;
                var encoded = _codec!.Encode(samples);
                packet = new byte[12 + encoded.Length]; encoded.CopyTo(packet, 12);
            }
            packet[0] = 0x80; packet[1] = (byte)_session!.PayloadType;
            int payloadOctets = packet.Length - 12; uint sentTimestamp = _timestamp;
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2), _sequence++);
            BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(4), _timestamp); _timestamp += 160;
            BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(8), _ssrc);
            lock (_gate)
            {
                if (_txCrypto is not null) packet = _txCrypto.Protect(packet, 12);
            }
            await _rtp.SendAsync(packet, _remote!, cancellationToken);
            lock (_gate) { _txPackets++; _txBytes += packet.Length; _control.RecordSent(sentTimestamp, payloadOctets); }
        }
    }
    internal static int RtpHeaderLength(ReadOnlySpan<byte> packet)
    {
        if (packet.Length < 12 || (packet[0] >> 6) != 2) return -1;
        int length = 12 + (packet[0] & 15) * 4;
        if (packet.Length < length) return -1;
        if ((packet[0] & 16) != 0)
        {
            if (packet.Length < length + 4) return -1;
            length += 4 + BinaryPrimitives.ReadUInt16BigEndian(packet[(length + 2)..]) * 4;
        }
        return length <= packet.Length ? length : -1;
    }
    private async Task ReceiveAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            var datagram = await _rtp.ReceiveAsync(cancellationToken);
            byte[] packet = datagram.Buffer;
            if (packet.Length > 4096 || !datagram.RemoteEndPoint.Address.Equals(_remote!.Address)) continue;
            if (!_config.AllowSymmetricRtp && datagram.RemoteEndPoint.Port != _remote.Port) continue;
            int header = RtpHeaderLength(packet);
            if (header < 0 || (packet[1] & 127) != _session!.PayloadType) continue;
            lock (_gate)
            {
                if (_rxCrypto is not null)
                {
                    var plaintext = _rxCrypto.Unprotect(packet, header); if (plaintext is null) continue;
                    packet = plaintext;
                }
                uint ssrc = BinaryPrimitives.ReadUInt32BigEndian(packet.AsSpan(8));
                if (_remoteSsrc.HasValue && _remoteSsrc != ssrc) continue;
                _remoteSsrc = ssrc;
                if (_config.AllowSymmetricRtp) _remote = datagram.RemoteEndPoint;
                int end = packet.Length;
                if ((packet[0] & 32) != 0)
                { int padding = packet[^1]; if (padding == 0 || padding > end - header) continue; end -= padding; }
                if (end <= header || end - header > 1600) continue;
                ushort seq = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(2));
                uint timestamp = BinaryPrimitives.ReadUInt32BigEndian(packet.AsSpan(4));
                _control.RecordReceived(ssrc, seq, timestamp);
                long extended = _highestSequence < 0 ? seq : (_highestSequence & ~65535L) + seq;
                if (_highestSequence >= 0 && extended - _highestSequence > 32768) extended -= 65536;
                else if (_highestSequence >= 0 && _highestSequence - extended > 32768) extended += 65536;
                if (_playing && extended < _playSequence) { _late++; continue; }
                if (_jitter.ContainsKey(extended)) { _duplicate++; continue; }
                if (_jitter.Count >= 12)
                {
                    // Recover toward the live edge after scheduling stalls/bursts.
                    // Dropping newest packets would preserve stale speech and add delay.
                    while (_jitter.Count > 3) { _jitter.Remove(_jitter.First().Key); _late++; }
                    if (_playing) { _playSequence = _jitter.First().Key; _decoded.Clear(); }
                }
                _jitter[extended] = (timestamp, packet.AsSpan(header, end - header).ToArray());
                _highestSequence = Math.Max(_highestSequence, extended); _rxPackets++; _rxBytes += datagram.Buffer.Length;
            }
        }
    }
    private async Task PlayoutAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(20), _time);
        while (await timer.WaitForNextTickAsync(cancellationToken))
        {
            short[] samples;
            lock (_gate)
            {
                if (!_playing) { if (_jitter.Count < 3) continue; _playing = true; _playSequence = _jitter.First().Key; }
                int frameSamples = CodecSampleRate / 50;
                while (_decoded.Count < frameSamples)
                {
                    if (_jitter.Remove(_playSequence, out var frame))
                    {
                        _playSequence++;
                        foreach (short sample in _codec!.Decode(frame.Payload)) _decoded.Enqueue(sample);
                    }
                    else
                    {
                        // Empty receive queues can mean silence suppression. RTP
                        // sequence numbers advance per transmitted packet, not per
                        // playout tick. Only a later packet proves a sequence gap.
                        if (_jitter.Count > 0 && _jitter.First().Key > _playSequence) { _lost++; _playSequence++; }
                        while (_decoded.Count < frameSamples) _decoded.Enqueue(0);
                    }
                }
                samples = new short[frameSamples];
                for (int i = 0; i < frameSamples; i++) samples[i] = _decoded.Dequeue();
                var resampled = _rxResampler!.Process(samples);
                _received.Writer.TryWrite(new(resampled, SampleRate, _samplePosition)); _samplePosition += resampled.Length;
            }
        }
    }
    private async Task MetricsAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(1), _time);
        while (await timer.WaitForNextTickAsync(cancellationToken))
            foreach (EventHandler<SipMediaMetrics> handler in MetricsChanged?.GetInvocationList() ?? [])
                try { handler(this, Metrics); } catch { }
    }
    private byte[] CreateControlPacket(bool goodbye = false)
    {
        byte[] packet = _control.CreateCompound(goodbye);
        if (_session?.Secure == true)
            return (_txControlCrypto ?? throw new InvalidOperationException("Encrypted control context is missing.")).Protect(packet);
        return packet;
    }
    private async Task SendControlAsync(CancellationToken cancellationToken)
    {
        bool initial = true;
        while (!cancellationToken.IsCancellationRequested)
        {
            // Point-to-point RFC 3550 interval randomization; no synchronized report bursts.
            double factor = (0.5 + Random.Shared.NextDouble()) / 1.21828;
            await Task.Delay(_config.RtcpReportInterval * (initial ? 0.5 : 1) * factor, _time, cancellationToken);
            initial = false;
            byte[] packet; IPEndPoint remote;
            lock (_gate) { packet = CreateControlPacket(); remote = _remoteControl!; }
            try
            {
                await _rtcp.SendAsync(packet, remote, cancellationToken);
                lock (_gate) _control.RecordControlSent();
            }
            catch (SocketException error) when (error.SocketErrorCode is SocketError.ConnectionReset or SocketError.ConnectionRefused)
            { lock (_gate) _control.RecordTransportError(); }
        }
    }
    private async Task ReceiveControlAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            UdpReceiveResult data;
            try { data = await _rtcp.ReceiveAsync(cancellationToken); }
            catch (SocketException error) when (error.SocketErrorCode is SocketError.ConnectionReset or SocketError.ConnectionRefused)
            { lock (_gate) _control.RecordTransportError(); continue; }
            lock (_gate)
            {
                if (data.Buffer.Length > 4110 || !data.RemoteEndPoint.Address.Equals(_remoteControl!.Address) ||
                    (!_config.AllowSymmetricRtp && data.RemoteEndPoint.Port != _remoteControl.Port))
                { _control.Reject(); continue; }
                byte[]? packet = _rxControlCrypto?.Unprotect(data.Buffer);
                if (_rxControlCrypto is null) packet = data.Buffer;
                if (packet is null) { _control.Reject(); continue; }
                if (_control.Receive(packet) && _config.AllowSymmetricRtp) _remoteControl = data.RemoteEndPoint;
            }
        }
    }
    public async ValueTask DisposeAsync()
    {
        byte[]? goodbye = null; bool alreadyDisposed;
        lock (_gate)
        {
            alreadyDisposed = _disposed;
            if (!alreadyDisposed)
            {
                _disposed = true; _stop.Cancel(); _outbound.Clear();
                if (_started) goodbye = CreateControlPacket(goodbye: true);
            }
        }
        if (alreadyDisposed) { await _disposedCompletion.Task; return; }
        try
        {
            if (goodbye is not null)
            {
                using var deadline = new CancellationTokenSource(TimeSpan.FromMilliseconds(200), _time);
                try { await _rtcp.SendAsync(goodbye, _remoteControl!, deadline.Token); lock (_gate) _control.RecordControlSent(); }
                catch (Exception error) when (error is OperationCanceledException or SocketException or IOException) { }
            }
            _rtp.Dispose(); _rtcp.Dispose(); await Task.WhenAll(_tasks); _received.Writer.TryComplete();
            _txCrypto?.Dispose(); _rxCrypto?.Dispose(); _txControlCrypto?.Dispose(); _rxControlCrypto?.Dispose();
            if (_masterKey is not null) CryptographicOperations.ZeroMemory(_masterKey);
            if (_session?.MasterKey is { } remoteKey) CryptographicOperations.ZeroMemory(remoteKey);
            _stop.Dispose();
        }
        finally { _disposedCompletion.TrySetResult(); }
    }
}
