using System.Buffers.Binary;
using System.Text;

namespace Ai.Tlbx.Sip.Media;

/// <summary>Point-to-point SR/RR/SDES reporting. The owning media session serializes access.</summary>
internal sealed class RtcpSession(uint localSource, TimeProvider time)
{
    private readonly byte[] _cname = Encoding.ASCII.GetBytes(SipClient.NewId() + "@ai.tlbx.sip");
    private readonly Dictionary<uint, long> _sentReports = [];
    private uint? _remoteSource;
    private long _base = -1, _highest = -1, _received, _priorExpected, _priorReceived;
    private int _lastTransit;
    private bool _transitKnown;
    private uint _lastRemoteSr;
    private long _lastRemoteSrAt, _lastSentAt;
    private uint _lastSentRtp;
    private long _sentPackets, _sentOctets, _txControl, _rxControl, _rejected, _transportErrors;
    private long? _remoteLost;
    private double? _remoteFraction, _remoteJitter;
    private DateTimeOffset? _lastReport;
    public double JitterSamples { get; private set; }
    public double? RoundTripMilliseconds { get; private set; }
    public SipRtcpMetrics Metrics => new(_txControl, _rxControl, _rejected, _remoteLost, _remoteFraction, _remoteJitter, _lastReport, _transportErrors);
    public void RecordSent(uint timestamp, int octets)
    { _sentPackets++; _sentOctets += octets; _lastSentRtp = timestamp; _lastSentAt = time.GetTimestamp(); }
    public void RecordReceived(uint source, ushort sequence, uint timestamp)
    {
        if (_remoteSource.HasValue && _remoteSource != source) return;
        _remoteSource = source;
        long extended = _highest < 0 ? sequence : (_highest & ~65535L) + sequence;
        if (_highest >= 0 && extended - _highest > 32768) extended -= 65536;
        else if (_highest >= 0 && _highest - extended > 32768) extended += 65536;
        if (_base < 0) _base = extended;
        _highest = Math.Max(_highest, extended); _received++;
        uint arrival = unchecked((uint)(time.GetTimestamp() * (8000.0 / time.TimestampFrequency)));
        int transit = unchecked((int)(arrival - timestamp));
        if (_transitKnown) JitterSamples += (Math.Abs((double)unchecked(transit - _lastTransit)) - JitterSamples) / 16.0;
        _lastTransit = transit; _transitKnown = true;
    }
    internal static ulong NtpTime(DateTimeOffset utc)
    {
        ulong seconds = unchecked((uint)(utc.ToUnixTimeSeconds() + 2208988800L));
        ulong fraction = (ulong)(utc.UtcTicks % TimeSpan.TicksPerSecond) * (1UL << 32) / TimeSpan.TicksPerSecond;
        return (seconds << 32) | fraction;
    }
    public byte[] CreateCompound(bool goodbye = false)
    {
        bool sender = _sentPackets > 0, report = _base >= 0;
        int firstLength = (sender ? 28 : 8) + (report ? 24 : 0);
        int sdesLength = (4 + 4 + 2 + _cname.Length + 1 + 3) & ~3;
        byte[] bytes = new byte[firstLength + sdesLength + (goodbye ? 8 : 0)];
        bytes[0] = report ? (byte)0x81 : (byte)0x80; bytes[1] = sender ? (byte)200 : (byte)201;
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(2), (ushort)(firstLength / 4 - 1));
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(4), localSource);
        if (sender)
        {
            ulong ntp = NtpTime(time.GetUtcNow());
            BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(8), ntp);
            uint timestamp = unchecked(_lastSentRtp + (uint)(time.GetElapsedTime(_lastSentAt).TotalSeconds * 8000));
            BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(16), timestamp);
            BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(20), unchecked((uint)_sentPackets));
            BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(24), unchecked((uint)_sentOctets));
            if (_sentReports.Count >= 32) _sentReports.Remove(_sentReports.Keys.First());
            _sentReports[(uint)(ntp >> 16)] = time.GetTimestamp();
        }
        if (report)
        {
            int offset = sender ? 28 : 8;
            long expected = _highest - _base + 1, lost = expected - _received;
            long intervalExpected = expected - _priorExpected, intervalLost = intervalExpected - (_received - _priorReceived);
            _priorExpected = expected; _priorReceived = _received;
            BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(offset), _remoteSource!.Value);
            bytes[offset + 4] = intervalExpected > 0 && intervalLost > 0 ? (byte)Math.Min(255, intervalLost * 256 / intervalExpected) : (byte)0;
            int signedLoss = (int)Math.Clamp(lost, -8388608, 8388607);
            bytes[offset + 5] = (byte)(signedLoss >> 16); bytes[offset + 6] = (byte)(signedLoss >> 8); bytes[offset + 7] = (byte)signedLoss;
            BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(offset + 8), unchecked((uint)_highest));
            BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(offset + 12), (uint)Math.Clamp(JitterSamples, 0, uint.MaxValue));
            BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(offset + 16), _lastRemoteSr);
            uint delay = _lastRemoteSr == 0 ? 0 : (uint)Math.Clamp(time.GetElapsedTime(_lastRemoteSrAt).TotalSeconds * 65536, 0, uint.MaxValue);
            BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(offset + 20), delay);
        }
        var sdes = bytes.AsSpan(firstLength, sdesLength); sdes[0] = 0x81; sdes[1] = 202;
        BinaryPrimitives.WriteUInt16BigEndian(sdes[2..], (ushort)(sdesLength / 4 - 1));
        BinaryPrimitives.WriteUInt32BigEndian(sdes[4..], localSource);
        sdes[8] = 1; sdes[9] = (byte)_cname.Length; _cname.CopyTo(sdes[10..]);
        if (goodbye)
        {
            var bye = bytes.AsSpan(firstLength + sdesLength); bye[0] = 0x81; bye[1] = 203;
            BinaryPrimitives.WriteUInt16BigEndian(bye[2..], 1); BinaryPrimitives.WriteUInt32BigEndian(bye[4..], localSource);
        }
        return bytes;
    }
    public void RecordControlSent() => _txControl++;
    public void Reject() => _rejected++;
    public void RecordTransportError() => _transportErrors++;
    public bool Receive(ReadOnlySpan<byte> compound)
    {
        if (!Validate(compound)) { Reject(); return false; }
        uint source = BinaryPrimitives.ReadUInt32BigEndian(compound[4..]);
        if (_remoteSource.HasValue && source != _remoteSource) { Reject(); return false; }
        _rxControl++; _lastReport = time.GetUtcNow();
        for (int offset = 0; offset < compound.Length;)
        {
            int length = (BinaryPrimitives.ReadUInt16BigEndian(compound[(offset + 2)..]) + 1) * 4;
            var packet = compound.Slice(offset, length); int count = packet[0] & 31;
            bool sender = packet[1] == 200;
            if (sender)
            { _lastRemoteSr = (uint)(BinaryPrimitives.ReadUInt64BigEndian(packet[8..]) >> 16); _lastRemoteSrAt = time.GetTimestamp(); }
            if (packet[1] is 200 or 201)
                for (int i = 0, pos = sender ? 28 : 8; i < count; i++, pos += 24)
                {
                    if (BinaryPrimitives.ReadUInt32BigEndian(packet[pos..]) != localSource) continue;
                    int lost = (packet[pos + 5] << 16) | (packet[pos + 6] << 8) | packet[pos + 7];
                    _remoteLost = (lost & 0x800000) != 0 ? lost | unchecked((int)0xff000000) : lost;
                    _remoteFraction = packet[pos + 4] / 256.0;
                    _remoteJitter = BinaryPrimitives.ReadUInt32BigEndian(packet[(pos + 12)..]) / 8.0;
                    uint lsr = BinaryPrimitives.ReadUInt32BigEndian(packet[(pos + 16)..]);
                    uint dlsr = BinaryPrimitives.ReadUInt32BigEndian(packet[(pos + 20)..]);
                    if (lsr != 0 && _sentReports.TryGetValue(lsr, out long sentAt))
                    {
                        double roundTrip = time.GetElapsedTime(sentAt).TotalMilliseconds - dlsr * (1000.0 / 65536);
                        if (roundTrip >= 0) RoundTripMilliseconds = roundTrip;
                    }
                }
            offset += length;
        }
        return true;
    }
    internal static bool Validate(ReadOnlySpan<byte> compound)
    {
        if (compound.Length < 8 || compound.Length > 4096 || compound[1] is not (200 or 201)) return false;
        for (int offset = 0; offset < compound.Length;)
        {
            if (compound.Length - offset < 4 || (compound[offset] >> 6) != 2) return false;
            int length = (BinaryPrimitives.ReadUInt16BigEndian(compound[(offset + 2)..]) + 1) * 4;
            if (length > compound.Length - offset) return false;
            var packet = compound.Slice(offset, length); int end = length, count = packet[0] & 31;
            if ((packet[0] & 32) != 0)
            {
                int padding = packet[^1];
                if (offset + length != compound.Length || padding == 0 || padding > length - 4) return false;
                end -= padding;
            }
            if (packet[1] == 200 && end < 28 + count * 24 || packet[1] == 201 && end < 8 + count * 24 || packet[1] == 203 && end < 4 + count * 4) return false;
            if (packet[1] == 202)
            {
                int pos = 4;
                for (int chunk = 0; chunk < count; chunk++)
                {
                    if (pos + 4 > end) return false; pos += 4; bool ended = false;
                    while (pos < end)
                    {
                        byte item = packet[pos++]; if (item == 0) { ended = true; pos = (pos + 3) & ~3; break; }
                        if (pos >= end) return false; int size = packet[pos++];
                        if (pos + size > end) return false; pos += size;
                    }
                    if (!ended || pos > end) return false;
                }
            }
            offset += length;
        }
        return true;
    }
}
