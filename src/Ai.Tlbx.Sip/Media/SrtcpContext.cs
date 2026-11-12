using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Ai.Tlbx.Sip.Media;

/// <summary>RFC 3711 SRTCP, encrypted AES-CM/HMAC-SHA1-80, independent keys/index/replay window.</summary>
internal sealed class SrtcpContext(ReadOnlySpan<byte> master) : IDisposable
{
    private readonly SrtpContext _keys = new(master, control: true);
    private uint _sendIndex;
    private long _highest = -1;
    private ulong _replay;
    private uint? _source;
    public byte[] Protect(ReadOnlySpan<byte> packet)
    {
        if (packet.Length < 8) throw new ArgumentException("RTCP header is incomplete.");
        if (_sendIndex > 0x7fffffff) throw new CryptographicException("SRTCP key usage limit reached; rekey before sending again.");
        byte[] result = new byte[packet.Length + 14]; packet.CopyTo(result);
        _keys.Crypt(result.AsSpan(8, packet.Length - 8), BinaryPrimitives.ReadUInt32BigEndian(packet[4..]), _sendIndex);
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(packet.Length), _sendIndex++ | 0x80000000);
        _keys.AuthenticationTag(result.AsSpan(0, packet.Length + 4)).AsSpan(0, 10).CopyTo(result.AsSpan(packet.Length + 4));
        return result;
    }
    public byte[]? Unprotect(ReadOnlySpan<byte> packet)
    {
        if (packet.Length < 22) return null;
        int length = packet.Length - 14;
        uint encoded = BinaryPrimitives.ReadUInt32BigEndian(packet[length..]), index = encoded & 0x7fffffff;
        if ((encoded & 0x80000000) == 0) return null; // This profile requires encrypted control traffic.
        uint source = BinaryPrimitives.ReadUInt32BigEndian(packet[4..]);
        if (_source.HasValue && _source != source) return null;
        long distance = _highest - index;
        if (distance >= 64 || (distance >= 0 && (_replay & (1UL << (int)distance)) != 0)) return null;
        var tag = _keys.AuthenticationTag(packet[..(length + 4)]);
        if (!CryptographicOperations.FixedTimeEquals(tag.AsSpan(0, 10), packet[(length + 4)..])) return null;
        byte[] result = packet[..length].ToArray(); _keys.Crypt(result.AsSpan(8), source, index);
        if (index > _highest)
        { long shift = index - _highest; _replay = shift >= 64 ? 1 : (_replay << (int)shift) | 1; _highest = index; }
        else _replay |= 1UL << (int)distance;
        _source = source; return result;
    }
    public void Dispose() => _keys.Dispose();
}
