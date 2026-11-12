using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Ai.Tlbx.Sip.Media;

/// <summary>RFC 3711 AES_CM_128_HMAC_SHA1_80, kdr=0. AES and HMAC use the platform cryptography APIs.</summary>
internal sealed class SrtpContext : IDisposable
{
    private readonly byte[] _encryption, _authentication, _salt;
    private long _highest = -1;
    private ulong _replay;
    public SrtpContext(ReadOnlySpan<byte> master)
    {
        if (master.Length != 30) throw new ArgumentException("SRTP requires a 16-byte key and 14-byte salt.");
        _encryption = Derive(master[..16], master[16..], 0, 16);
        _authentication = Derive(master[..16], master[16..], 1, 20);
        _salt = Derive(master[..16], master[16..], 2, 14);
    }
    internal static byte[] Derive(ReadOnlySpan<byte> key, ReadOnlySpan<byte> salt, byte label, int length)
    {
        byte[] iv = new byte[16]; salt.CopyTo(iv); iv[7] ^= label;
        return KeyStream(key, iv, length);
    }
    private static byte[] KeyStream(ReadOnlySpan<byte> key, byte[] counter, int length)
    {
        using var aes = Aes.Create(); aes.Key = key.ToArray();
        byte[] result = new byte[length]; Span<byte> block = stackalloc byte[16];
        for (int offset = 0; offset < length; offset += 16)
        {
            aes.EncryptEcb(counter, block, PaddingMode.None);
            block[..Math.Min(16, length - offset)].CopyTo(result.AsSpan(offset));
            for (int i = 15; i >= 0 && ++counter[i] == 0; i--) { }
        }
        return result;
    }
    private long Estimate(ushort sequence)
    {
        if (_highest < 0) return sequence;
        long roc = _highest >> 16; int last = (ushort)_highest;
        if (last < 32768 && sequence - last > 32768) roc--;
        else if (last >= 32768 && last - sequence > 32768) roc++;
        return (roc << 16) | sequence;
    }
    private void Crypt(Span<byte> payload, uint ssrc, long index)
    {
        byte[] iv = new byte[16]; _salt.CopyTo(iv, 0);
        Span<byte> mask = stackalloc byte[16]; mask.Clear();
        BinaryPrimitives.WriteUInt32BigEndian(mask[4..], ssrc);
        ulong shifted = (ulong)index << 16;
        BinaryPrimitives.WriteUInt64BigEndian(mask[8..], shifted);
        for (int i = 0; i < 16; i++) iv[i] ^= mask[i];
        byte[] stream = KeyStream(_encryption, iv, payload.Length);
        for (int i = 0; i < payload.Length; i++) payload[i] ^= stream[i];
        CryptographicOperations.ZeroMemory(stream);
    }
    public byte[] Protect(ReadOnlySpan<byte> packet, int headerLength)
    {
        ushort sequence = BinaryPrimitives.ReadUInt16BigEndian(packet[2..]);
        long index = Estimate(sequence);
        if (index < 0 || index >= (1L << 48)) throw new CryptographicException("SRTP packet index exhausted.");
        byte[] result = new byte[packet.Length + 10]; packet.CopyTo(result);
        Crypt(result.AsSpan(headerLength, packet.Length - headerLength), BinaryPrimitives.ReadUInt32BigEndian(packet[8..]), index);
        byte[] authenticated = new byte[packet.Length + 4]; result.AsSpan(0, packet.Length).CopyTo(authenticated);
        BinaryPrimitives.WriteUInt32BigEndian(authenticated.AsSpan(packet.Length), (uint)(index >> 16));
        HMACSHA1.HashData(_authentication, authenticated).AsSpan(0, 10).CopyTo(result.AsSpan(packet.Length));
        _highest = Math.Max(_highest, index); return result;
    }
    public byte[]? Unprotect(ReadOnlySpan<byte> packet, int headerLength)
    {
        if (packet.Length < headerLength + 10) return null;
        ushort sequence = BinaryPrimitives.ReadUInt16BigEndian(packet[2..]);
        long index = Estimate(sequence), distance = _highest - index;
        if (index < 0 || distance >= 64 || (distance >= 0 && (_replay & (1UL << (int)distance)) != 0)) return null;
        int length = packet.Length - 10;
        byte[] authenticated = new byte[length + 4]; packet[..length].CopyTo(authenticated);
        BinaryPrimitives.WriteUInt32BigEndian(authenticated.AsSpan(length), (uint)(index >> 16));
        var tag = HMACSHA1.HashData(_authentication, authenticated);
        if (!CryptographicOperations.FixedTimeEquals(tag.AsSpan(0, 10), packet[length..])) return null;
        byte[] result = packet[..length].ToArray();
        Crypt(result.AsSpan(headerLength), BinaryPrimitives.ReadUInt32BigEndian(packet[8..]), index);
        if (index > _highest)
        {
            long shift = index - _highest; _replay = shift >= 64 ? 1 : (_replay << (int)shift) | 1;
            _highest = index;
        }
        else _replay |= 1UL << (int)distance;
        return result;
    }
    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(_encryption); CryptographicOperations.ZeroMemory(_authentication); CryptographicOperations.ZeroMemory(_salt);
    }
}
