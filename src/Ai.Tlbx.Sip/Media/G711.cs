namespace Ai.Tlbx.Sip.Media;

internal static class G711
{
    public static short Decode(byte value, bool alaw)
    {
        if (!alaw)
        {
            int u = (~value) & 255;
            int magnitude = (((u & 15) << 3) + 132) << ((u >> 4) & 7);
            return (short)((u & 128) != 0 ? 132 - magnitude : magnitude - 132);
        }
        int a = value ^ 0x55, segment = (a >> 4) & 7;
        int sample = ((a & 15) << 4) + (segment == 0 ? 8 : 264);
        if (segment > 1) sample <<= segment - 1;
        return (short)((a & 128) != 0 ? sample : -sample);
    }
    public static byte Encode(short sample, bool alaw)
    {
        int value = sample;
        if (!alaw)
        {
            int sign = value < 0 ? 128 : 0;
            value = Math.Min(Math.Abs(value), 32635) + 132;
            int exponent = 7;
            for (int mask = 0x4000; exponent > 0 && (value & mask) == 0; exponent--, mask >>= 1) { }
            return (byte)~(sign | (exponent << 4) | ((value >> (exponent + 3)) & 15));
        }
        int xor = value >= 0 ? 0xD5 : 0x55;
        value = Math.Min(value < 0 ? -value - 1 : value, 32767);
        int segment = 0;
        for (int end = 255; segment < 7 && value > end; segment++, end = (end << 1) | 1) { }
        return (byte)(((segment << 4) | ((value >> (segment == 0 ? 4 : segment + 3)) & 15)) ^ xor);
    }
}
