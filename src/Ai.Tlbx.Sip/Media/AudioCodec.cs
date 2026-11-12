using NAudio.Codecs;

namespace Ai.Tlbx.Sip.Media;

internal sealed class AudioCodec(string name)
{
    private readonly G722Codec _g722 = new();
    private readonly G722CodecState _encoder = new(64000, G722Flags.None);
    private readonly G722CodecState _decoder = new(64000, G722Flags.None);
    public int SampleRate => name == "G722" ? 16000 : 8000;
    // RFC 3551 deliberately uses an 8-kHz RTP clock for G.722's 16-kHz PCM.
    public int ClockRate => 8000;
    public byte[] Encode(short[] samples)
    {
        if (name == "G722")
        {
            var bytes = new byte[(samples.Length + 1) / 2];
            int count = _g722.Encode(_encoder, bytes, samples, samples.Length);
            return bytes.AsSpan(0, count).ToArray();
        }
        return samples.Select(s => G711.Encode(s, name == "PCMA")).ToArray();
    }
    public short[] Decode(byte[] payload)
    {
        if (name == "G722")
        {
            var samples = new short[payload.Length * 2];
            int count = _g722.Decode(_decoder, samples, payload, payload.Length);
            return samples.AsSpan(0, count).ToArray();
        }
        return payload.Select(b => G711.Decode(b, name == "PCMA")).ToArray();
    }
}
