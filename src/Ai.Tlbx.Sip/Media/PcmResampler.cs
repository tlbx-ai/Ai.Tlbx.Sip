namespace Ai.Tlbx.Sip.Media;

/// <summary>Streaming band-limited PCM16 resampler. One instance owns each direction's phase and filter history.</summary>
public sealed class PcmResampler
{
    private const int Radius = 32;
    private readonly int _inputRate, _outputRate;
    private readonly List<short> _input = [];
    private long _baseIndex, _received, _produced;
    private bool _finished;
    public PcmResampler(int inputRate, int outputRate)
    {
        if (inputRate is < 8000 or > 192000 || outputRate is < 8000 or > 192000) throw new ArgumentOutOfRangeException(nameof(inputRate));
        _inputRate = inputRate; _outputRate = outputRate;
    }
    public short[] Process(ReadOnlySpan<short> samples, bool endOfStream = false)
    {
        if (_finished) throw new InvalidOperationException("Resampler has been flushed. Reset before reusing it.");
        _finished = endOfStream;
        if (_inputRate == _outputRate) return samples.ToArray();
        foreach (short s in samples) _input.Add(s);
        _received += samples.Length;
        var result = new List<short>();
        double cutoff = Math.Min(1.0, (double)_outputRate / _inputRate) * 0.92;
        while (_produced * _inputRate < (endOfStream ? _received : _received - Radius) * _outputRate)
        {
            double position = (double)_produced * _inputRate / _outputRate;
            long center = (long)Math.Floor(position);
            double value = 0, weightSum = 0;
            for (long i = center - Radius + 1; i <= center + Radius; i++)
            {
                double distance = position - i;
                if (Math.Abs(distance) >= Radius) continue;
                double x = Math.PI * cutoff * distance;
                double sinc = Math.Abs(x) < 1e-12 ? 1 : Math.Sin(x) / x;
                double window = 0.42 + 0.5 * Math.Cos(Math.PI * distance / Radius) + 0.08 * Math.Cos(2 * Math.PI * distance / Radius);
                double weight = cutoff * sinc * window;
                long clamped = Math.Clamp(i, 0, Math.Max(0, _received - 1));
                if (clamped >= _baseIndex && clamped - _baseIndex < _input.Count)
                    value += _input[(int)(clamped - _baseIndex)] * weight;
                weightSum += weight;
            }
            result.Add((short)Math.Clamp(Math.Round(value / weightSum), short.MinValue, short.MaxValue));
            _produced++;
        }
        long nextCenter = _produced * _inputRate / _outputRate;
        int remove = (int)Math.Clamp(nextCenter - Radius - _baseIndex, 0, _input.Count);
        if (remove > 0) { _input.RemoveRange(0, remove); _baseIndex += remove; }
        return result.ToArray();
    }
    public void Reset() { _input.Clear(); _baseIndex = _received = _produced = 0; _finished = false; }
}
