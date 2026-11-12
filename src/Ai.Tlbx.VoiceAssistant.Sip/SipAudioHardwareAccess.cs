using System.Buffers.Binary;
using Ai.Tlbx.Sip;
using Ai.Tlbx.Sip.Media;
using Ai.Tlbx.VoiceAssistant.Interfaces;
using Ai.Tlbx.VoiceAssistant.Models;

namespace Ai.Tlbx.VoiceAssistant.Sip;

/// <summary>One adapter per call. Disposing it leaves call ownership with the application.</summary>
public sealed class SipAudioHardwareAccess : IAudioHardwareAccess
{
    private readonly SipCall call;
    private readonly TimeSpan _maxBufferedAudio;
    private readonly object _outputGate = new();
    private readonly Queue<OutputChunk> _output = new();
    private readonly SemaphoreSlim _outputReady = new(0, 1);
    private readonly CancellationTokenSource _outputStop = new();
    private readonly Task _send;
    private double _pendingSeconds;
    private sealed class OutputChunk(short[] samples, int rate)
    {
        public short[] Samples { get; } = samples;
        public int Rate { get; } = rate;
        public int Offset;
    }
    /// <param name="maxBufferedAudio">Maximum unsent AI audio, including the SIP queue. Defaults to one minute.</param>
    public SipAudioHardwareAccess(SipCall call, TimeSpan? maxBufferedAudio = null)
    {
        this.call = call ?? throw new ArgumentNullException(nameof(call));
        _maxBufferedAudio = maxBufferedAudio ?? TimeSpan.FromMinutes(1);
        if (_maxBufferedAudio < TimeSpan.FromMilliseconds(20) || _maxBufferedAudio > TimeSpan.FromMinutes(5))
            throw new ArgumentOutOfRangeException(nameof(maxBufferedAudio));
        _send = SendAsync();
    }
    /// <summary>Unsent audio in both the adapter and paced SIP transmitter.</summary>
    public TimeSpan BufferedAudio { get { lock (_outputGate) return TimeSpan.FromSeconds(_pendingSeconds) + call.Audio.QueuedAudio; } }
    private readonly SemaphoreSlim _lifecycle = new(1, 1);
    private CancellationTokenSource? _recording;
    private Task? _receive;
    private DiagnosticLevel _diagnostic;
    private Action<LogLevel, string> _log = (_, _) => { };
    private bool _disposed;
    public event EventHandler<string>? AudioError;
    public Task InitAudioAsync() { ObjectDisposedException.ThrowIf(_disposed, this); return Task.CompletedTask; }
    public async Task<bool> StartRecordingAudio(MicrophoneAudioReceivedEventHandler audioDataReceivedHandler, AudioSampleRate targetSampleRate = AudioSampleRate.Rate24000)
    {
        ArgumentNullException.ThrowIfNull(audioDataReceivedHandler);
        await _lifecycle.WaitAsync();
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_receive is not null) return false;
            _recording = new();
            _receive = ReceiveAsync(audioDataReceivedHandler, (int)targetSampleRate, _recording.Token);
            return true;
        }
        finally { _lifecycle.Release(); }
    }
    private async Task ReceiveAsync(MicrophoneAudioReceivedEventHandler handler, int rate, CancellationToken cancellationToken)
    {
        var resampler = new PcmResampler(call.Audio.SampleRate, rate);
        try
        {
            await foreach (var frame in call.Audio.ReadFramesAsync(cancellationToken))
            {
                short[] samples = resampler.Process(frame.Samples.Span);
                byte[] bytes = new byte[samples.Length * 2];
                for (int i = 0; i < samples.Length; i++) BinaryPrimitives.WriteInt16LittleEndian(bytes.AsSpan(i * 2), samples[i]);
                handler(this, new MicrophoneAudioReceivedEventArgs(Convert.ToBase64String(bytes)));
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        catch (Exception error) { Fail(error.Message); }
    }
    public bool PlayAudio(string base64EncodedPcm16Audio, int sampleRate)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        try
        {
            if (sampleRate is < 8000 or > 96000) throw new ArgumentOutOfRangeException(nameof(sampleRate));
            byte[] bytes = Convert.FromBase64String(base64EncodedPcm16Audio);
            if ((bytes.Length & 1) != 0) throw new ArgumentException("PCM16 requires complete samples.");
            short[] samples = new short[bytes.Length / 2];
            for (int i = 0; i < samples.Length; i++) samples[i] = BinaryPrimitives.ReadInt16LittleEndian(bytes.AsSpan(i * 2));
            lock (_outputGate)
            {
                if (!_disposed && call.Status.State == SipCallState.Established &&
                    _pendingSeconds + call.Audio.QueuedAudio.TotalSeconds + (double)samples.Length / sampleRate <= _maxBufferedAudio.TotalSeconds)
                {
                    if (samples.Length > 0)
                    {
                        _output.Enqueue(new(samples, sampleRate));
                        _pendingSeconds += (double)samples.Length / sampleRate;
                        if (_outputReady.CurrentCount == 0) _outputReady.Release();
                    }
                    return true;
                }
            }
            Fail("SIP playback buffer limit exceeded or call is not established; audio chunk rejected.");
            return false;
        }
        catch (Exception error) when (error is FormatException or ArgumentException or ObjectDisposedException)
        { Fail(error.Message); return false; }
    }
    private async Task SendAsync()
    {
        try
        {
            while (true)
            {
                await _outputReady.WaitAsync(_outputStop.Token);
                while (true)
                {
                    bool blocked;
                    lock (_outputGate)
                    {
                        if (_output.Count == 0) break;
                        if (call.Status.State != SipCallState.Established)
                        { _output.Clear(); _pendingSeconds = 0; break; }
                        var chunk = _output.Peek();
                        // AI callbacks can deliver many seconds faster than real time.
                        // Retry small slices without dropping or reordering their middle.
                        int count = Math.Min(chunk.Samples.Length - chunk.Offset, chunk.Rate / 100);
                        blocked = !call.Audio.TryWrite(chunk.Samples.AsSpan(chunk.Offset, count), chunk.Rate);
                        if (!blocked)
                        {
                            chunk.Offset += count; _pendingSeconds = Math.Max(0, _pendingSeconds - (double)count / chunk.Rate);
                            if (chunk.Offset == chunk.Samples.Length) _output.Dequeue();
                        }
                    }
                    if (blocked) await Task.Delay(10, _outputStop.Token);
                }
            }
        }
        catch (OperationCanceledException) when (_outputStop.IsCancellationRequested) { }
        catch (Exception error) { Fail(error.Message); }
    }
    public async Task<bool> StopRecordingAudio()
    {
        await _lifecycle.WaitAsync();
        try
        {
            if (_recording is null) return true;
            _recording.Cancel(); if (_receive is not null) await _receive;
            _recording.Dispose(); _recording = null; _receive = null; return true;
        }
        finally { _lifecycle.Release(); }
    }
    public Task ClearAudioQueueAsync()
    {
        // The sender holds this same lock while submitting slices: cleared audio
        // can never be reintroduced after an interruption.
        lock (_outputGate) { _output.Clear(); _pendingSeconds = 0; call.Audio.ClearOutput(); }
        return Task.CompletedTask;
    }
    public Task<List<AudioDeviceInfo>> GetAvailableMicrophonesAsync() => Task.FromResult<List<AudioDeviceInfo>>([new() { Id = call.Id, Name = "SIP call", IsDefault = true }]);
    public Task<List<AudioDeviceInfo>> RequestMicrophonePermissionAndGetDevicesAsync() => GetAvailableMicrophonesAsync();
    public Task<bool> SetMicrophoneDeviceAsync(string deviceId) => Task.FromResult(deviceId == call.Id);
    public Task<string?> GetCurrentMicrophoneDeviceAsync() => Task.FromResult<string?>(call.Id);
    public Task<bool> SetDiagnosticLevelAsync(DiagnosticLevel level) { _diagnostic = level; return Task.FromResult(true); }
    public Task<DiagnosticLevel> GetDiagnosticLevelAsync() => Task.FromResult(_diagnostic);
    public void SetLogAction(Action<LogLevel, string> logAction) => _log = logAction ?? throw new ArgumentNullException(nameof(logAction));
    public async Task<bool> WaitForPlaybackDrainAsync(TimeSpan? timeout = null)
    {
        var elapsed = System.Diagnostics.Stopwatch.StartNew();
        var limit = timeout ?? TimeSpan.FromSeconds(30);
        while (true)
        {
            lock (_outputGate)
            {
                if (_disposed) return false;
                if (_output.Count == 0) break;
            }
            if (elapsed.Elapsed >= limit || call.Status.State != SipCallState.Established) return false;
            await Task.Delay(10);
        }
        return await call.Audio.WaitForDrainAsync(limit > elapsed.Elapsed ? limit - elapsed.Elapsed : TimeSpan.Zero);
    }
    private void Fail(string message)
    {
        try { _log(LogLevel.Error, message); } catch { }
        foreach (EventHandler<string> handler in AudioError?.GetInvocationList() ?? []) try { handler(this, message); } catch { }
    }
    public async ValueTask DisposeAsync()
    {
        lock (_outputGate)
        {
            if (_disposed) return;
            _disposed = true; _output.Clear(); _pendingSeconds = 0;
            _outputStop.Cancel(); call.Audio.ClearOutput();
        }
        await _send; await StopRecordingAudio();
        _outputStop.Dispose(); _outputReady.Dispose();
    }
}
