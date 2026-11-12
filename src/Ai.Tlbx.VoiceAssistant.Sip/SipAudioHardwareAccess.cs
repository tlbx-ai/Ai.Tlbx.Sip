using System.Buffers.Binary;
using Ai.Tlbx.Sip;
using Ai.Tlbx.Sip.Media;
using Ai.Tlbx.VoiceAssistant.Interfaces;
using Ai.Tlbx.VoiceAssistant.Models;

namespace Ai.Tlbx.VoiceAssistant.Sip;

/// <summary>One adapter per call. Disposing it leaves call ownership with the application.</summary>
public sealed class SipAudioHardwareAccess(SipCall call) : IAudioHardwareAccess
{
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
            byte[] bytes = Convert.FromBase64String(base64EncodedPcm16Audio);
            if ((bytes.Length & 1) != 0) throw new ArgumentException("PCM16 requires complete samples.");
            short[] samples = new short[bytes.Length / 2];
            for (int i = 0; i < samples.Length; i++) samples[i] = BinaryPrimitives.ReadInt16LittleEndian(bytes.AsSpan(i * 2));
            bool accepted = call.Audio.TryWrite(samples, sampleRate);
            if (!accepted) Fail("SIP transmit audio queue is full or closed.");
            return accepted;
        }
        catch (Exception error) when (error is FormatException or ArgumentException or ObjectDisposedException)
        { Fail(error.Message); return false; }
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
    public Task ClearAudioQueueAsync() { call.Audio.ClearOutput(); return Task.CompletedTask; }
    public Task<List<AudioDeviceInfo>> GetAvailableMicrophonesAsync() => Task.FromResult<List<AudioDeviceInfo>>([new() { Id = call.Id, Name = "SIP call", IsDefault = true }]);
    public Task<List<AudioDeviceInfo>> RequestMicrophonePermissionAndGetDevicesAsync() => GetAvailableMicrophonesAsync();
    public Task<bool> SetMicrophoneDeviceAsync(string deviceId) => Task.FromResult(deviceId == call.Id);
    public Task<string?> GetCurrentMicrophoneDeviceAsync() => Task.FromResult<string?>(call.Id);
    public Task<bool> SetDiagnosticLevelAsync(DiagnosticLevel level) { _diagnostic = level; return Task.FromResult(true); }
    public Task<DiagnosticLevel> GetDiagnosticLevelAsync() => Task.FromResult(_diagnostic);
    public void SetLogAction(Action<LogLevel, string> logAction) => _log = logAction ?? throw new ArgumentNullException(nameof(logAction));
    public Task<bool> WaitForPlaybackDrainAsync(TimeSpan? timeout = null) => call.Audio.WaitForDrainAsync(timeout ?? TimeSpan.FromSeconds(30));
    private void Fail(string message)
    {
        try { _log(LogLevel.Error, message); } catch { }
        foreach (EventHandler<string> handler in AudioError?.GetInvocationList() ?? []) try { handler(this, message); } catch { }
    }
    public async ValueTask DisposeAsync() { if (_disposed) return; _disposed = true; await StopRecordingAudio(); }
}
