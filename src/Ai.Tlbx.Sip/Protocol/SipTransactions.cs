using System.Collections.Concurrent;

namespace Ai.Tlbx.Sip.Protocol;

internal sealed class SipTransactions(SipClientConfig config, TimeProvider time)
{
    private sealed class Pending
    {
        public TaskCompletionSource<SipMessage> Final { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public bool Provisional;
        public Action<SipMessage>? Progress;
    }
    private readonly ConcurrentDictionary<string, Pending> _pending = new();
    public bool Receive(SipMessage message)
    {
        if (!_pending.TryGetValue(message.TransactionKey, out var pending)) return false;
        if (message.StatusCode < 200)
        {
            pending.Provisional = true; pending.Progress?.Invoke(message);
        }
        else pending.Final.TrySetResult(message);
        return true;
    }
    public void Fail(Exception error)
    {
        foreach (var p in _pending.Values) p.Final.TrySetException(error);
    }
    public async Task<SipMessage> SendAsync(SipMessage request, SipTransport transport,
        Action<SipMessage>? progress, CancellationToken cancellationToken)
    {
        var pending = new Pending { Progress = progress };
        if (!_pending.TryAdd(request.TransactionKey, pending)) throw new InvalidOperationException("Duplicate SIP transaction.");
        using var deadline = new CancellationTokenSource(config.TransactionTimeout, time);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        try
        {
            await transport.SendAsync(request, linked.Token);
            TimeSpan interval = config.InitialRetransmitInterval;
            while (!pending.Final.Task.IsCompleted)
            {
                if (transport.IsReliable || (request.Method == "INVITE" && pending.Provisional))
                    return await pending.Final.Task.WaitAsync(linked.Token);
                using var tick = CancellationTokenSource.CreateLinkedTokenSource(linked.Token);
                var delay = Task.Delay(interval, time, tick.Token);
                var completed = await Task.WhenAny(pending.Final.Task, delay);
                if (completed == pending.Final.Task) { tick.Cancel(); break; }
                await delay;
                if (request.Method != "INVITE" || !pending.Provisional) await transport.SendAsync(request, linked.Token);
                interval = TimeSpan.FromMilliseconds(Math.Min(interval.TotalMilliseconds * 2, request.Method == "INVITE" ? 32000 : 4000));
            }
            return await pending.Final.Task;
        }
        catch (OperationCanceledException) when (deadline.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        { throw new TimeoutException($"SIP {request.Method} transaction timed out."); }
        finally { _pending.TryRemove(request.TransactionKey, out _); }
    }
}
