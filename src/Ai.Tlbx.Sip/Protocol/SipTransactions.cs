using System.Collections.Concurrent;

namespace Ai.Tlbx.Sip.Protocol;

internal sealed class SipTransactions(SipClientConfig config, TimeProvider time)
{
    private sealed class Pending
    {
        public TaskCompletionSource<SipMessage> Final { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource FirstResponse { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public volatile bool Provisional;
        public required string CallId;
        public required string FromTag;
        public Action<SipMessage>? Progress;
        public Action? StartAnswerTimer;
        public bool Closed;
    }
    private readonly ConcurrentDictionary<string, Pending> _pending = new();
    public bool Receive(SipMessage message)
    {
        if (!_pending.TryGetValue(message.TransactionKey, out var pending)) return false;
        lock (pending)
        {
            if (pending.Closed || message.Get("Call-ID") != pending.CallId || SipMessage.Parameter(message.Get("From"), "tag") != pending.FromTag) return false;
            if (pending.Final.Task.IsCompleted) return false;
            if (message.StatusCode < 200)
            {
                if (!pending.Provisional) { pending.Provisional = true; pending.StartAnswerTimer?.Invoke(); }
            }
            pending.Progress?.Invoke(message);
            if (message.StatusCode >= 200) pending.Final.TrySetResult(message);
            pending.FirstResponse.TrySetResult();
            return true;
        }
    }
    public void Fail(Exception error)
    {
        foreach (var p in _pending.Values) { p.Final.TrySetException(error); p.FirstResponse.TrySetResult(); }
    }
    public async Task<SipMessage> SendAsync(SipMessage request, SipTransport transport,
        Action<SipMessage>? progress, CancellationToken cancellationToken)
    {
        using var deadline = new CancellationTokenSource();
        using var timer = time.CreateTimer(_ => deadline.Cancel(), null, config.TransactionTimeout, Timeout.InfiniteTimeSpan);
        var pending = new Pending
        {
            Progress = progress, CallId = request.Get("Call-ID"), FromTag = SipMessage.Parameter(request.Get("From"), "tag"),
            StartAnswerTimer = request.Method == "INVITE" ? () => timer.Change(config.CallAnswerTimeout, Timeout.InfiniteTimeSpan) : null
        };
        string key = request.TransactionKey;
        if (!_pending.TryAdd(key, pending)) throw new InvalidOperationException("Duplicate SIP transaction.");
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
        catch (OperationCanceledException) when (request.Method == "INVITE")
        {
            // Keep the INVITE transaction registered while cancelling so that a
            // racing final response still reaches the dialog owner.
            try
            {
                var final = await CancelInviteAsync(request, pending, transport);
                if (cancellationToken.IsCancellationRequested) return final;
            }
            catch (Exception error) when (error is OperationCanceledException or TimeoutException or IOException or System.Net.Sockets.SocketException)
            { /* The original cancellation/timeout remains the public outcome. */ }
            if (cancellationToken.IsCancellationRequested) throw new OperationCanceledException(cancellationToken);
            throw new TimeoutException("SIP INVITE transaction timed out.");
        }
        catch (OperationCanceledException) when (deadline.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        { throw new TimeoutException($"SIP {request.Method} transaction timed out."); }
        finally { lock (pending) { pending.Closed = true; _pending.TryRemove(key, out _); } }
    }
    private async Task<SipMessage> CancelInviteAsync(SipMessage invite, Pending pending, SipTransport transport)
    {
        using var cleanup = new CancellationTokenSource(config.TransactionTimeout, time);
        // RFC 3261 section 9.1: never send CANCEL before any provisional response.
        await pending.FirstResponse.Task.WaitAsync(cleanup.Token);
        if (pending.Final.Task.IsCompleted) return await pending.Final.Task;
        var cancel = new SipMessage { StartLine = $"CANCEL {invite.RequestUri} SIP/2.0" };
        foreach (string name in new[] { "Via", "From", "To", "Call-ID", "Route", "Max-Forwards" })
            foreach (string value in invite.GetAll(name)) cancel.Add(name, value);
        cancel.Add("CSeq", invite.CSeqNumber + " CANCEL");
        await SendAsync(cancel, transport, null, cleanup.Token);
        return await pending.Final.Task.WaitAsync(cleanup.Token);
    }
}
