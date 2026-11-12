using System.Net;
using System.Net.Sockets;
using Ai.Tlbx.Sip.Protocol;

/// <summary>A real stream peer that deliberately splits SIP messages across writes.</summary>
internal sealed class TcpTestPbx : IAsyncDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource _stop = new();
    private readonly Task _loop;
    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;
    public bool Unregistered { get; private set; }
    public TcpTestPbx() { _listener.Start(); _loop = RunAsync(); }
    private async Task RunAsync()
    {
        try
        {
            using var client = await _listener.AcceptTcpClientAsync(_stop.Token);
            using var stream = client.GetStream();
            byte[] buffer = new byte[65536]; int used = 0;
            while (!_stop.IsCancellationRequested)
            {
                int read = await stream.ReadAsync(buffer.AsMemory(used), _stop.Token); if (read == 0) return;
                used += read;
                while (SipMessage.TryGetLength(buffer.AsSpan(0, used), out int length, out _) && used >= length)
                {
                    var request = SipMessage.Parse(buffer.AsSpan(0, length));
                    Buffer.BlockCopy(buffer, length, buffer, 0, used - length); used -= length;
                    if (request.Method != "REGISTER") throw new Exception("Unexpected TCP request.");
                    Unregistered = request.Get("Expires") == "0";
                    var response = SipMessage.Response(request, 200, "OK"); response.Add("Expires", request.Get("Expires"));
                    byte[] bytes = response.Serialize();
                    for (int offset = 0; offset < bytes.Length; offset += 7)
                        await stream.WriteAsync(bytes.AsMemory(offset, Math.Min(7, bytes.Length - offset)), _stop.Token);
                }
            }
        }
        catch (OperationCanceledException) when (_stop.IsCancellationRequested) { }
        catch (ObjectDisposedException) when (_stop.IsCancellationRequested) { }
    }
    public async ValueTask DisposeAsync() { _stop.Cancel(); _listener.Stop(); await _loop; _stop.Dispose(); }
}
