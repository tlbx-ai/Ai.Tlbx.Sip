using System.Collections.Concurrent;

namespace Ai.Tlbx.Sip;

/// <summary>Owns independent identities. Loading configuration never implicitly connects or persists secrets.</summary>
public sealed class SipClientManager(TimeProvider? timeProvider = null) : IAsyncDisposable
{
    private readonly ConcurrentDictionary<string, SipClient> _clients = new(StringComparer.Ordinal);
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;
    private readonly object _gate = new();
    private bool _disposed;
    public IReadOnlyCollection<SipClient> Clients => _clients.Values.ToArray();
    public SipClient CreateClient(SipClientConfig configuration)
    {
        configuration.Validate();
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_clients.ContainsKey(configuration.Id)) throw new ArgumentException("A client with this ID already exists.", nameof(configuration));
            var client = new SipClient(configuration, _time);
            _clients[configuration.Id] = client;
            return client;
        }
    }
    public IReadOnlyList<SipClient> LoadClients(IEnumerable<SipClientConfig> configurations)
    {
        var configs = configurations.ToArray();
        foreach (var config in configs) config.Validate();
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (configs.Select(c => c.Id).Distinct(StringComparer.Ordinal).Count() != configs.Length || configs.Any(c => _clients.ContainsKey(c.Id)))
                throw new ArgumentException("Configuration contains duplicate or existing client IDs.");
            return configs.Select(CreateClient).ToArray();
        }
    }
    public SipClient GetClient(string id) => _clients.TryGetValue(id, out var client) ? client : throw new KeyNotFoundException(id);
    public async Task<bool> RemoveClientAsync(string id)
    {
        SipClient? client;
        lock (_gate) { if (!_clients.TryRemove(id, out client)) return false; }
        await client.DisposeAsync(); return true;
    }
    public async ValueTask DisposeAsync()
    {
        SipClient[] clients;
        lock (_gate) { if (_disposed) return; _disposed = true; clients = _clients.Values.ToArray(); _clients.Clear(); }
        await Task.WhenAll(clients.Select(async c => await c.DisposeAsync()));
    }
}
