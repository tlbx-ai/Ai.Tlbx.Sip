using System.Globalization;
using System.Text;

namespace Ai.Tlbx.Sip.Protocol;

/// <summary>RFC 3261 message syntax. Duplicate headers are preserved; body lengths count UTF-8 octets.</summary>
internal sealed class SipMessage
{
    private static readonly Dictionary<string, string> Compact = new(StringComparer.OrdinalIgnoreCase)
    {
        ["v"] = "Via", ["f"] = "From", ["t"] = "To", ["i"] = "Call-ID", ["m"] = "Contact",
        ["l"] = "Content-Length", ["c"] = "Content-Type", ["k"] = "Supported", ["s"] = "Subject"
    };
    public const int MaxMessageBytes = 65536;
    public required string StartLine { get; init; }
    public List<KeyValuePair<string, string>> Headers { get; } = [];
    public byte[] Body { get; set; } = [];
    public bool IsResponse => StartLine.StartsWith("SIP/2.0 ", StringComparison.Ordinal);
    public int StatusCode => IsResponse ? int.Parse(StartLine.Split(' ', 3)[1], CultureInfo.InvariantCulture) : 0;
    public string ReasonPhrase => IsResponse ? StartLine.Split(' ', 3).ElementAtOrDefault(2) ?? "" : "";
    public string Method => IsResponse ? CSeqMethod : StartLine.Split(' ', 3)[0];
    public string RequestUri => StartLine.Split(' ', 3)[1];
    public string CSeqMethod => Get("CSeq").Split(' ', StringSplitOptions.RemoveEmptyEntries).LastOrDefault() ?? "";
    public int CSeqNumber => int.Parse(Get("CSeq").Split(' ', StringSplitOptions.RemoveEmptyEntries)[0], CultureInfo.InvariantCulture);
    public string TransactionKey => Parameter(Get("Via"), "branch") + ":" + Get("CSeq");
    public string Get(string name) => Headers.FirstOrDefault(h => h.Key.Equals(name, StringComparison.OrdinalIgnoreCase)).Value ?? "";
    public IEnumerable<string> GetAll(string name) => Headers.Where(h => h.Key.Equals(name, StringComparison.OrdinalIgnoreCase)).Select(h => h.Value);
    public void Add(string name, string value)
    {
        if (name.Any(c => c <= ' ' || c >= 127 || c == ':') || value.Any(c => c is '\r' or '\n' or '\0'))
            throw new ArgumentException("Invalid SIP header.");
        Headers.Add(new(name, value));
    }
    public void Set(string name, string value) { Headers.RemoveAll(h => h.Key.Equals(name, StringComparison.OrdinalIgnoreCase)); Add(name, value); }
    public static SipMessage FailureAck(SipMessage invite, SipMessage response)
    {
        var ack = new SipMessage { StartLine = $"ACK {invite.RequestUri} SIP/2.0" };
        foreach (string name in new[] { "Via", "From", "Call-ID", "Max-Forwards", "Route" })
            foreach (string value in invite.GetAll(name)) ack.Add(name, value);
        ack.Add("To", response.Get("To")); ack.Add("CSeq", invite.CSeqNumber + " ACK");
        return ack;
    }
    public byte[] Serialize()
    {
        var text = new StringBuilder().Append(StartLine).Append("\r\n");
        foreach (var h in Headers.Where(h => !h.Key.Equals("Content-Length", StringComparison.OrdinalIgnoreCase)))
            text.Append(h.Key).Append(": ").Append(h.Value).Append("\r\n");
        text.Append("Content-Length: ").Append(Body.Length).Append("\r\n\r\n");
        var header = Encoding.UTF8.GetBytes(text.ToString());
        if (header.Length + Body.Length > MaxMessageBytes) throw new InvalidDataException("SIP message too large.");
        return [..header, ..Body];
    }
    public static SipMessage Parse(ReadOnlySpan<byte> bytes)
    {
        if (!TryGetLength(bytes, out var total, out var headerLength) || bytes.Length < total)
            throw new InvalidDataException("Incomplete SIP message.");
        var lines = Encoding.UTF8.GetString(bytes[..(headerLength - 4)]).Split("\r\n");
        if (lines.Length == 0 || !ValidStartLine(lines[0])) throw new InvalidDataException("Invalid SIP start line.");
        var message = new SipMessage { StartLine = lines[0], Body = bytes[headerLength..total].ToArray() };
        for (int i = 1; i < lines.Length; i++)
        {
            if (lines[i].StartsWith(' ') || lines[i].StartsWith('\t'))
            {
                if (message.Headers.Count == 0) throw new InvalidDataException("Orphan header continuation.");
                var last = message.Headers[^1]; message.Headers[^1] = new(last.Key, last.Value + " " + lines[i].Trim());
                continue;
            }
            int colon = lines[i].IndexOf(':');
            if (colon < 1) throw new InvalidDataException("Invalid SIP header.");
            string name = lines[i][..colon].Trim();
            message.Add(Compact.GetValueOrDefault(name, name), lines[i][(colon + 1)..].Trim());
        }
        return message;
    }
    public static bool TryGetLength(ReadOnlySpan<byte> bytes, out int total, out int headerLength)
    {
        total = headerLength = 0;
        int end = bytes.IndexOf("\r\n\r\n"u8);
        if (end < 0) { if (bytes.Length >= MaxMessageBytes) throw new InvalidDataException("SIP headers too large."); return false; }
        headerLength = end + 4;
        var lines = Encoding.UTF8.GetString(bytes[..end]).Split("\r\n");
        int length = 0; bool seen = false;
        foreach (string line in lines.Skip(1))
        {
            int colon = line.IndexOf(':'); if (colon < 0) continue;
            string name = line[..colon].Trim();
            if (!name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase) && !name.Equals("l", StringComparison.OrdinalIgnoreCase)) continue;
            if (seen || !int.TryParse(line[(colon + 1)..].Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out length) || length < 0)
                throw new InvalidDataException("Invalid or duplicate Content-Length.");
            seen = true;
        }
        total = checked(headerLength + length);
        if (total > MaxMessageBytes) throw new InvalidDataException("SIP message too large.");
        return true;
    }
    private static bool ValidStartLine(string line)
    {
        var parts = line.Split(' ', 3);
        return parts.Length == 3 && (parts[0] == "SIP/2.0"
            ? int.TryParse(parts[1], out int code) && code is >= 100 and <= 699
            : parts[2] == "SIP/2.0" && parts[0].All(c => c is >= 'A' and <= 'Z'));
    }
    public static string Parameter(string value, string name)
    {
        foreach (string part in value.Split(';').Skip(1))
        {
            var pair = part.Trim().Split('=', 2);
            if (pair[0].Equals(name, StringComparison.OrdinalIgnoreCase)) return pair.Length == 2 ? pair[1].Trim('"') : "";
        }
        return "";
    }
    public static string UriFromHeader(string value)
    {
        int start = value.IndexOf('<'), end = value.IndexOf('>');
        return start >= 0 && end > start ? value[(start + 1)..end] : value.Split(';')[0].Trim();
    }
    public static SipMessage Response(SipMessage request, int code, string reason, string? localTag = null)
    {
        var response = new SipMessage { StartLine = $"SIP/2.0 {code} {reason}" };
        foreach (string via in request.GetAll("Via")) response.Add("Via", via);
        foreach (string name in new[] { "From", "To", "Call-ID", "CSeq" }) response.Add(name, request.Get(name));
        if (localTag is not null && Parameter(response.Get("To"), "tag").Length == 0)
            response.Set("To", response.Get("To") + ";tag=" + localTag);
        foreach (var route in request.GetAll("Record-Route")) response.Add("Record-Route", route);
        return response;
    }
}
