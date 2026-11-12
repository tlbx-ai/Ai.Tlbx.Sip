using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Ai.Tlbx.Sip.Protocol;

internal sealed partial class DigestAuthentication
{
    private readonly Dictionary<string, uint> _counts = new(StringComparer.Ordinal);
    public string Authorize(string challenge, SipCredentials credentials, string method, string uri)
    {
        if (!challenge.StartsWith("Digest ", StringComparison.OrdinalIgnoreCase)) throw new NotSupportedException("Only SIP Digest authentication is supported.");
        var fields = FieldPattern().Matches(challenge[7..]).ToDictionary(m => m.Groups[1].Value,
            m => m.Groups[2].Success ? m.Groups[2].Value.Replace("\\\"", "\"") : m.Groups[3].Value.Trim(), StringComparer.OrdinalIgnoreCase);
        if (!fields.TryGetValue("realm", out var realm) || !fields.TryGetValue("nonce", out var nonce)) throw new InvalidDataException("Incomplete Digest challenge.");
        string algorithm = fields.GetValueOrDefault("algorithm", "MD5");
        bool session = algorithm.EndsWith("-sess", StringComparison.OrdinalIgnoreCase);
        string hashName = session ? algorithm[..^5] : algorithm;
        string Hash(string s)
        {
            var data = Encoding.UTF8.GetBytes(s);
            return Convert.ToHexStringLower(hashName.ToUpperInvariant() switch
            {
                "MD5" => MD5.HashData(data), "SHA-256" => SHA256.HashData(data),
                _ => throw new NotSupportedException($"Unsupported SIP Digest algorithm: {algorithm}")
            });
        }
        string cnonce = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
        string ha1 = Hash($"{credentials.Username}:{realm}:{credentials.Password}");
        if (session) ha1 = Hash($"{ha1}:{nonce}:{cnonce}");
        string ha2 = Hash($"{method}:{uri}");
        bool hasQop = fields.TryGetValue("qop", out string? qop);
        if (hasQop && !qop!.Split(',').Any(s => s.Trim().Equals("auth", StringComparison.OrdinalIgnoreCase)))
            throw new NotSupportedException("The server does not offer Digest qop=auth.");
        uint count = _counts.GetValueOrDefault(nonce) + 1; _counts[nonce] = count;
        string nc = count.ToString("x8");
        string result = hasQop ? Hash($"{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}") : Hash($"{ha1}:{nonce}:{ha2}");
        static string Quote(string s) => "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
        string auth = $"Digest username={Quote(credentials.Username)}, realm={Quote(realm)}, nonce={Quote(nonce)}, uri={Quote(uri)}, response={Quote(result)}, algorithm={algorithm}";
        if (hasQop) auth += $", qop=auth, nc={nc}, cnonce={Quote(cnonce)}";
        else if (session) auth += $", cnonce={Quote(cnonce)}";
        if (fields.TryGetValue("opaque", out var opaque)) auth += $", opaque={Quote(opaque)}";
        return auth;
    }
    [GeneratedRegex("([a-zA-Z][a-zA-Z0-9_-]*)\\s*=\\s*(?:\"((?:\\\\.|[^\"])*)\"|([^,]+))")]
    private static partial Regex FieldPattern();
}
