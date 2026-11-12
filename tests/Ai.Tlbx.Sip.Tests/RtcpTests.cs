using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using Ai.Tlbx.Sip;
using Ai.Tlbx.Sip.Media;
using Ai.Tlbx.Sip.Protocol;

internal static class RtcpTests
{
    public static readonly (string Name, Func<Task> Run)[] Cases =
    [
        ("SRTP/SRTCP match independent libSRTP vectors and reject replays", () =>
        {
            // Numeric interoperability fixtures: Cisco libSRTP test/srtp_driver.c,
            // srtp_validate(), https://github.com/cisco/libsrtp/blob/main/test/srtp_driver.c
            // No library implementation is copied or required at runtime.
            byte[] master = Convert.FromHexString("E1F97A0D3E018BE0D64FA32C06DE41390EC675AD498AFEEBB6960B3AABE6");
            byte[] rtp = Convert.FromHexString("800F1234DECAFBADCAFEBABEABABABABABABABABABABABABABABABAB");
            byte[] rtpReference = Convert.FromHexString("800F1234DECAFBADCAFEBABE4E55DC4CE79978D88CA4D215949D2402B78D6ACC99EA179B8DBB");
            using var rtpSender = new SrtpContext(master);
            Check.That(rtpSender.Protect(rtp, 12).SequenceEqual(rtpReference), "SRTP external encryption vector");
            byte[] plain = Convert.FromHexString("81C8000BCAFEBABEABABABABABABABABABABABABABABABAB");
            byte[] reference = Convert.FromHexString("81C8000BCAFEBABE7128035BE487B9BDBEF89041F977A5A880000001993E08CD54D6C1230798");
            using var sender = new SrtcpContext(master); using var receiver = new SrtcpContext(master);
            var zero = sender.Protect(plain);
            Check.That(BinaryPrimitives.ReadUInt32BigEndian(zero.AsSpan(plain.Length)) == 0x80000000, "SRTCP starts at index zero.");
            Check.That(sender.Protect(plain).SequenceEqual(reference), "SRTCP external encryption vector at index one");
            var corrupt = reference.ToArray(); corrupt[10] ^= 1;
            Check.That(receiver.Unprotect(corrupt) is null, "tampered encrypted control rejected");
            Check.That(receiver.Unprotect(reference)!.SequenceEqual(plain), "independent ciphertext decrypts");
            Check.That(receiver.Unprotect(reference) is null, "SRTCP replay rejected");
            Check.That(receiver.Unprotect(zero)!.SequenceEqual(plain), "valid out-of-order control accepted");
            Check.That(receiver.Unprotect([]) is null);
            return Task.CompletedTask;
        }),
        ("RTCP report fields, NTP era, signed loss and monotonic RTT", () =>
        {
            var clock = new RtcpTestClock();
            var local = new RtcpSession(10, clock); var peer = new RtcpSession(20, clock);
            local.RecordSent(1000, 160);
            foreach (ushort sequence in new ushort[] { 65534, 65535, 0, 2 })
            { local.RecordReceived(20, sequence, (uint)(sequence * 160)); clock.Advance(TimeSpan.FromMilliseconds(20)); }
            byte[] report = local.CreateCompound();
            Check.That(RtcpSession.Validate(report) && report[1] == 200 && (report[0] & 31) == 1);
            Check.That(BinaryPrimitives.ReadUInt32BigEndian(report.AsSpan(20)) == 1);
            Check.That(BinaryPrimitives.ReadUInt32BigEndian(report.AsSpan(24)) == 160, "SR counts payload octets only.");
            Check.That(report[32] == 51 && report[35] == 1, "one missing packet out of five");
            Check.That(BinaryPrimitives.ReadUInt32BigEndian(report.AsSpan(36)) == 65538, "extended sequence rollover");
            Check.That(RtcpSession.NtpTime(DateTimeOffset.UnixEpoch) == 0x83AA7E8000000000);
            peer.RecordReceived(10, 1, 1000); Check.That(peer.Receive(report));
            Check.That(peer.Metrics.RemoteLostPackets == 1 && peer.Metrics.RemoteLossFraction == 51 / 256.0);
            clock.Advance(TimeSpan.FromMilliseconds(100)); byte[] returned = peer.CreateCompound();
            clock.Advance(TimeSpan.FromMilliseconds(40)); Check.That(local.Receive(returned));
            Check.That(local.RoundTripMilliseconds is > 39.9 and < 40.1, "RTT excludes receiver processing delay.");
            var duplicateStats = new RtcpSession(30, clock); var duplicatePeer = new RtcpSession(40, clock);
            duplicateStats.RecordReceived(40, 1, 100); duplicateStats.RecordReceived(40, 1, 100);
            Check.That(duplicatePeer.Receive(duplicateStats.CreateCompound()));
            Check.That(duplicatePeer.Metrics.RemoteLostPackets == -1, "signed 24-bit cumulative loss");
            var malformed = returned.ToArray(); malformed[2] = 0x7f;
            Check.That(!local.Receive(malformed) && local.Metrics.RejectedPackets == 1);
            return Task.CompletedTask;
        }),
        ("SDP negotiates explicit RTCP endpoint and rejects invalid mux-only", () =>
        {
            string offer = SdpSession.Offer(IPAddress.Loopback, 4000, null, 1, rtcpPort: 5001);
            var session = SdpSession.Parse(System.Text.Encoding.UTF8.GetBytes(offer), SipMediaSecurity.Unencrypted);
            Check.That(session.RtcpPort == 5001 && session.RtcpAddress.Equals(IPAddress.Loopback));
            Check.Throws<NotSupportedException>(() => SdpSession.Parse(System.Text.Encoding.UTF8.GetBytes(offer + "a=rtcp-mux-only\r\n"), SipMediaSecurity.Unencrypted));
            Check.Throws<InvalidDataException>(() => SdpSession.Parse(System.Text.Encoding.UTF8.GetBytes(offer.Replace("a=rtcp:5001", "a=rtcp:0")), SipMediaSecurity.Unencrypted));
            return Task.CompletedTask;
        }),
        ("Media sockets reserve and release an even RTP/odd RTCP pair", async () =>
        {
            var media = new SipCallAudio(Check.Config(5060), TimeProvider.System, IPAddress.Loopback, _ => { });
            int rtpPort = media.Port, rtcpPort = media.ControlPort;
            Check.That((rtpPort & 1) == 0 && rtcpPort == rtpPort + 1);
            await Task.WhenAll(media.DisposeAsync().AsTask(), media.DisposeAsync().AsTask());
            using var rtp = new UdpClient(new IPEndPoint(IPAddress.Loopback, rtpPort));
            using var rtcp = new UdpClient(new IPEndPoint(IPAddress.Loopback, rtcpPort));
        }),
        ("RTP/RTCP and SRTP/SRTCP exchange reports and measured RTT", async () =>
        {
            foreach (bool secure in new[] { false, true })
            {
                var errors = new System.Collections.Concurrent.ConcurrentQueue<string>();
                var config = new SipClientConfig
                {
                    Id = "control", Registrar = "127.0.0.1", User = "test",
                    Credentials = new() { Username = "test", Password = "test" },
                    Transport = SipTransportProtocol.Tls, MediaSecurity = secure ? SipMediaSecurity.SdesRequired : SipMediaSecurity.Unencrypted,
                    RtcpReportInterval = TimeSpan.FromSeconds(1), AllowSymmetricRtp = true
                };
                await using var first = new SipCallAudio(config, TimeProvider.System, IPAddress.Loopback, errors.Enqueue);
                await using var second = new SipCallAudio(config, TimeProvider.System, IPAddress.Loopback, errors.Enqueue);
                first.Start(new(IPAddress.Loopback, second.Port, 8, "PCMA", 8000, secure, second.MasterKey?.ToArray(), ControlPort: second.ControlPort));
                second.Start(new(IPAddress.Loopback, first.Port, 8, "PCMA", 8000, secure, first.MasterKey?.ToArray(), ControlPort: first.ControlPort));
                Check.That(first.TryWrite(new short[2400], 24000));
                await Check.EventuallyAsync(() => first.Metrics.RoundTripMilliseconds.HasValue && second.Metrics.RoundTripMilliseconds.HasValue);
                Check.That(first.Metrics.Control is { TransmittedPackets: > 0, ReceivedPackets: > 0 });
                Check.That(second.Metrics.Control?.RemoteLostPackets >= 0 && errors.IsEmpty, string.Join(";", errors));
                long before = first.Metrics.ReceivedPackets;
                using var invalid = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
                await invalid.SendAsync(new byte[] { 0, 1, 2, 3 }, new IPEndPoint(IPAddress.Loopback, first.ControlPort));
                await Check.EventuallyAsync(() => first.Metrics.Control?.RejectedPackets > 0 && first.Metrics.ReceivedPackets > before);
                Check.That(errors.IsEmpty, "Malformed control must not stop RTP or retarget the peer.");
                await first.DisposeAsync();
                Check.That(!first.TryWrite(new short[480], 24000));
            }
        }),
        ("Unavailable RTCP port does not interrupt RTP transmission", async () =>
        {
            int closedPort;
            using (var reservation = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0)))
                closedPort = ((IPEndPoint)reservation.Client.LocalEndPoint!).Port;
            using var peerRtp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            var errors = new System.Collections.Concurrent.ConcurrentQueue<string>();
            var config = new SipClientConfig
            {
                Id = "no-control", Registrar = "127.0.0.1", User = "test", Credentials = new() { Username = "test", Password = "test" },
                RtcpReportInterval = TimeSpan.FromSeconds(1)
            };
            await using var media = new SipCallAudio(config, TimeProvider.System, IPAddress.Loopback, errors.Enqueue);
            media.Start(new(IPAddress.Loopback, ((IPEndPoint)peerRtp.Client.LocalEndPoint!).Port, 8, "PCMA", 8000, false, null, ControlPort: closedPort));
            await Check.EventuallyAsync(() => media.Metrics.TransmittedPackets >= 65);
            Check.That(errors.IsEmpty && media.Metrics.RoundTripMilliseconds is null, string.Join(";", errors));
        })
    ];
}

internal sealed class RtcpTestClock : TimeProvider
{
    private long _ticks;
    public override long TimestampFrequency => TimeSpan.TicksPerSecond;
    public override long GetTimestamp() => _ticks;
    public override DateTimeOffset GetUtcNow() => new DateTimeOffset(2026, 11, 12, 12, 0, 0, TimeSpan.Zero).AddTicks(_ticks);
    public void Advance(TimeSpan elapsed) => _ticks += elapsed.Ticks;
}
