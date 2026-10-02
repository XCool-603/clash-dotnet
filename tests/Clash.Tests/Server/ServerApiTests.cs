using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using Clash.Core.Common;
using Clash.Server;
using Xunit;

namespace Clash.Tests.Server;

/// <summary>End-to-end coverage of the Clash-compatible control API.</summary>
public sealed class ServerApiTests
{
    // ── Misc ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Version_and_root_respond()
    {
        await using var fixture = await ServerFixture.StartAsync();

        var version = await fixture.Client.GetFromJsonAsync<JsonElement>("/version");
        Assert.Equal(JsonValueKind.String, version.GetProperty("version").ValueKind);
        Assert.False(string.IsNullOrWhiteSpace(version.GetProperty("version").GetString()));
        Assert.True(version.GetProperty("meta").GetBoolean());

        var root = await fixture.Client.GetFromJsonAsync<JsonElement>("/");
        Assert.Equal("clash", root.GetProperty("hello").GetString());
    }

    [Fact]
    public async Task Dns_and_fakeip_caches_flush()
    {
        await using var fixture = await ServerFixture.StartAsync();

        var fakeIp = await fixture.Client.GetAsync("/cache/fakeip/flush");
        Assert.Equal(HttpStatusCode.NoContent, fakeIp.StatusCode);

        var dns = await fixture.Client.GetAsync("/cache/dns/flush");
        Assert.Equal(HttpStatusCode.NoContent, dns.StatusCode);
    }

    // ── Auth ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Bearer_token_is_enforced()
    {
        await using var fixture = await ServerFixture.StartAsync(secret: "s3cr3t");

        var anonymous = await fixture.Client.GetAsync("/version");
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
        Assert.Empty(await anonymous.Content.ReadAsByteArrayAsync());

        using var authorizedRequest = new HttpRequestMessage(HttpMethod.Get, "/version");
        authorizedRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "s3cr3t");
        var authorized = await fixture.Client.SendAsync(authorizedRequest);
        Assert.Equal(HttpStatusCode.OK, authorized.StatusCode);

        var viaQuery = await fixture.Client.GetAsync("/version?token=s3cr3t");
        Assert.Equal(HttpStatusCode.OK, viaQuery.StatusCode);

        var wrong = await fixture.Client.GetAsync("/version?token=nope");
        Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);

        // The dashboard shell and its assets stay reachable so the UI can load and
        // then prompt for the secret.
        Assert.NotEqual(HttpStatusCode.Unauthorized, (await fixture.Client.GetAsync("/")).StatusCode);
        Assert.NotEqual(HttpStatusCode.Unauthorized, (await fixture.Client.GetAsync("/index.html")).StatusCode);
        Assert.NotEqual(HttpStatusCode.Unauthorized, (await fixture.Client.GetAsync("/assets/app.js")).StatusCode);

        using var preflight = new HttpRequestMessage(HttpMethod.Options, "/version");
        Assert.NotEqual(HttpStatusCode.Unauthorized, (await fixture.Client.SendAsync(preflight)).StatusCode);
    }

    [Fact]
    public async Task An_empty_secret_allows_everything()
    {
        await using var fixture = await ServerFixture.StartAsync();
        Assert.Equal(HttpStatusCode.OK, (await fixture.Client.GetAsync("/version")).StatusCode);
    }

    // ── Configs ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task Configs_reports_the_general_object_and_accepts_a_patch()
    {
        await using var fixture = await ServerFixture.StartAsync();

        var configs = await fixture.Client.GetFromJsonAsync<JsonElement>("/configs");

        string[] expected =
        [
            "port", "socks-port", "redir-port", "tproxy-port", "mixed-port",
            "allow-lan", "bind-address", "mode", "log-level", "ipv6", "interface-name",
            "routing-mark", "secret", "external-controller", "external-ui",
            "unified-delay", "tcp-concurrent", "find-process-mode", "global-client-fingerprint",
            "tun", "dns", "sniffer", "profile", "experimental", "hosts", "geodata",
            "profile-path", "home-dir", "inbound-ports",
        ];

        foreach (var key in expected)
        {
            Assert.True(configs.TryGetProperty(key, out _), $"GET /configs is missing [{key}]");
        }

        Assert.Equal("rule", configs.GetProperty("mode").GetString());
        Assert.Equal("127.0.0.1:9090", configs.GetProperty("external-controller").GetString());
        Assert.Equal(fixture.HomeDir, configs.GetProperty("home-dir").GetString());
        Assert.Equal(JsonValueKind.Object, configs.GetProperty("dns").ValueKind);
        Assert.Equal(JsonValueKind.Object, configs.GetProperty("tun").ValueKind);

        // The mihomo alias must answer identically.
        var general = await fixture.Client.GetFromJsonAsync<JsonElement>("/configs/general");
        Assert.Equal(configs.GetProperty("mode").GetString(), general.GetProperty("mode").GetString());

        var patch = await fixture.Client.PatchAsync("/configs", Json("""{"mode":"direct"}"""));
        Assert.Equal(HttpStatusCode.NoContent, patch.StatusCode);
        Assert.Equal(Mode.Direct, fixture.Runtime.Tunnel.Mode);

        var patched = await fixture.Client.GetFromJsonAsync<JsonElement>("/configs");
        Assert.Equal("direct", patched.GetProperty("mode").GetString());

        // A nested patch must merge rather than replace the whole dns object.
        var nested = await fixture.Client.PatchAsync("/configs", Json("""{"dns":{"enable":false}}"""));
        Assert.Equal(HttpStatusCode.NoContent, nested.StatusCode);
        var afterNested = await fixture.Client.GetFromJsonAsync<JsonElement>("/configs");
        Assert.False(afterNested.GetProperty("dns").GetProperty("enable").GetBoolean());
        Assert.Equal(JsonValueKind.Array, afterNested.GetProperty("dns").GetProperty("nameserver").ValueKind);
    }

    [Fact]
    public async Task Configs_put_accepts_an_inline_payload_and_rejects_broken_yaml()
    {
        await using var fixture = await ServerFixture.StartAsync();

        var ok = await fixture.Client.PutAsync("/configs?force=true", Json("""{"payload":"mode: global\nlog-level: debug\n"}"""));
        Assert.Equal(HttpStatusCode.NoContent, ok.StatusCode);
        Assert.Equal(Mode.Global, fixture.Runtime.Tunnel.Mode);

        var broken = await fixture.Client.PutAsync("/configs", Json("""{"payload":"dns: [unclosed"}"""));
        Assert.Equal(HttpStatusCode.BadRequest, broken.StatusCode);
        var body = await broken.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(body.TryGetProperty("message", out var message));
        Assert.False(string.IsNullOrWhiteSpace(message.GetString()));

        var missing = await fixture.Client.PutAsync("/configs", Json("""{"path":"/definitely/not/here.yaml"}"""));
        Assert.Equal(HttpStatusCode.BadRequest, missing.StatusCode);
    }

    // ── Proxies ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task Proxies_lists_builtins_and_switches_a_selector()
    {
        await using var fixture = await ServerFixture.StartAsync();

        var body = await fixture.Client.GetFromJsonAsync<JsonElement>("/proxies");
        var proxies = body.GetProperty("proxies");

        Assert.True(proxies.TryGetProperty("DIRECT", out _), "DIRECT is missing");
        Assert.True(proxies.TryGetProperty("REJECT", out _), "REJECT is missing");
        Assert.True(proxies.TryGetProperty("GLOBAL", out _), "GLOBAL is missing");
        Assert.True(proxies.TryGetProperty("PROXY", out var group));

        Assert.Equal("Selector", group.GetProperty("type").GetString());
        Assert.Equal("PROXY", group.GetProperty("name").GetString());
        Assert.True(group.GetProperty("udp").ValueKind is JsonValueKind.True or JsonValueKind.False);
        Assert.Equal(JsonValueKind.Array, group.GetProperty("all").ValueKind);
        Assert.Equal(JsonValueKind.Array, group.GetProperty("history").ValueKind);
        Assert.Equal(JsonValueKind.Object, group.GetProperty("extra").ValueKind);
        Assert.True(group.TryGetProperty("now", out _));
        Assert.True(group.TryGetProperty("testUrl", out _));
        Assert.Equal("*", group.GetProperty("expectedStatus").GetString());
        Assert.False(group.GetProperty("hidden").GetBoolean());
        Assert.True(group.TryGetProperty("icon", out _));

        var members = group.GetProperty("all").EnumerateArray().Select(e => e.GetString()).ToList();
        Assert.Contains("DIRECT", members);
        Assert.Contains("REJECT", members);

        // A concrete adapter has the base shape but no group fields.
        var direct = proxies.GetProperty("DIRECT");
        Assert.False(direct.TryGetProperty("all", out _));

        var single = await fixture.Client.GetFromJsonAsync<JsonElement>("/proxies/PROXY");
        Assert.Equal("PROXY", single.GetProperty("name").GetString());

        var select = await fixture.Client.PutAsync("/proxies/PROXY", Json("""{"name":"REJECT"}"""));
        Assert.Equal(HttpStatusCode.NoContent, select.StatusCode);

        var after = await fixture.Client.GetFromJsonAsync<JsonElement>("/proxies/PROXY");
        Assert.Equal("REJECT", after.GetProperty("now").GetString());

        var unknown = await fixture.Client.PutAsync("/proxies/PROXY", Json("""{"name":"does-not-exist"}"""));
        Assert.Equal(HttpStatusCode.BadRequest, unknown.StatusCode);
        var unknownBody = await unknown.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(unknownBody.TryGetProperty("message", out _));

        var notASelector = await fixture.Client.PutAsync("/proxies/DIRECT", Json("""{"name":"REJECT"}"""));
        Assert.Equal(HttpStatusCode.BadRequest, notASelector.StatusCode);

        var missingProxy = await fixture.Client.GetAsync("/proxies/nope");
        Assert.Equal(HttpStatusCode.NotFound, missingProxy.StatusCode);
    }

    [Fact]
    public async Task Group_listing_and_delay_endpoints_respond()
    {
        await using var fixture = await ServerFixture.StartAsync();

        var groups = await fixture.Client.GetFromJsonAsync<JsonElement>("/group");
        var list = groups.GetProperty("proxies").EnumerateArray().ToList();
        Assert.Contains(list, g => g.GetProperty("name").GetString() == "PROXY");
        Assert.Contains(list, g => g.GetProperty("name").GetString() == "GLOBAL");

        // Both delay endpoints answer with the documented shape; the probe itself
        // is expected to fail (there is nothing listening) and report 0.
        var delay = await fixture.Client.GetFromJsonAsync<JsonElement>("/proxies/DIRECT/delay?timeout=200");
        Assert.True(delay.TryGetProperty("delay", out var value));
        Assert.True(value.GetInt32() >= 0);

        var groupDelay = await fixture.Client.GetFromJsonAsync<JsonElement>("/group/PROXY/delay?timeout=200");
        Assert.True(groupDelay.TryGetProperty("DIRECT", out _));
        Assert.True(groupDelay.TryGetProperty("REJECT", out _));
    }

    // ── Rules ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Rules_are_reported_in_order_and_can_be_disabled()
    {
        await using var fixture = await ServerFixture.StartAsync();

        var body = await fixture.Client.GetFromJsonAsync<JsonElement>("/rules");
        var rules = body.GetProperty("rules").EnumerateArray().ToList();
        Assert.Equal(4, rules.Count);

        Assert.Equal("DOMAIN-SUFFIX", rules[0].GetProperty("type").GetString());
        Assert.Equal("google.com", rules[0].GetProperty("payload").GetString());
        Assert.Equal("PROXY", rules[0].GetProperty("proxy").GetString());
        Assert.Equal(-1, rules[0].GetProperty("size").GetInt32());

        Assert.Equal("DOMAIN", rules[1].GetProperty("type").GetString());
        Assert.Equal("example.com", rules[1].GetProperty("payload").GetString());
        Assert.Equal("DIRECT", rules[1].GetProperty("proxy").GetString());

        Assert.Equal("IP-CIDR", rules[2].GetProperty("type").GetString());
        Assert.Equal("10.0.0.0/8", rules[2].GetProperty("payload").GetString());

        Assert.Equal("MATCH", rules[3].GetProperty("type").GetString());
        Assert.Equal("PROXY", rules[3].GetProperty("proxy").GetString());

        var disable = await fixture.Client.PatchAsync(
            "/rules",
            Json("""{"type":"DOMAIN-SUFFIX","payload":"google.com","disabled":true}"""));
        Assert.Equal(HttpStatusCode.NoContent, disable.StatusCode);
        Assert.True(fixture.Runtime.Tunnel.Rules.IsDisabled("DOMAIN-SUFFIX", "google.com"));

        var enable = await fixture.Client.PatchAsync(
            "/rules",
            Json("""{"type":"DOMAIN-SUFFIX","payload":"google.com","disabled":false}"""));
        Assert.Equal(HttpStatusCode.NoContent, enable.StatusCode);
        Assert.False(fixture.Runtime.Tunnel.Rules.IsDisabled("DOMAIN-SUFFIX", "google.com"));
    }

    // ── Connections ──────────────────────────────────────────────────────────

    [Fact]
    public async Task Connections_reports_the_envelope_and_the_metadata_shape()
    {
        await using var fixture = await ServerFixture.StartAsync();

        var metadata = new Metadata
        {
            Network = Network.Tcp,
            SourceAddress = "127.0.0.1",
            SourcePort = 1234,
            DestinationAddress = "1.2.3.4",
            DestinationPort = 443,
            Host = "google.com",
            InboundType = "http",
            DnsMode = DnsMode.FakeIp,
            ProcessPath = "/usr/bin/curl",
            RemoteDestination = "1.2.3.4:443",
        };
        metadata.Rule = "DOMAIN-SUFFIX";
        metadata.RulePayload = "google.com";
        metadata.Chain.Add("PROXY");
        metadata.Chain.Add("node1");

        var tracked = fixture.Runtime.Tunnel.Connections.Track(metadata);
        tracked.AddUpload(11);
        tracked.AddDownload(22);

        var body = await fixture.Client.GetFromJsonAsync<JsonElement>("/connections");
        Assert.True(body.TryGetProperty("downloadTotal", out var downloadTotal));
        Assert.Equal(JsonValueKind.Number, downloadTotal.ValueKind);
        Assert.True(body.TryGetProperty("uploadTotal", out var uploadTotal));
        Assert.Equal(JsonValueKind.Number, uploadTotal.ValueKind);
        Assert.True(body.GetProperty("memory").GetInt64() > 0);

        var connection = Assert.Single(body.GetProperty("connections").EnumerateArray().ToList());
        Assert.Equal(tracked.Id, connection.GetProperty("id").GetString());
        Assert.Equal(11L, connection.GetProperty("upload").GetInt64());
        Assert.Equal(22L, connection.GetProperty("download").GetInt64());
        Assert.Equal(JsonValueKind.String, connection.GetProperty("start").ValueKind);
        Assert.Equal("PROXY", connection.GetProperty("chains")[0].GetString());
        Assert.Equal("node1", connection.GetProperty("chains")[1].GetString());
        Assert.Equal("DOMAIN-SUFFIX", connection.GetProperty("rule").GetString());
        Assert.Equal("google.com", connection.GetProperty("rulePayload").GetString());

        var meta = connection.GetProperty("metadata");
        Assert.Equal("tcp", meta.GetProperty("network").GetString());
        Assert.Equal("HTTP", meta.GetProperty("type").GetString());
        Assert.Equal("127.0.0.1", meta.GetProperty("sourceIP").GetString());
        Assert.Equal("1.2.3.4", meta.GetProperty("destinationIP").GetString());
        Assert.Equal("1234", meta.GetProperty("sourcePort").GetString());
        Assert.Equal("443", meta.GetProperty("destinationPort").GetString());
        Assert.Equal("google.com", meta.GetProperty("host").GetString());
        Assert.Equal("fake-ip", meta.GetProperty("dnsMode").GetString());
        Assert.Equal("/usr/bin/curl", meta.GetProperty("processPath").GetString());
        Assert.Equal("1.2.3.4:443", meta.GetProperty("remoteDestination").GetString());
        Assert.Equal(JsonValueKind.Number, meta.GetProperty("uid").ValueKind);
        Assert.Equal(JsonValueKind.Number, meta.GetProperty("dscp").ValueKind);

        foreach (var key in new[] { "specialProxy", "specialRules", "sniffHost", "inboundName", "inboundPort" })
        {
            Assert.True(meta.TryGetProperty(key, out _), $"metadata is missing [{key}]");
        }

        // Closing an unknown id is harmless, exactly like Clash.
        Assert.Equal(HttpStatusCode.NoContent, (await fixture.Client.DeleteAsync("/connections/nope")).StatusCode);

        Assert.Equal(HttpStatusCode.NoContent, (await fixture.Client.DeleteAsync($"/connections/{tracked.Id}")).StatusCode);

        var after = await fixture.Client.GetFromJsonAsync<JsonElement>("/connections");
        Assert.Empty(after.GetProperty("connections").EnumerateArray());

        Assert.Equal(HttpStatusCode.NoContent, (await fixture.Client.DeleteAsync("/connections")).StatusCode);
    }

    // ── Profiles ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task Profiles_round_trip_against_a_temporary_home()
    {
        await using var fixture = await ServerFixture.StartAsync();

        var initial = await fixture.Client.GetFromJsonAsync<JsonElement>("/profiles");
        Assert.Equal(JsonValueKind.Array, initial.GetProperty("profiles").ValueKind);
        Assert.Empty(initial.GetProperty("profiles").EnumerateArray());

        var created = await fixture.Client.PostAsync(
            "/profiles",
            Json("""{"name":"local-one","type":"local","content":"mode: rule\n"}"""));
        Assert.Equal(HttpStatusCode.OK, created.StatusCode);

        var profile = await created.Content.ReadFromJsonAsync<JsonElement>();
        var id = profile.GetProperty("id").GetString();
        Assert.False(string.IsNullOrWhiteSpace(id));
        Assert.Equal("local-one", profile.GetProperty("name").GetString());
        Assert.Equal("local", profile.GetProperty("type").GetString());
        Assert.True(profile.GetProperty("selected").GetBoolean());
        Assert.True(File.Exists(profile.GetProperty("path").GetString()));

        var listed = await fixture.Client.GetFromJsonAsync<JsonElement>("/profiles");
        Assert.Single(listed.GetProperty("profiles").EnumerateArray().ToList());

        var preview = await fixture.Client.GetAsync($"/profiles/{id}/preview");
        Assert.Equal(HttpStatusCode.OK, preview.StatusCode);
        Assert.StartsWith("text/plain", preview.Content.Headers.ContentType?.ToString());
        Assert.Equal("mode: rule\n", await preview.Content.ReadAsStringAsync());

        var write = await fixture.Client.PutAsync($"/profiles/{id}/content", Json("""{"content":"mode: direct\n"}"""));
        Assert.Equal(HttpStatusCode.NoContent, write.StatusCode);
        Assert.Equal("mode: direct\n", await fixture.Client.GetStringAsync($"/profiles/{id}/preview"));

        var rename = await fixture.Client.PutAsync($"/profiles/{id}", Json("""{"name":"renamed","description":"hello"}"""));
        Assert.Equal(HttpStatusCode.NoContent, rename.StatusCode);
        var renamed = await fixture.Client.GetFromJsonAsync<JsonElement>("/profiles");
        var entry = Assert.Single(renamed.GetProperty("profiles").EnumerateArray().ToList());
        Assert.Equal("renamed", entry.GetProperty("name").GetString());
        Assert.Equal("hello", entry.GetProperty("description").GetString());

        var select = await fixture.Client.PutAsync($"/profiles/{id}/select", Json("{}"));
        Assert.Equal(HttpStatusCode.NoContent, select.StatusCode);
        Assert.Equal(Mode.Direct, fixture.Runtime.Tunnel.Mode);

        var delete = await fixture.Client.DeleteAsync($"/profiles/{id}");
        Assert.Equal(HttpStatusCode.NoContent, delete.StatusCode);

        var after = await fixture.Client.GetFromJsonAsync<JsonElement>("/profiles");
        Assert.Empty(after.GetProperty("profiles").EnumerateArray());
    }

    [Fact]
    public async Task Profiles_import_url_requires_a_usable_url()
    {
        await using var fixture = await ServerFixture.StartAsync();

        var missing = await fixture.Client.PostAsync("/profiles/import-url", Json("{}"));
        Assert.Equal(HttpStatusCode.BadRequest, missing.StatusCode);

        var invalid = await fixture.Client.PostAsync("/profiles/import-url", Json("""{"url":"not-a-url"}"""));
        Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);
    }

    // ── Providers ────────────────────────────────────────────────────────────

    [Fact]
    public async Task Providers_endpoints_degrade_when_no_loader_is_registered()
    {
        await using var fixture = await ServerFixture.StartAsync();

        var proxies = await fixture.Client.GetFromJsonAsync<JsonElement>("/providers/proxies");
        Assert.Equal(JsonValueKind.Object, proxies.GetProperty("providers").ValueKind);

        var rules = await fixture.Client.GetFromJsonAsync<JsonElement>("/providers/rules");
        Assert.Equal(JsonValueKind.Object, rules.GetProperty("providers").ValueKind);

        var refresh = await fixture.Client.PutAsync("/providers/proxies/nope", Json("{}"));
        Assert.Equal(HttpStatusCode.NotImplemented, refresh.StatusCode);
        var body = await refresh.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Contains("loader", body.GetProperty("message").GetString()!, StringComparison.OrdinalIgnoreCase);

        var ruleRefresh = await fixture.Client.PutAsync("/providers/rules/nope", Json("{}"));
        Assert.Equal(HttpStatusCode.NotImplemented, ruleRefresh.StatusCode);
    }

    // ── WebSockets ───────────────────────────────────────────────────────────

    [Fact]
    public async Task Traffic_and_logs_stream_frames()
    {
        await using var fixture = await ServerFixture.StartAsync();

        using var traffic = await fixture.Server
            .CreateWebSocketClient()
            .ConnectAsync(new Uri("ws://localhost/traffic"), CancellationToken.None);

        var trafficFrame = await ReceiveAsync(traffic, TimeSpan.FromSeconds(15));
        Assert.True(trafficFrame.TryGetProperty("up", out _), "traffic frame is missing [up]");
        Assert.True(trafficFrame.TryGetProperty("down", out _), "traffic frame is missing [down]");

        await traffic.CloseAsync(WebSocketCloseStatus.NormalClosure, "done", CancellationToken.None);

        using var logs = await fixture.Server
            .CreateWebSocketClient()
            .ConnectAsync(new Uri("ws://localhost/logs?level=debug"), CancellationToken.None);

        fixture.Runtime.Tunnel.Log("info", "hello from the test");

        var logFrame = await ReceiveMatchingAsync(
            logs,
            frame => frame.TryGetProperty("payload", out var payload) && payload.GetString() == "hello from the test",
            TimeSpan.FromSeconds(15));

        Assert.Equal("info", logFrame.GetProperty("type").GetString());
        Assert.Equal("hello from the test", logFrame.GetProperty("payload").GetString());

        await logs.CloseAsync(WebSocketCloseStatus.NormalClosure, "done", CancellationToken.None);
    }

    [Fact]
    public async Task Memory_stream_delivers_a_frame()
    {
        await using var fixture = await ServerFixture.StartAsync();

        using var socket = await fixture.Server
            .CreateWebSocketClient()
            .ConnectAsync(new Uri("ws://localhost/memory"), CancellationToken.None);

        var frame = await ReceiveAsync(socket, TimeSpan.FromSeconds(15));
        Assert.True(frame.GetProperty("inuse").GetInt64() > 0);
        Assert.Equal(0L, frame.GetProperty("oslimit").GetInt64());

        await socket.CloseAsync(WebSocketCloseStatus.NormalClosure, "done", CancellationToken.None);
    }

    [Fact]
    public async Task Logs_respects_the_level_filter()
    {
        await using var fixture = await ServerFixture.StartAsync();

        using var socket = await fixture.Server
            .CreateWebSocketClient()
            .ConnectAsync(new Uri("ws://localhost/logs?level=warning"), CancellationToken.None);

        fixture.Runtime.Tunnel.Log("debug", "should be dropped");
        fixture.Runtime.Tunnel.Log("error", "should arrive");

        var frame = await ReceiveMatchingAsync(
            socket,
            candidate => candidate.TryGetProperty("payload", out var payload) && payload.GetString() == "should arrive",
            TimeSpan.FromSeconds(15));

        Assert.Equal("error", frame.GetProperty("type").GetString());
        await socket.CloseAsync(WebSocketCloseStatus.NormalClosure, "done", CancellationToken.None);
    }

    // ── Fallback ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task Unknown_api_paths_answer_json_instead_of_the_dashboard()
    {
        await using var fixture = await ServerFixture.StartAsync();

        using var request = new HttpRequestMessage(HttpMethod.Get, "/configs/not-a-real-endpoint");
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/html"));

        var response = await fixture.Client.SendAsync(request);
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static StringContent Json(string json) => new(json, Encoding.UTF8, "application/json");

    private static async Task<JsonElement> ReceiveAsync(WebSocket socket, TimeSpan timeout)
    {
        using var cts = new CancellationTokenSource(timeout);
        var buffer = new byte[16 * 1024];
        var result = await socket.ReceiveAsync(buffer.AsMemory(), cts.Token);

        Assert.Equal(WebSocketMessageType.Text, result.MessageType);

        using var document = JsonDocument.Parse(buffer.AsMemory(0, result.Count));
        return document.RootElement.Clone();
    }

    private static async Task<JsonElement> ReceiveMatchingAsync(
        WebSocket socket,
        Func<JsonElement, bool> predicate,
        TimeSpan timeout)
    {
        using var cts = new CancellationTokenSource(timeout);
        var buffer = new byte[16 * 1024];

        while (!cts.IsCancellationRequested)
        {
            var result = await socket.ReceiveAsync(buffer.AsMemory(), cts.Token);
            if (result.MessageType == WebSocketMessageType.Close) break;

            using var document = JsonDocument.Parse(buffer.AsMemory(0, result.Count));
            var frame = document.RootElement.Clone();
            if (predicate(frame)) return frame;
        }

        throw new InvalidOperationException("no matching websocket frame arrived before the timeout");
    }
}
