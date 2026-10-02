using Clash.Core.Configuration;
using Xunit;

namespace Clash.Tests.Deployment;

/// <summary>
/// Checks the container deployment files that no compiler reads.
/// <para>
/// The container's starter configuration is the one artefact in this repository
/// that only ever runs inside an image: nothing in the test suite or the build
/// touches it, so a typo in it would surface as a container that fails on first
/// run. Parsing it with the core's own parser is the cheapest way to make that
/// impossible, and asserting the two container-specific values keeps a later
/// edit from quietly making the API unreachable from the host.
/// </para>
/// </summary>
public sealed class DockerDeploymentTests
{
    /// <summary>
    /// Walks up to the repository root. The deployment files live outside any
    /// project, so they are addressed by path rather than copied into the build
    /// output, where they would be one more copy to keep in step.
    /// </summary>
    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "Clash.slnx")))
        {
            directory = directory.Parent;
        }

        Assert.NotNull(directory);
        return directory!.FullName;
    }

    private static string ReadRepositoryFile(params string[] parts)
        => File.ReadAllText(Path.Combine([RepositoryRoot(), .. parts]));

    [Fact]
    public void TheContainerStarterConfigIsOneTheCoreAccepts()
    {
        var text = ReadRepositoryFile("docker", "config.yaml");

        var config = ConfigParser.Parse(YamlReader.Parse(text));

        Assert.Equal(7890, config.MixedPort);
    }

    [Fact]
    public void TheContainerStarterConfigIsReachableFromOutsideTheContainer()
    {
        var config = ConfigParser.Parse(YamlReader.Parse(ReadRepositoryFile("docker", "config.yaml")));

        // A loopback listener inside a container cannot be reached from the host,
        // and allow-lan gates the proxy port the same way. Both would look correct
        // in review and be broken in practice, which is why they are asserted.
        Assert.False(
            config.ExternalController.StartsWith("127.", StringComparison.Ordinal)
                || config.ExternalController.StartsWith("localhost", StringComparison.OrdinalIgnoreCase),
            $"the container's external-controller [{config.ExternalController}] binds to loopback, so the dashboard is unreachable from the host");

        Assert.True(config.AllowLan, "the container's proxy port is unreachable unless allow-lan is true");
        Assert.Equal("*", config.BindAddress);
    }

    [Fact]
    public void TheContainerStarterConfigLeavesTheNodesToTheUser()
    {
        var config = ConfigParser.Parse(YamlReader.Parse(ReadRepositoryFile("docker", "config.yaml")));

        // Shipping a starter config with nodes in it would mean shipping someone's
        // credentials; an empty list is also what makes the dashboard the obvious
        // next step.
        Assert.Empty(config.Proxies);
    }

    [Theory]
    [InlineData("docker-compose.yml")]
    [InlineData(".github/workflows/docker.yml")]
    public void TheDeploymentYamlParses(string relativePath)
    {
        // YamlDotNet is the same reader the core uses for its own configuration,
        // so this catches a malformed deployment file before Docker or GitHub does.
        var text = ReadRepositoryFile(relativePath.Split('/'));

        var parsed = YamlReader.Parse(text);

        Assert.NotNull(parsed);
    }

    [Fact]
    public void TheComposeFileMountsTheDataVolumeAndPublishesTheProxyPort()
    {
        var text = ReadRepositoryFile("docker-compose.yml");

        // The two things whose absence would silently lose data or make the
        // deployment useless.
        Assert.Contains("/data", text, StringComparison.Ordinal);
        Assert.Contains("7890:7890/tcp", text, StringComparison.Ordinal);
        Assert.Contains("9090:9090/tcp", text, StringComparison.Ordinal);
    }

    [Fact]
    public void TheEntrypointKeepsAnExistingConfiguration()
    {
        var text = ReadRepositoryFile("docker", "entrypoint.sh");

        // The guard is what makes an upgrade non-destructive: without it, every
        // restart would replace the user's configuration with the starter one.
        Assert.Contains("[ ! -f \"$home/config.yaml\" ]", text, StringComparison.Ordinal);
    }
}
