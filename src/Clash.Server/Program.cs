using Clash.Server;

// Entry point for `dotnet run --project src/Clash.Server`.
// The desktop shell (Clash.Desktop) builds the same host in-process.
await ClashHost.RunAsync(args).ConfigureAwait(false);
