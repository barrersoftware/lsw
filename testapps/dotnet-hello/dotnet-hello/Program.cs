// LSW .NET Framework-Dependent Test App
Console.WriteLine("LSW .NET Test: Hello from .NET 8 framework-dependent app!");
Console.WriteLine($"Runtime: {System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription}");
Console.WriteLine($"OS: {System.Runtime.InteropServices.RuntimeInformation.OSDescription}");
Console.WriteLine($"ProcessorCount: {System.Environment.ProcessorCount}");
Console.WriteLine($"CurrentDir: {System.Environment.CurrentDirectory}");
Console.WriteLine("LSW .NET Test: SUCCESS");
