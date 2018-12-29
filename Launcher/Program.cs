namespace Launcher
{
    using EasyHook;

    internal class Program
    {
        private static string hiSuitePath;

        private static void LaunchHiSuite()
        {
            const string LibraryPath = "Interceptor.dll";

            RemoteHooking.CreateAndInject(hiSuitePath, string.Empty, 0, LibraryPath, LibraryPath, out var _, string.Empty);
        }

        private static void LoadConfiguration()
        {
            // TODO: Load from configuration file
            hiSuitePath = @"C:\Program Files (x86)\HiSuite\HiSuite.exe";
        }

        private static void Main(string[] args)
        {
            LoadConfiguration();
            LaunchHiSuite();
        }
    }
}