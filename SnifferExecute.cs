using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace TarTarSniffer
{
    public class SnifferExecute
    {
        [STAThread]
        static void Main()
        {
            //admin or not
            if (isAdmin())
            {
                //if admin, run it directly
                Application.EnableVisualStyles();
                Application.Run(new MainWindow());
            }
            else
            {
                //try to run by admin
                System.Diagnostics.ProcessStartInfo _startInfo = new System.Diagnostics.ProcessStartInfo();
                _startInfo.UseShellExecute = true;
                _startInfo.WorkingDirectory = Environment.CurrentDirectory;
                _startInfo.FileName = Application.ExecutablePath;
                //make sure this is run by administrator;
                _startInfo.Verb = @"runas";
                try
                {
                    System.Diagnostics.Process.Start(_startInfo);
                }
                catch
                {
                    return;
                }
                Application.Exit();
            }
        }

        private static bool isAdmin()
        {
            WindowsIdentity used_identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(used_identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
    }
}