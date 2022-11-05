using System;
using System.Collections.Generic;
using System.Linq;
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
            //Get USER ID;
            System.Security.Principal.WindowsPrincipal _userGroups = new System.Security.Principal.WindowsPrincipal(System.Security.Principal.WindowsIdentity.GetCurrent());
            
            //admin or not
            if (_userGroups.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator))
            {
                //if this were run by administrators, run it directly
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
    }
}