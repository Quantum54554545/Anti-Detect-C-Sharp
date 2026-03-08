using detect_handle.core;
using System;

namespace detect_handle
{
    public class con_log : logger
    {
        public void log_handle_detection(string message)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"[!] {message}");
            Console.ResetColor();
        }
    }

    internal class Program
    {
        static void Main(string[] args)
        {
            var Logger = new con_log();

            using (var detector = new handle_detector(myLogger))
            {
                detector.on_first_suspicious += (ev) =>
                    Logger.log_handle_detection($"PID={ev.owner_pid} Name={ev.owner_name}");

                detector.on_escalated_suspicious += (ev) =>
                    Logger.log_handle_detection($"PID={ev.owner_pid} Name={ev.owner_name}");

                detector.start_background_scanning();

                Console.ReadLine();
            }
        }
    }

}
