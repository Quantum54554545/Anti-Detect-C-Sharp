using System.Runtime.InteropServices;
using System.Text;

namespace detect_handle.win_api
{
    internal static class calls
    {
        public const uint process_query_limited_information = 0x1000;
        public const uint process_vm_read = 0x0010;
        public const uint process_vm_write = 0x0020;
        public const uint process_vm_operation = 0x0008;
        public const uint process_dup_handle = 0x0040;
        public const uint process_create_thread = 0x0002;

        public const uint duplicate_same_access = 0x00000002;
        public const int system_extended_handle_information = 64; 
        public const int status_info_length_mismatch = unchecked((int)0xC0000004);

        public const uint th32cs_snapthread = 0x00000004;
        public const uint thread_query_information = 0x0040;
        public const int thread_query_set_win32_start_address = 9; [DllImport("kernel32.dll", EntryPoint = "OpenProcess", SetLastError = true)]
        public static extern IntPtr open_process(uint dw_desired_access, bool b_inherit_handle, uint dw_process_id); [DllImport("kernel32.dll", EntryPoint = "DuplicateHandle", SetLastError = true)]
        public static extern bool duplicate_handle(IntPtr h_source_process_handle, IntPtr h_source_handle, IntPtr h_target_process_handle, out IntPtr lp_target_handle, uint dw_desired_access, bool b_inherit_handle, uint dw_options); [DllImport("kernel32.dll", EntryPoint = "CloseHandle", SetLastError = true)]
        public static extern bool close_handle(IntPtr h_object);

        [DllImport("ntdll.dll", EntryPoint = "NtQuerySystemInformation")]
        public static extern int nt_query_system_information(int system_information_class, IntPtr system_information, int system_information_length, out int return_length); [DllImport("kernel32.dll", EntryPoint = "QueryFullProcessImageNameW", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool query_full_process_image_name(IntPtr h_process, uint dw_flags, StringBuilder lp_exe_name, ref int lpdw_size); [DllImport("kernel32.dll", EntryPoint = "CreateToolhelp32Snapshot", SetLastError = true)]
        public static extern IntPtr create_toolhelp32_snapshot(uint dw_flags, uint th32_process_id); [DllImport("kernel32.dll", EntryPoint = "Thread32First", SetLastError = true)]
        public static extern bool thread32_first(IntPtr h_snapshot, ref threadentry32 lpte); [DllImport("kernel32.dll", EntryPoint = "Thread32Next", SetLastError = true)]
        public static extern bool thread32_next(IntPtr h_snapshot, ref threadentry32 lpte); [DllImport("kernel32.dll", EntryPoint = "OpenThread", SetLastError = true)]
        public static extern IntPtr open_thread(uint dw_desired_access, bool b_inherit_handle, uint dw_thread_id); [DllImport("ntdll.dll", EntryPoint = "NtQueryInformationThread")]
        public static extern int nt_query_information_thread(IntPtr thread_handle, int thread_information_class, IntPtr thread_information, int thread_information_length, IntPtr return_length);
    }
}