using System.Runtime.InteropServices;

namespace detect_handle.win_api
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct system_handle_table_entry_info_ex
    {
        public IntPtr object_ptr;
        public IntPtr unique_process_id;
        public IntPtr handle_value;
        public uint granted_access;
        public ushort creator_back_trace_index;
        public ushort object_type_index;
        public uint handle_attributes;
        public uint reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct threadentry32
    {
        public uint dw_size;
        public uint cnt_usage;
        public uint th32_thread_id;
        public uint th32_owner_process_id;
        public int tp_base_pri;
        public int tp_delta_pri;
        public uint dw_flags;
    }
}