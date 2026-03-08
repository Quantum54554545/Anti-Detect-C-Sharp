using detect_handle.win_api;
using System.Runtime.InteropServices;

namespace detect_handle.core
{
    internal delegate void handle_scanner_callback(ref system_handle_table_entry_info_ex entry);

    public class system_handle_scanner : IDisposable
    {
        private IntPtr _buffer = IntPtr.Zero;
        private int _buffer_size = 0x20000;

        internal void scan(handle_scanner_callback callback)
        {
            int status;
            int needed_size;

            if (_buffer == IntPtr.Zero)
                _buffer = Marshal.AllocHGlobal(_buffer_size);

            while ((status = calls.nt_query_system_information(
                       calls.system_extended_handle_information,
                       _buffer, _buffer_size, out needed_size)) == calls.status_info_length_mismatch)
            {
                _buffer_size = needed_size + 0x10000; 
                _buffer = Marshal.ReAllocHGlobal(_buffer, (IntPtr)_buffer_size);
            }

            if (status == 0)
            {
                long count = Marshal.ReadInt64(_buffer);
                int entry_size = Marshal.SizeOf<system_handle_table_entry_info_ex>();
                IntPtr current_ptr = IntPtr.Add(_buffer, IntPtr.Size * 2);

                for (long i = 0; i < count; i++)
                {
                    var entry = Marshal.PtrToStructure<system_handle_table_entry_info_ex>(current_ptr);
                    callback(ref entry);
                    current_ptr = IntPtr.Add(current_ptr, entry_size);
                }
            }
        }

        public void Dispose()
        {
            if (_buffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(_buffer);
                _buffer = IntPtr.Zero;
            }
        }
    }
}
