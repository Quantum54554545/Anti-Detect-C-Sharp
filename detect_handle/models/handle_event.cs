namespace detect_handle.models
{
    public class handle_event
    {
        public uint owner_pid { get; set; }
        public string owner_name { get; set; }
        public string owner_path { get; set; }
        public IntPtr handle_value { get; set; }
        public uint granted_access { get; set; }
        public string grants { get; set; }
        public int score { get; set; }
        public bool duplicate_succeeded { get; set; }
        public bool signed_trusted { get; set; }
    }
}