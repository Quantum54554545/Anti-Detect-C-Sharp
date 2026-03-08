using detect_handle.models;
using detect_handle.utils;
using detect_handle.win_api;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace detect_handle.core
{
    public sealed class handle_detector : IDisposable
    {
        private readonly logger _logger;
        private readonly IntPtr _my_process_handle;
        private readonly IntPtr _my_kernel_object;
        private CancellationTokenSource _cts;
        private Task _background_task;

        private readonly HashSet<string> _whitelist_names;
        private readonly HashSet<string> _whitelist_paths;
        private readonly HashSet<uint> _whitelist_pids;
        private readonly HashSet<string> _whitelist_cert_subjects;
        private readonly HashSet<string> _whitelist_cert_thumbprints;
        private readonly HashSet<string> _trusted_publishers;

        private readonly Dictionary<uint, List<DateTime>> _pid_events = new Dictionary<uint, List<DateTime>>();
        private readonly Random _random = new Random();

        private readonly timed_cache<uint, string> _proc_path_cache = new timed_cache<uint, string>(TimeSpan.FromSeconds(30));
        private readonly timed_cache<uint, string> _proc_name_cache = new timed_cache<uint, string>(TimeSpan.FromSeconds(30));
        private readonly timed_cache<uint, bool> _injection_cache = new timed_cache<uint, bool>(TimeSpan.FromSeconds(10));
        private readonly timed_cache<string, certificate_info> _cert_info_cache = new timed_cache<string, certificate_info>(TimeSpan.FromHours(6));

        private readonly system_handle_scanner _scanner = new system_handle_scanner();
        private readonly string _system_folder_path;
        private readonly List<(long start, long end)> _my_modules_range;

        public int score_threshold { get; set; } = 7;
        public TimeSpan event_window { get; set; } = TimeSpan.FromSeconds(10);
        public int repeat_threshold { get; set; } = 3;
        public TimeSpan scan_min_interval { get; set; } = TimeSpan.FromSeconds(1);
        public TimeSpan scan_max_interval { get; set; } = TimeSpan.FromSeconds(3);

        public event Action<handle_event> on_first_suspicious;
        public event Action<handle_event> on_escalated_suspicious;

        public handle_detector(logger logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));

            _whitelist_names = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "System", "csrss", "conhost", "explorer", "svchost" };
            _whitelist_paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _whitelist_pids = new HashSet<uint>();

            _whitelist_cert_subjects = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _whitelist_cert_thumbprints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _trusted_publishers = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "Microsoft Corporation",
                "Microsoft Windows"
            };

            _system_folder_path = Environment.GetFolderPath(Environment.SpecialFolder.System);

            _my_modules_range = new List<(long start, long end)>();
            foreach (ProcessModule m in Process.GetCurrentProcess().Modules)
            {
                long base_addr = m.BaseAddress.ToInt64();
                _my_modules_range.Add((base_addr, base_addr + m.ModuleMemorySize));
            }

            utils.utils.enable_se_debug_privilege();

            uint current_pid = (uint)Process.GetCurrentProcess().Id;
            _my_process_handle = calls.open_process(calls.process_query_limited_information, false, current_pid);
            if (_my_process_handle == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());

            _my_kernel_object = find_my_kernel_object();
            if (_my_kernel_object == IntPtr.Zero) throw new InvalidOperationException("Run as admin.");
        }

        public void add_to_whitelist_by_pid(uint pid) => _whitelist_pids.Add(pid);
        public void add_to_whitelist_by_path(string path) => _whitelist_paths.Add(path);
        public void add_to_whitelist_by_cert_subject(string subject) => _whitelist_cert_subjects.Add(subject);
        public void add_to_whitelist_by_cert_thumbprint(string thumbprint) => _whitelist_cert_thumbprints.Add(thumbprint);

        public void start_background_scanning()
        {
            _cts = new CancellationTokenSource();
            _background_task = Task.Run(async () =>
            {
                while (!_cts.IsCancellationRequested)
                {
                    try { scan_once(); }
                    catch (Exception ex) { Console.WriteLine($"{ex.Message}"); }
                    int delay_ms = _random.Next((int)scan_min_interval.TotalMilliseconds, (int)scan_max_interval.TotalMilliseconds + 1);
                    await Task.Delay(delay_ms, _cts.Token).ConfigureAwait(false);
                }
            }, _cts.Token);
        }

        public void stop_background_scanning()
        {
            if (_cts == null) return;
            _cts.Cancel();
            try { _background_task?.Wait(1000); } catch { }
            _cts.Dispose(); _cts = null; _background_task = null;
        }

        private void scan_once()
        {
            try
            {
                _scanner.scan((ref system_handle_table_entry_info_ex entry) =>
                {
                    if (entry.object_ptr == _my_kernel_object && (uint)entry.unique_process_id.ToInt64() != Process.GetCurrentProcess().Id)
                    {
                        var ev = build_and_score_event(entry);
                        if (!is_whitelisted(ev) && ev.score >= score_threshold)
                        {
                            process_suspicious_event(ev);
                        }
                    }
                });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"scan_once: {ex.Message}");
            }
        }

        private handle_event build_and_score_event(system_handle_table_entry_info_ex entry)
        {
            var ev = new handle_event
            {
                owner_pid = (uint)entry.unique_process_id.ToInt64(),
                handle_value = entry.handle_value,
                granted_access = entry.granted_access
            };

            ev.owner_name = _proc_name_cache.get_or_add(ev.owner_pid, pid =>
            {
                try { return Process.GetProcessById((int)pid).ProcessName; } catch { return "<unknown>"; }
            });

            ev.owner_path = _proc_path_cache.get_or_add(ev.owner_pid, try_get_process_path_internal);
            ev.grants = grants_to_string(ev.granted_access);
            ev.signed_trusted = utils.utils.is_signed_by_trusted_publisher(ev.owner_path);

            if (ev.score >= 5)
            {
                try_duplicate_handle_confirm(ev);
            }

            ev.score = compute_score(ev);

            if (_injection_cache.get_or_add(ev.owner_pid, check_threads_for_injection))
            {
                ev.score += 6;
            }

            return ev;
        }

        private bool is_whitelisted(handle_event ev)
        {
            if (ev.owner_pid == 4) return true; 

            try
            {
                if (_whitelist_pids.Contains(ev.owner_pid)) return true;
                if (!string.IsNullOrEmpty(ev.owner_path) && _whitelist_paths.Contains(ev.owner_path)) return true;

                if (!string.IsNullOrEmpty(ev.owner_path))
                {
                    var cert_info = _cert_info_cache.get_or_add(ev.owner_path, utils.utils.get_certificate_info);
                    if (cert_info != null)
                    {
                        if (!string.IsNullOrEmpty(cert_info.thumbprint) && _whitelist_cert_thumbprints.Contains(cert_info.thumbprint))
                            return true;

                        if (!string.IsNullOrEmpty(cert_info.subject) && _whitelist_cert_subjects.Any(s => cert_info.subject.IndexOf(s, StringComparison.OrdinalIgnoreCase) >= 0))
                            return true;
                    }
                }

                if (is_legitimate_system_process(ev))
                {
                    return true;
                }
            }
            catch (Exception ex)
            {
                _logger.log_handle_detection(ex.Message);
            }
            return false;
        }

        private bool is_legitimate_system_process(handle_event ev)
        {
            if (string.IsNullOrEmpty(ev.owner_name) || !_whitelist_names.Contains(ev.owner_name))
            {
                return false;
            }

            if (string.IsNullOrEmpty(ev.owner_path) || !ev.owner_path.StartsWith(_system_folder_path, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            return true;
        }

        private int compute_score(handle_event ev)
        {
            int score = 0;
            if ((ev.granted_access & calls.process_vm_read) != 0) score += 3;
            if ((ev.granted_access & calls.process_vm_write) != 0) score += 5;
            if ((ev.granted_access & calls.process_vm_operation) != 0) score += 2;
            if ((ev.granted_access & calls.process_dup_handle) != 0) score += 6;
            if ((ev.granted_access & calls.process_create_thread) != 0) score += 6;
            if (!ev.signed_trusted) score += 3;
            if (ev.duplicate_succeeded) score += 8;
            return score;
        }

        private void process_suspicious_event(handle_event ev)
        {
            lock (_pid_events)
            {
                if (!_pid_events.TryGetValue(ev.owner_pid, out var list))
                {
                    list = new List<DateTime>();
                    _pid_events[ev.owner_pid] = list;
                }

                DateTime now = DateTime.UtcNow;
                list.RemoveAll(t => (now - t) > event_window);
                list.Add(now);

                if (list.Count == 1)
                {
                    on_first_suspicious?.Invoke(ev);
                }
                if (list.Count == repeat_threshold)
                {
                    on_escalated_suspicious?.Invoke(ev);
                }
            }
        }

        private void try_duplicate_handle_confirm(handle_event ev)
        {
            IntPtr proc_handle = IntPtr.Zero;
            IntPtr duplicated_handle = IntPtr.Zero;
            try
            {
                proc_handle = calls.open_process(calls.process_dup_handle, false, ev.owner_pid);
                if (proc_handle == IntPtr.Zero)
                {
                    ev.duplicate_succeeded = false;
                    return;
                }
                ev.duplicate_succeeded = calls.duplicate_handle(proc_handle, ev.handle_value, Process.GetCurrentProcess().Handle, out duplicated_handle, 0, false, calls.duplicate_same_access);
            }
            catch { ev.duplicate_succeeded = false; }
            finally
            {
                if (duplicated_handle != IntPtr.Zero) calls.close_handle(duplicated_handle);
                if (proc_handle != IntPtr.Zero) calls.close_handle(proc_handle);
            }
        }

        private IntPtr find_my_kernel_object()
        {
            IntPtr found_object = IntPtr.Zero;
            uint my_pid = (uint)Process.GetCurrentProcess().Id;
            ulong my_handle_val = (ulong)_my_process_handle.ToInt64();

            _scanner.scan((ref system_handle_table_entry_info_ex entry) =>
            {
                if ((uint)entry.unique_process_id.ToInt64() == my_pid &&
                    (ulong)entry.handle_value.ToInt64() == my_handle_val)
                {
                    found_object = entry.object_ptr;
                }
            });

            return found_object;
        }

        private bool check_threads_for_injection(uint owner_pid)
        {
            IntPtr snap_handle = calls.create_toolhelp32_snapshot(calls.th32cs_snapthread, 0);
            if (snap_handle == IntPtr.Zero || snap_handle.ToInt64() == -1) return false;

            try
            {
                threadentry32 te = new threadentry32 { dw_size = (uint)Marshal.SizeOf<threadentry32>() };
                if (!calls.thread32_first(snap_handle, ref te)) return false;
                do
                {
                    if (te.th32_owner_process_id != owner_pid) continue;

                    IntPtr h_thread = calls.open_thread(calls.thread_query_information, false, te.th32_thread_id);
                    if (h_thread == IntPtr.Zero) continue;

                    IntPtr addr_buf = Marshal.AllocHGlobal(IntPtr.Size);
                    try
                    {
                        if (calls.nt_query_information_thread(h_thread, calls.thread_query_set_win32_start_address, addr_buf, IntPtr.Size, IntPtr.Zero) == 0)
                        {
                            if (is_address_in_our_image_range(Marshal.ReadIntPtr(addr_buf))) return true;
                        }
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(addr_buf);
                        calls.close_handle(h_thread);
                    }
                } while (calls.thread32_next(snap_handle, ref te));
            }
            finally { calls.close_handle(snap_handle); }

            return false;
        }

        private bool is_address_in_our_image_range(IntPtr addr)
        {
            if (addr == IntPtr.Zero) return false;
            long target_address = addr.ToInt64();

            foreach (var (start, end) in _my_modules_range)
            {
                if (target_address >= start && target_address < end) return true;
            }
            return false;
        }

        private static string grants_to_string(uint g)
        {
            var parts = new List<string>();
            if ((g & calls.process_create_thread) != 0) parts.Add("CREATE_THREAD");
            if ((g & calls.process_vm_operation) != 0) parts.Add("VM_OPERATION");
            if ((g & calls.process_vm_read) != 0) parts.Add("VM_READ");
            if ((g & calls.process_vm_write) != 0) parts.Add("VM_WRITE");
            if ((g & calls.process_dup_handle) != 0) parts.Add("DUP_HANDLE");

            return parts.Count == 0 ? $"0x{g:X}" : string.Join("|", parts);
        }

        private string try_get_process_path_internal(uint pid)
        {
            IntPtr h_process = calls.open_process(calls.process_query_limited_information, false, pid);
            if (h_process == IntPtr.Zero) return "<no-access>";
            try
            {
                var sb = new StringBuilder(1024);
                int capacity = sb.Capacity;
                return calls.query_full_process_image_name(h_process, 0, sb, ref capacity) ? sb.ToString() : "<unknown>";
            }
            finally { calls.close_handle(h_process); }
        }

        public void Dispose()
        {
            stop_background_scanning();
            if (_my_process_handle != IntPtr.Zero)
            {
                calls.close_handle(_my_process_handle);
            }
            _scanner.Dispose();
        }
    }
}
