using detect_handle.models;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;

namespace detect_handle.utils
{
    internal static class utils
    {
        public static void enable_se_debug_privilege()
        {
            Process.EnterDebugMode();
        }

        public static bool is_signed_by_trusted_publisher(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            try
            {
                var cert = X509Certificate.CreateFromSignedFile(path);
                return cert != null;
            }
            catch { return false; }
        }

        public static certificate_info get_certificate_info(string path)
        {
            if (string.IsNullOrEmpty(path)) return null;
            try
            {
                var cert = new X509Certificate2(path);
                return new certificate_info
                {
                    thumbprint = cert.Thumbprint,
                    subject = cert.Subject
                };
            }
            catch { return null; }
        }
    }
}
