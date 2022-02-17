using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Permissions;

namespace Framework.lib2
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STAT_WORKSTATION_0
    {
        public long StatisticsStartTime;
        public long BytesReceived;
        public long SmbsReceived;
        public long PagingReadBytesRequested;
        public long NonPagingReadBytesRequested;
        public long CacheReadBytesRequested;
        public long NetworkReadBytesRequested;
        public long BytesTransmitted;
        public long SmbsTransmitted;
        public long PagingWriteBytesRequested;
        public long NonPagingWriteBytesRequested;
        public long CacheWriteBytesRequested;
        public long NetworkWriteBytesRequested;
        public uint InitiallyFailedOperations;
        public uint FailedCompletionOperations;
        public uint ReadOperations;
        public uint RandomReadOperations;
        public uint ReadSmbs;
        public uint LargeReadSmbs;
        public uint SmallReadSmbs;
        public uint WriteOperations;
        public uint RandomWriteOperations;
        public uint WriteSmbs;
        public uint LargeWriteSmbs;
        public uint SmallWriteSmbs;
        public uint RawReadsDenied;
        public uint RawWritesDenied;
        public uint NetworkErrors;
        public uint Sessions;
        public uint FailedSessions;
        public uint Reconnects;
        public uint CoreConnects;
        public uint Lanman20Connects;
        public uint Lanman21Connects;
        public uint LanmanNtConnects;
        public uint ServerDisconnects;
        public uint HungSessions;
        public uint UseCount;
        public uint FailedUseCount;
        public uint CurrentCommands;
    }
    public class NativeMethods
    {
        [DllImport("Netapi32", CharSet = CharSet.Auto)]
        internal static extern int NetApiBufferFree(IntPtr Buffer);

        [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern uint NetStatisticsGet(
                    [In, MarshalAs(UnmanagedType.LPWStr)] string server,
                    [In, MarshalAs(UnmanagedType.LPWStr)] string service,
                    int level,
                    int options,
                    out IntPtr bufptr);

        [SecurityPermission(SecurityAction.Demand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        public static DateTime GetStartupTime(string server)
        {
            IntPtr buffer = IntPtr.Zero;
            uint ret = NetStatisticsGet(server, "LanmanWorkstation", 0, 0, out buffer);
            if (ret != 0)
            {
                Trace.WriteLine("GetStartupTime " + server + " returned " + ret);
                return DateTime.MinValue;
            }
            try
            {
                STAT_WORKSTATION_0 data = (STAT_WORKSTATION_0)Marshal.PtrToStructure(buffer, typeof(STAT_WORKSTATION_0));
                return DateTime.FromFileTime(data.StatisticsStartTime);
            }
            finally
            {
                NetApiBufferFree(buffer);
            }
        }
    }
}
