using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace MynaAuth.Jpki;

internal interface IPkcs11Module : IDisposable
{
    CardDevice? DetectedDevice => null;
    uint[] GetSlots();
    void Open(uint slot);
    uint Login(byte[] pin);
    byte[] Certificate();
    byte[] Sign(byte[] digestInfo);
}

// Windows PKCS#11 uses 32-bit CK_ULONG even in a 64-bit process, and pack(1).
// Function indices follow the standard CK_FUNCTION_LIST v2.x order.
internal sealed class Pkcs11Module : IPkcs11Module
{
    public CardDevice? DetectedDevice => CardDevice.PhysicalCard;
    private IntPtr _library;
    private IntPtr _functions;
    private uint _session;
    private bool _initialized;
    private bool _open;
    private bool _loggedIn;

    public Pkcs11Module()
    {
        if (!Environment.Is64BitProcess)
            throw new DllNotFoundException();
        string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "JPKI", "JPKIPKCS11Auth64.dll");
        _library = LoadLibraryEx(path, IntPtr.Zero, 0x100 | 0x1000);
        if (_library == IntPtr.Zero)
            throw new DllNotFoundException();
        try
        {
            GetFunctionList getList = Marshal.GetDelegateForFunctionPointer<GetFunctionList>(
                NativeLibrary.GetExport(_library, "C_GetFunctionList"));
            Ensure(getList(out _functions), JpkiOperation.Initialize);
            if (_functions == IntPtr.Zero || Marshal.ReadByte(_functions) != 2)
                throw new Pkcs11Exception(0x6);
            Ensure(Function<PointerCall>(0)(IntPtr.Zero), JpkiOperation.Initialize);
            _initialized = true;
        }
        catch
        {
            Dispose();
            throw;
        }
    }

    public uint[] GetSlots()
    {
        uint count = 0;
        SlotList getSlots = Function<SlotList>(4);
        Ensure(getSlots(1, null, ref count), JpkiOperation.GetSlots);
        if (count > 64)
            throw new Pkcs11Exception(0x6);
        if (count == 0)
            return [];
        uint[] slots = new uint[count];
        Ensure(getSlots(1, slots, ref count), JpkiOperation.GetSlots);
        return slots.Take(checked((int)count)).ToArray();
    }

    public void Open(uint slot)
    {
        // J-LIS documents these two calls before C_OpenSession. They also
        // let the module establish card metadata before a PIN is submitted.
        ReadInfo(slot, 5, 104, JpkiOperation.GetSlotInfo);
        ReadInfo(slot, 6, 160, JpkiOperation.GetTokenInfo);
        Ensure(Function<OpenSession>(12)(slot, 4, IntPtr.Zero, IntPtr.Zero, out _session), JpkiOperation.OpenSession);
        _open = true;
    }

    private void ReadInfo(uint slot, int function, int length, JpkiOperation operation)
    {
        byte[] info = new byte[length];
        try { Ensure(Function<InfoCall>(function)(slot, info), operation); }
        finally { CryptographicOperations.ZeroMemory(info); }
    }

    public uint Login(byte[] pin)
    {
        GCHandle pinned = GCHandle.Alloc(pin, GCHandleType.Pinned);
        try
        {
            uint result = Function<LoginCall>(18)(_session, 1, pinned.AddrOfPinnedObject(), (uint)pin.Length);
            _loggedIn = result == 0;
            return result;
        }
        finally { pinned.Free(); }
    }

    public byte[] Certificate()
    {
        uint certificate = Find(1, "USERCERT");
        return Attribute(certificate, 0x11); // CKA_VALUE
    }

    public byte[] Sign(byte[] digestInfo)
    {
        uint privateKey = Find(3, null);
        Mechanism mechanism = new() { Type = 1 }; // CKM_RSA_PKCS
        Ensure(Function<SignInit>(42)(_session, ref mechanism, privateKey), JpkiOperation.Sign);
        SignCall sign = Function<SignCall>(43);
        uint length = 0;
        Ensure(sign(_session, digestInfo, (uint)digestInfo.Length, null, ref length), JpkiOperation.Sign);
        if (length is < 128 or > 512)
            throw new Pkcs11Exception(0x6);
        byte[] signature = new byte[length];
        try
        {
            Ensure(sign(_session, digestInfo, (uint)digestInfo.Length, signature, ref length), JpkiOperation.Sign);
            if (length != signature.Length)
                throw new Pkcs11Exception(0x6);
            return signature;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(signature);
            throw;
        }
    }

    private uint Find(uint objectClass, string? label)
    {
        byte[] classBytes = BitConverter.GetBytes(objectClass);
        byte[] labelBytes = label is null ? [] : Encoding.ASCII.GetBytes(label);
        GCHandle classPin = GCHandle.Alloc(classBytes, GCHandleType.Pinned);
        GCHandle labelPin = GCHandle.Alloc(labelBytes, GCHandleType.Pinned);
        try
        {
            NativeAttribute[] template = label is null
                ? [new() { Type = 0, Value = classPin.AddrOfPinnedObject(), Length = 4 }]
                : [new() { Type = 0, Value = classPin.AddrOfPinnedObject(), Length = 4 },
                   new() { Type = 3, Value = labelPin.AddrOfPinnedObject(), Length = (uint)labelBytes.Length }];
            Ensure(Function<FindInit>(26)(_session, template, (uint)template.Length), JpkiOperation.FindObjects);
            try
            {
                uint[] objects = new uint[2];
                Ensure(Function<FindObjects>(27)(_session, objects, 2, out uint count), JpkiOperation.FindObjects);
                if (count != 1)
                    throw new Pkcs11Exception(0x6);
                return objects[0];
            }
            finally { _ = Function<SessionCall>(28)(_session); }
        }
        finally
        {
            labelPin.Free();
            classPin.Free();
        }
    }

    private byte[] Attribute(uint handle, uint type)
    {
        NativeAttribute[] attributes = [new() { Type = type }];
        GetAttribute get = Function<GetAttribute>(24);
        Ensure(get(_session, handle, attributes, 1), JpkiOperation.ReadCertificate);
        uint length = attributes[0].Length;
        if (length is 0 or > 16384)
            throw new Pkcs11Exception(0x6);
        byte[] value = new byte[length];
        GCHandle pinned = GCHandle.Alloc(value, GCHandleType.Pinned);
        try
        {
            attributes[0].Value = pinned.AddrOfPinnedObject();
            Ensure(get(_session, handle, attributes, 1), JpkiOperation.ReadCertificate);
            if (attributes[0].Length != length)
                throw new Pkcs11Exception(0x6);
            return value;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(value);
            throw;
        }
        finally { pinned.Free(); }
    }

    private T Function<T>(int index) where T : Delegate =>
        Marshal.GetDelegateForFunctionPointer<T>(Marshal.ReadIntPtr(_functions, 2 + index * IntPtr.Size));

    private static void Ensure(uint status, JpkiOperation operation)
    {
        if (status != 0)
            throw new Pkcs11Exception(status, operation);
    }

    public void Dispose()
    {
        if (_loggedIn) { _ = Function<SessionCall>(19)(_session); _loggedIn = false; }
        if (_open) { _ = Function<SessionCall>(13)(_session); _open = false; }
        if (_initialized) { _ = Function<PointerCall>(1)(IntPtr.Zero); _initialized = false; }
        if (_library != IntPtr.Zero) { NativeLibrary.Free(_library); _library = IntPtr.Zero; }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct NativeAttribute { public uint Type; public IntPtr Value; public uint Length; }
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct Mechanism { public uint Type; public IntPtr Parameter; public uint Length; }
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate uint GetFunctionList(out IntPtr functions);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate uint PointerCall(IntPtr pointer);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate uint SlotList(byte present, [Out] uint[]? slots, ref uint count);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate uint OpenSession(uint slot, uint flags, IntPtr application, IntPtr notify, out uint session);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate uint InfoCall(uint slot, [Out] byte[] info);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate uint SessionCall(uint session);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate uint LoginCall(uint session, uint user, IntPtr pin, uint length);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate uint FindInit(uint session, [In] NativeAttribute[] template, uint count);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate uint FindObjects(uint session, [Out] uint[] objects, uint maximum, out uint count);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate uint GetAttribute(uint session, uint handle, [In, Out] NativeAttribute[] attributes, uint count);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate uint SignInit(uint session, ref Mechanism mechanism, uint key);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate uint SignCall(uint session, [In] byte[] data, uint length, [Out] byte[]? signature, ref uint signatureLength);
    [DllImport("kernel32.dll", EntryPoint = "LoadLibraryExW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr LoadLibraryEx(string fileName, IntPtr file, uint flags);
}

internal sealed class Pkcs11Exception(uint code, JpkiOperation operation = JpkiOperation.Unknown) : Exception("JPKI operation failed.")
{
    public uint Code { get; } = code;
    public JpkiOperation Operation { get; } = operation;
}
