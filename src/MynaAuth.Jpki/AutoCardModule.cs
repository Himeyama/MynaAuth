namespace MynaAuth.Jpki;

internal sealed class AutoCardModule : IPkcs11Module
{
    private readonly AndroidCardModule _probe;
    private readonly Func<IPkcs11Module> _physicalFactory;
    private IPkcs11Module? _selected;
    private bool _opened;

    public AutoCardModule() : this(new AndroidCardModule(() => new PcscConnection(), null), () => new Pkcs11Module()) { }

    internal AutoCardModule(AndroidCardModule probe, Func<IPkcs11Module> physicalFactory)
    {
        _probe = probe;
        _physicalFactory = physicalFactory;
    }

    public CardDevice? DetectedDevice { get; private set; }
    public uint[] GetSlots() => _probe.GetSlots();

    public void Open(uint slot)
    {
        if (_opened) throw new Pkcs11Exception(0x6, JpkiOperation.OpenSession);
        _opened = true;
        _probe.Open(slot); // Public type only: no PIN, certificate or signature.
        DetectedDevice = _probe.DetectedDevice;
        if (DetectedDevice == CardDevice.Android)
        {
            _selected = _probe; // Keep this exact NFC session for Android.
            return;
        }
        if (DetectedDevice != CardDevice.PhysicalCard)
            throw new Pkcs11Exception(0xE1, JpkiOperation.AndroidReadToken);

        // Release the PC/SC transaction before opening the existing JPKI path.
        _probe.Dispose();
        _selected = _physicalFactory();
        uint[] slots = _selected.GetSlots();
        if (slots.Length != 1) throw new Pkcs11Exception(0xE0, JpkiOperation.GetSlots);
        _selected.Open(slots[0]);
    }

    public uint Login(byte[] pin) => Selected.Login(pin);
    public byte[] Certificate() => Selected.Certificate();
    public byte[] Sign(byte[] digestInfo) => Selected.Sign(digestInfo);
    private IPkcs11Module Selected => _selected ?? throw new Pkcs11Exception(0x6, JpkiOperation.OpenSession);

    public void Dispose()
    {
        if (_selected is not null && !ReferenceEquals(_selected, _probe)) _selected.Dispose();
        _probe.Dispose();
        _selected = null;
    }
}
