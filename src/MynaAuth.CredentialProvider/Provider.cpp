#define SECURITY_WIN32
#include <windows.h>
#include <credentialprovider.h>
#include <propkey.h>
#include <ntsecapi.h>
#include <wincred.h>
#include <shlwapi.h>
#include <atomic>
#include <string>
#include <vector>
#include <new>
#include <cstring>
#include <functional>

static const CLSID ProviderId = {0x37167329,0xb6d8,0x4379,{0x90,0xa9,0x0d,0x35,0x0f,0x82,0xf3,0x1a}};
static HMODULE moduleHandle;
static std::atomic<long> objects{0};
static constexpr DWORD FieldCount = 5;

static HRESULT CopyText(const wchar_t* source, PWSTR* target)
{
    if (!target) return E_POINTER;
    *target = nullptr;
    size_t bytes = (wcslen(source) + 1) * sizeof(wchar_t);
    *target = static_cast<PWSTR>(CoTaskMemAlloc(bytes));
    if (!*target) return E_OUTOFMEMORY;
    memcpy(*target, source, bytes);
    return S_OK;
}
static void Wipe(std::vector<BYTE>& bytes)
{
    if (!bytes.empty()) SecureZeroMemory(bytes.data(), bytes.size());
    bytes.clear();
}
class Handle
{
public:
    HANDLE value = nullptr;
    ~Handle() { Close(); }
    void Close() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); value = nullptr; }
    Handle() = default;
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
};

static HRESULT AuthenticateCard(const std::wstring& sid, const BYTE pin[4], IQueryContinueWithStatus* query, std::vector<BYTE>& packed)
{
    wchar_t dllPath[32768]{};
    DWORD pathLength = GetModuleFileNameW(moduleHandle, dllPath, ARRAYSIZE(dllPath));
    if (!pathLength || pathLength >= ARRAYSIZE(dllPath)) return E_FAIL;
    std::wstring helper(dllPath);
    size_t slash = helper.find_last_of(L'\\');
    if (slash == std::wstring::npos) return E_FAIL;
    helper.resize(slash + 1);
    helper += L"MynaAuth.LogonHost.exe";
    std::wstring command = L"\"" + helper + L"\" --authenticate " + sid;
    SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
    Handle inputRead, inputWrite, outputRead, outputWrite, process, thread, job;
    if (!CreatePipe(&inputRead.value, &inputWrite.value, &security, 65536) ||
        !CreatePipe(&outputRead.value, &outputWrite.value, &security, 65536)) return HRESULT_FROM_WIN32(GetLastError());
    if (!SetHandleInformation(inputWrite.value, HANDLE_FLAG_INHERIT, 0) ||
        !SetHandleInformation(outputRead.value, HANDLE_FLAG_INHERIT, 0)) return E_FAIL;

    SIZE_T attributeBytes = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attributeBytes);
    std::vector<BYTE> attributes(attributeBytes);
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = inputRead.value;
    startup.StartupInfo.hStdOutput = outputWrite.value;
    startup.StartupInfo.hStdError = outputWrite.value;
    startup.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributes.data());
    if (!InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &attributeBytes)) return E_FAIL;
    HANDLE inherited[] = {inputRead.value, outputWrite.value};
    if (!UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited, sizeof(inherited), nullptr, nullptr))
    { DeleteProcThreadAttributeList(startup.lpAttributeList); return E_FAIL; }

    job.value = CreateJobObjectW(nullptr, nullptr);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!job.value || !SetInformationJobObject(job.value, JobObjectExtendedLimitInformation, &limits, sizeof(limits)))
    { DeleteProcThreadAttributeList(startup.lpAttributeList); return E_FAIL; }
    PROCESS_INFORMATION info{};
    BOOL created = CreateProcessW(helper.c_str(), command.data(), nullptr, nullptr, TRUE,
        CREATE_NO_WINDOW | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr, &startup.StartupInfo, &info);
    DeleteProcThreadAttributeList(startup.lpAttributeList);
    if (!created) return HRESULT_FROM_WIN32(GetLastError());
    process.value = info.hProcess; thread.value = info.hThread;
    if (!AssignProcessToJobObject(job.value, process.value)) { TerminateProcess(process.value, 1); return E_FAIL; }
    inputRead.Close(); outputWrite.Close();
    if (ResumeThread(thread.value) == static_cast<DWORD>(-1)) return E_FAIL;
    DWORD written = 0;
    if (!WriteFile(inputWrite.value, pin, 4, &written, nullptr) || written != 4) return E_FAIL;
    inputWrite.Close();
    for (unsigned int iteration = 0; ; iteration++)
    {
        DWORD wait = WaitForSingleObject(process.value, 100);
        if (wait == WAIT_OBJECT_0) break;
        if (wait != WAIT_TIMEOUT || iteration >= 650 || (query && FAILED(query->QueryContinue()))) return E_ABORT;
    }
    BYTE header[12]{};
    DWORD read = 0;
    if (!ReadFile(outputRead.value, header, sizeof(header), &read, nullptr) || read != sizeof(header) || memcmp(header, "MYL1", 4)) return E_FAIL;
    DWORD status = 1, length = 0;
    memcpy(&status, header + 4, 4); memcpy(&length, header + 8, 4);
    if (status == 2) return HRESULT_FROM_WIN32(ERROR_INVALID_PASSWORD);
    if (status == 3) return HRESULT_FROM_WIN32(ERROR_ACCOUNT_LOCKED_OUT);
    if (status == 4) return HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
    if (status == 5) return HRESULT_FROM_WIN32(ERROR_TIMEOUT);
    if (status != 0 || length == 0 || length > 65536) return E_ACCESSDENIED;
    packed.resize(length);
    DWORD offset = 0;
    while (offset < length)
    {
        if (!ReadFile(outputRead.value, packed.data() + offset, length - offset, &read, nullptr) || read == 0)
        { Wipe(packed); return E_FAIL; }
        offset += read;
    }
    return S_OK;
}

class Tile final : public IConnectableCredentialProviderCredential, public ICredentialProviderCredential2
{
    std::atomic<ULONG> references{1};
    std::wstring sid;
    wchar_t pin[5]{};
    std::vector<BYTE> packed;
    ICredentialProviderCredentialEvents* events = nullptr;
    HRESULT authentication = E_ACCESSDENIED;
    bool attempted = false;
    bool autoPending = false;
    bool connecting = false;
    std::function<void()> requestSubmit;
public:
    explicit Tile(std::wstring value, std::function<void()> submit = {}) : sid(std::move(value)), requestSubmit(std::move(submit)) { ++objects; }
    ~Tile() { Clear(); if (events) events->Release(); --objects; }
    void Clear() { SecureZeroMemory(pin, sizeof(pin)); Wipe(packed); authentication = E_ACCESSDENIED; attempted = false; autoPending = false; }
    bool AutoPending() const { return autoPending; }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID id, void** output) override
    {
        if (!output) return E_POINTER;
        *output = nullptr;
        if (id == IID_IUnknown || id == __uuidof(ICredentialProviderCredential) || id == __uuidof(ICredentialProviderCredential2))
            *output = static_cast<ICredentialProviderCredential2*>(this);
        else if (id == __uuidof(IConnectableCredentialProviderCredential)) *output = static_cast<IConnectableCredentialProviderCredential*>(this);
        else return E_NOINTERFACE;
        AddRef(); return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++references; }
    ULONG STDMETHODCALLTYPE Release() override { ULONG count = --references; if (!count) delete this; return count; }
    HRESULT STDMETHODCALLTYPE Advise(ICredentialProviderCredentialEvents* value) override
    { if (events) events->Release(); events = value; if (events) events->AddRef(); return S_OK; }
    HRESULT STDMETHODCALLTYPE UnAdvise() override { if (events) events->Release(); events = nullptr; return S_OK; }
    HRESULT STDMETHODCALLTYPE SetSelected(BOOL* automatic) override { if (!automatic) return E_POINTER; *automatic = autoPending ? TRUE : FALSE; return S_OK; }
    HRESULT STDMETHODCALLTYPE SetDeselected() override { Clear(); return S_OK; }
    HRESULT STDMETHODCALLTYPE GetFieldState(DWORD field, CREDENTIAL_PROVIDER_FIELD_STATE* state, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* interactive) override
    {
        if (!state || !interactive) return E_POINTER;
        if (field >= FieldCount) return E_INVALIDARG;
        *state = field <= 1 ? CPFS_DISPLAY_IN_BOTH : CPFS_DISPLAY_IN_SELECTED_TILE;
        *interactive = field == 3 ? CPFIS_FOCUSED : CPFIS_NONE; return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetStringValue(DWORD field, PWSTR* value) override
    {
        switch (field)
        {
        case 1: return CopyText(L"マイナンバーカードによるログイン", value);
        case 2: return CopyText(L"PIN を 4 桁入力すると読み取りを開始します。マイナンバーカードか Android をかざしてください。", value);
        case 3: return CopyText(pin, value);
        case 4: return CopyText(L"認証", value);
        default: return E_INVALIDARG;
        }
    }
    HRESULT STDMETHODCALLTYPE GetBitmapValue(DWORD field, HBITMAP* bitmap) override
    {
        if (field != 0 || !bitmap) return E_INVALIDARG;
        BITMAPINFO info{}; info.bmiHeader.biSize = sizeof(BITMAPINFOHEADER); info.bmiHeader.biWidth = 64;
        info.bmiHeader.biHeight = -64; info.bmiHeader.biPlanes = 1; info.bmiHeader.biBitCount = 32;
        void* pixels = nullptr;
        *bitmap = CreateDIBSection(nullptr, &info, DIB_RGB_COLORS, &pixels, nullptr, 0);
        if (!*bitmap) return E_OUTOFMEMORY;
        DWORD* colors = static_cast<DWORD*>(pixels);
        SecureZeroMemory(colors, 64 * 64 * sizeof(DWORD));
        HDC dc = CreateCompatibleDC(nullptr);
        HFONT font = CreateFontW(-46, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, ANTIALIASED_QUALITY, DEFAULT_PITCH, L"Segoe MDL2 Assets");
        if (!dc || !font)
        { if (font) DeleteObject(font); if (dc) DeleteDC(dc); DeleteObject(*bitmap); *bitmap = nullptr; return E_FAIL; }
        HGDIOBJ oldBitmap = SelectObject(dc, *bitmap);
        HGDIOBJ oldFont = SelectObject(dc, font);
        SetBkMode(dc, TRANSPARENT); SetTextColor(dc, RGB(255, 255, 255));
        RECT bounds{0, 0, 64, 64};
        DrawTextW(dc, L"\xE779", 1, &bounds, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        GdiFlush();
        // GDI draws white coverage on black without alpha. Convert that coverage
        // to premultiplied white so the tile background remains transparent.
        for (int index = 0; index < 64 * 64; index++)
        {
            DWORD coverage = colors[index] & 0xFF;
            colors[index] = (coverage << 24) | (coverage << 16) | (coverage << 8) | coverage;
        }
        SelectObject(dc, oldFont); SelectObject(dc, oldBitmap); DeleteObject(font); DeleteDC(dc);
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetCheckboxValue(DWORD, BOOL*, PWSTR*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetSubmitButtonValue(DWORD field, DWORD* adjacent) override { if (field != 4 || !adjacent) return E_INVALIDARG; *adjacent = 3; return S_OK; }
    HRESULT STDMETHODCALLTYPE GetComboBoxValueCount(DWORD, DWORD*, DWORD*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetComboBoxValueAt(DWORD, DWORD, PWSTR*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE SetStringValue(DWORD field, PCWSTR value) override
    {
        if (field != 3 || !value) return E_INVALIDARG;
        if (connecting) return *value == L'\0' ? S_OK : E_PENDING;
        if (wcscmp(pin, value) == 0) return S_OK;
        Clear(); size_t length = wcslen(value);
        if (length > 4) return E_INVALIDARG;
        memcpy(pin, value, length * sizeof(wchar_t));
        bool digits = length == 4;
        for (size_t index = 0; index < length; index++) digits = digits && pin[index] >= L'0' && pin[index] <= L'9';
        if (digits && requestSubmit) { autoPending = true; requestSubmit(); }
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE SetCheckboxValue(DWORD, BOOL) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE SetComboBoxSelectedValue(DWORD, DWORD) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE CommandLinkClicked(DWORD) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetUserSid(PWSTR* value) override { return CopyText(sid.c_str(), value); }
    HRESULT STDMETHODCALLTYPE Connect(IQueryContinueWithStatus* query) override
    {
        if (connecting || attempted) return S_OK;
        connecting = true; autoPending = false;
        Wipe(packed); authentication = E_ACCESSDENIED;
        BYTE digits[4]{};
        bool valid = wcslen(pin) == 4;
        for (int index = 0; index < 4; index++) { valid = valid && pin[index] >= L'0' && pin[index] <= L'9'; digits[index] = static_cast<BYTE>(pin[index]); }
        SecureZeroMemory(pin, sizeof(pin));
        if (events) events->SetFieldString(static_cast<ICredentialProviderCredential2*>(this), 3, L"");
        attempted = true;
        if (!valid) { SecureZeroMemory(digits, sizeof(digits)); connecting = false; return S_OK; }
        if (query) query->SetStatusMessage(L"マイナンバーカードまたは Android をかざしてください。自動再試行は行いません。");
        try { authentication = AuthenticateCard(sid, digits, query, packed); }
        catch (...) { Wipe(packed); authentication = E_FAIL; }
        SecureZeroMemory(digits, sizeof(digits));
        connecting = false;
        return S_OK; // GetSerialization reports a sanitized failure, never raw native exceptions.
    }
    HRESULT STDMETHODCALLTYPE Disconnect() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* response, CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* serialization, PWSTR* text, CREDENTIAL_PROVIDER_STATUS_ICON* icon) override
    {
        if (!response || !serialization || !text || !icon) return E_POINTER;
        *response = CPGSR_NO_CREDENTIAL_NOT_FINISHED; *serialization = {}; *text = nullptr; *icon = CPSI_NONE;
        // A normal logon host need not call the optional PLAP Connect interface.
        if (!attempted && wcslen(pin) == 4) Connect(nullptr);
        if (FAILED(authentication) || packed.empty())
        {
            *icon = CPSI_ERROR;
            const wchar_t* message = L"認証できませんでした。登録したカード／スマホを確認してください。標準のサインイン方法も利用できます。";
            if (authentication == HRESULT_FROM_WIN32(ERROR_INVALID_PASSWORD)) message = L"PIN が一致しません。自動再試行はしていません。3回連続で誤るとロックされるため、正しい番号を確認してください。";
            if (authentication == HRESULT_FROM_WIN32(ERROR_ACCOUNT_LOCKED_OUT)) message = L"カード／スマホの PIN がロックされています。標準の方法でサインインしてください。";
            if (authentication == HRESULT_FROM_WIN32(ERROR_NOT_FOUND)) message = L"このカード／スマホは対象の Windows アカウントに登録されていません。";
            if (authentication == HRESULT_FROM_WIN32(ERROR_TIMEOUT) || authentication == E_ABORT) message = L"認証をキャンセルしたか、待ち時間を過ぎました。標準の方法でもサインインできます。";
            return CopyText(message, text);
        }
        LSA_HANDLE lsa = nullptr;
        if (LsaConnectUntrusted(&lsa) != 0) { Wipe(packed); return E_FAIL; }
        char negotiate[] = "Negotiate";
        LSA_STRING name{}; name.Buffer = negotiate; name.Length = static_cast<USHORT>(strlen(negotiate)); name.MaximumLength = sizeof(negotiate);
        ULONG package = 0;
        NTSTATUS status = LsaLookupAuthenticationPackage(lsa, &name, &package);
        LsaDeregisterLogonProcess(lsa);
        if (status != 0) { Wipe(packed); return E_FAIL; }
        serialization->rgbSerialization = static_cast<BYTE*>(CoTaskMemAlloc(packed.size()));
        if (!serialization->rgbSerialization) { Wipe(packed); return E_OUTOFMEMORY; }
        memcpy(serialization->rgbSerialization, packed.data(), packed.size());
        serialization->cbSerialization = static_cast<ULONG>(packed.size());
        serialization->ulAuthenticationPackage = package;
        serialization->clsidCredentialProvider = ProviderId;
        *response = CPGSR_RETURN_CREDENTIAL_FINISHED;
        Wipe(packed); authentication = E_ACCESSDENIED;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE ReportResult(NTSTATUS status, NTSTATUS, PWSTR* text, CREDENTIAL_PROVIDER_STATUS_ICON* icon) override
    {
        Clear(); if (!text || !icon) return E_POINTER; *text = nullptr; *icon = CPSI_NONE;
        if (status < 0) { *icon = CPSI_ERROR; return CopyText(L"Windows が資格情報を受け付けませんでした。標準の方法でサインインし、登録した Windows パスワードを更新してください。", text); }
        return S_OK;
    }
};

class Provider final : public ICredentialProvider, public ICredentialProviderSetUserArray
{
    std::atomic<ULONG> references{1};
    std::vector<Tile*> tiles;
    ICredentialProviderEvents* events = nullptr;
    UINT_PTR eventContext = 0;
    void RequestSubmit() { if (events) events->CredentialsChanged(eventContext); }
public:
    Provider() { ++objects; }
    ~Provider() { for (Tile* tile : tiles) tile->Release(); if (events) events->Release(); --objects; }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID id, void** output) override
    {
        if (!output) return E_POINTER; *output = nullptr;
        if (id == IID_IUnknown || id == __uuidof(ICredentialProvider)) *output = static_cast<ICredentialProvider*>(this);
        else if (id == __uuidof(ICredentialProviderSetUserArray)) *output = static_cast<ICredentialProviderSetUserArray*>(this);
        else return E_NOINTERFACE;
        AddRef(); return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++references; }
    ULONG STDMETHODCALLTYPE Release() override { ULONG count = --references; if (!count) delete this; return count; }
    HRESULT STDMETHODCALLTYPE SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario, DWORD) override
    { return scenario == CPUS_LOGON || scenario == CPUS_UNLOCK_WORKSTATION ? S_OK : E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Advise(ICredentialProviderEvents* value, UINT_PTR context) override
    { if (events) events->Release(); events = value; eventContext = context; if (events) events->AddRef(); return S_OK; }
    HRESULT STDMETHODCALLTYPE UnAdvise() override { if (events) events->Release(); events = nullptr; return S_OK; }
    HRESULT STDMETHODCALLTYPE GetFieldDescriptorCount(DWORD* count) override { if (!count) return E_POINTER; *count = FieldCount; return S_OK; }
    HRESULT STDMETHODCALLTYPE GetFieldDescriptorAt(DWORD index, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** descriptor) override
    {
        if (!descriptor) return E_POINTER; *descriptor = nullptr; if (index >= FieldCount) return E_INVALIDARG;
        CREDENTIAL_PROVIDER_FIELD_TYPE types[] = {CPFT_TILE_IMAGE, CPFT_LARGE_TEXT, CPFT_SMALL_TEXT, CPFT_PASSWORD_TEXT, CPFT_SUBMIT_BUTTON};
        const wchar_t* labels[] = {L"マイナンバーカードによるログイン", L"マイナンバーカードによるログイン", L"説明", L"利用者証明用 PIN", L"認証"};
        *descriptor = static_cast<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*>(CoTaskMemAlloc(sizeof(**descriptor)));
        if (!*descriptor) return E_OUTOFMEMORY;
        **descriptor = {}; (*descriptor)->dwFieldID = index; (*descriptor)->cpft = types[index];
        HRESULT hr = CopyText(labels[index], &(*descriptor)->pszLabel);
        if (FAILED(hr)) { CoTaskMemFree(*descriptor); *descriptor = nullptr; }
        return hr;
    }
    HRESULT STDMETHODCALLTYPE GetCredentialCount(DWORD* count, DWORD* selected, BOOL* automatic) override
    {
        if (!count || !selected || !automatic) return E_POINTER;
        *count = static_cast<DWORD>(tiles.size()); *selected = CREDENTIAL_PROVIDER_NO_DEFAULT; *automatic = FALSE;
        for (DWORD index = 0; index < *count; index++)
            if (tiles[index]->AutoPending()) { *selected = index; *automatic = TRUE; break; }
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetCredentialAt(DWORD index, ICredentialProviderCredential** credential) override
    { if (!credential) return E_POINTER; *credential = nullptr; if (index >= tiles.size()) return E_INVALIDARG; return tiles[index]->QueryInterface(__uuidof(ICredentialProviderCredential), reinterpret_cast<void**>(credential)); }
    HRESULT STDMETHODCALLTYPE SetUserArray(ICredentialProviderUserArray* users) override
    {
        for (Tile* tile : tiles) tile->Release(); tiles.clear();
        if (!users) return E_INVALIDARG;
        DWORD count = 0; HRESULT hr = users->GetCount(&count); if (FAILED(hr)) return hr;
        try
        {
            for (DWORD index = 0; index < count; index++)
            {
                ICredentialProviderUser* user = nullptr;
                if (FAILED(users->GetAt(index, &user))) continue;
                PWSTR sid = nullptr; HRESULT result = user->GetSid(&sid); user->Release();
                if (SUCCEEDED(result) && sid)
                {
                    std::wstring path = L"SOFTWARE\\MynaAuth\\Accounts\\" + std::wstring(sid);
                    HKEY key = nullptr;
                    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0, KEY_READ, &key) == ERROR_SUCCESS)
                    { RegCloseKey(key); tiles.push_back(new Tile(sid, [this]() { RequestSubmit(); })); }
                }
                CoTaskMemFree(sid);
            }
        }
        catch (...) { return E_OUTOFMEMORY; }
        return S_OK;
    }
};

class Factory final : public IClassFactory
{
    std::atomic<ULONG> references{1};
public:
    Factory() { ++objects; }
    ~Factory() { --objects; }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID id, void** result) override
    { if (!result) return E_POINTER; *result = nullptr; if (id != IID_IUnknown && id != IID_IClassFactory) return E_NOINTERFACE; *result = static_cast<IClassFactory*>(this); AddRef(); return S_OK; }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++references; }
    ULONG STDMETHODCALLTYPE Release() override { ULONG count = --references; if (!count) delete this; return count; }
    HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown* outer, REFIID id, void** result) override
    {
        if (outer) return CLASS_E_NOAGGREGATION;
        Provider* provider = new(std::nothrow) Provider(); if (!provider) return E_OUTOFMEMORY;
        HRESULT hr = provider->QueryInterface(id, result); provider->Release(); return hr;
    }
    HRESULT STDMETHODCALLTYPE LockServer(BOOL lock) override { if (lock) ++objects; else --objects; return S_OK; }
};
extern "C" HRESULT __stdcall DllGetClassObject(REFCLSID id, REFIID iid, void** result)
{
    if (id != ProviderId) return CLASS_E_CLASSNOTAVAILABLE;
    Factory* factory = new(std::nothrow) Factory(); if (!factory) return E_OUTOFMEMORY;
    HRESULT hr = factory->QueryInterface(iid, result); factory->Release(); return hr;
}
extern "C" HRESULT __stdcall DllCanUnloadNow() { return objects == 0 ? S_OK : S_FALSE; }
BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID)
{ if (reason == DLL_PROCESS_ATTACH) { moduleHandle = instance; DisableThreadLibraryCalls(instance); } return TRUE; }
