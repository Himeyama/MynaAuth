#include <windows.h>
#include <credentialprovider.h>
#include <iostream>
#include <fstream>
#include "Provider.cpp"

int wmain(int count, wchar_t** args)
{
    if (count != 2 && count != 3) return 1;
    HMODULE library = LoadLibraryW(args[1]); if (!library) return 2;
    using GetClass = HRESULT(__stdcall*)(REFCLSID, REFIID, void**);
    GetClass getClass = reinterpret_cast<GetClass>(GetProcAddress(library, "DllGetClassObject"));
    CLSID id{0x37167329,0xb6d8,0x4379,{0x90,0xa9,0x0d,0x35,0x0f,0x82,0xf3,0x1a}};
    IClassFactory* factory = nullptr;
    if (!getClass || FAILED(getClass(id, IID_IClassFactory, reinterpret_cast<void**>(&factory)))) return 3;
    ICredentialProvider* provider = nullptr;
    HRESULT hr = factory->CreateInstance(nullptr, __uuidof(ICredentialProvider), reinterpret_cast<void**>(&provider)); factory->Release();
    if (FAILED(hr)) return 4;
    DWORD fields = 0, credentials = 0, selected = 0; BOOL automatic = TRUE;
    bool ok = SUCCEEDED(provider->SetUsageScenario(CPUS_LOGON, 0)) &&
        SUCCEEDED(provider->SetUsageScenario(CPUS_UNLOCK_WORKSTATION, 0)) &&
        FAILED(provider->SetUsageScenario(CPUS_CREDUI, 0)) &&
        SUCCEEDED(provider->GetFieldDescriptorCount(&fields)) && fields == 5 &&
        SUCCEEDED(provider->GetCredentialCount(&credentials, &selected, &automatic)) && credentials == 0 && !automatic;
    for (DWORD index = 0; index < fields; index++)
    {
        CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* descriptor = nullptr;
        ok = ok && SUCCEEDED(provider->GetFieldDescriptorAt(index, &descriptor));
        if (descriptor) { CoTaskMemFree(descriptor->pszLabel); CoTaskMemFree(descriptor); }
    }
    provider->Release(); FreeLibrary(library);
    Tile* tile = new Tile(L"S-1-5-21-1-2-3-1001");
    IConnectableCredentialProviderCredential* connectable = nullptr;
    ok = ok && SUCCEEDED(tile->QueryInterface(__uuidof(IConnectableCredentialProviderCredential), reinterpret_cast<void**>(&connectable)));
    if (connectable) connectable->Release();
    BOOL tileAutomatic = TRUE;
    ok = ok && SUCCEEDED(tile->SetSelected(&tileAutomatic)) && !tileAutomatic;
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE response{};
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION serialization{};
    PWSTR statusText = nullptr;
    CREDENTIAL_PROVIDER_STATUS_ICON icon{};
    ok = ok && SUCCEEDED(tile->GetSerialization(&response, &serialization, &statusText, &icon)) &&
        response == CPGSR_NO_CREDENTIAL_NOT_FINISHED && serialization.rgbSerialization == nullptr;
    CoTaskMemFree(statusText); statusText = nullptr;
    ok = ok && FAILED(tile->SetStringValue(3, L"too-long"));
    tile->SetStringValue(3, L"abcd");
    tile->Connect(nullptr); // Invalid PIN must never launch a helper or contact a card.
    ok = ok && SUCCEEDED(tile->GetSerialization(&response, &serialization, &statusText, &icon)) &&
        response == CPGSR_NO_CREDENTIAL_NOT_FINISHED && serialization.rgbSerialization == nullptr;
    CoTaskMemFree(statusText);
    tile->SetDeselected();
    PWSTR erasedPin = nullptr;
    tile->GetStringValue(3, &erasedPin);
    ok = ok && erasedPin && wcslen(erasedPin) == 0;
    CoTaskMemFree(erasedPin);
    tile->Release();
    unsigned int submissions = 0;
    Tile* automaticTile = new Tile(L"S-1-5-21-1-2-3-1001", [&submissions]() { submissions++; });
    automaticTile->SetStringValue(3, L"123");
    ok = ok && submissions == 0 && !automaticTile->AutoPending();
    automaticTile->SetStringValue(3, L"12a4");
    ok = ok && submissions == 0 && !automaticTile->AutoPending();
    automaticTile->SetStringValue(3, L"1234");
    ok = ok && submissions == 1 && automaticTile->AutoPending();
    automaticTile->SetStringValue(3, L"1234");
    ok = ok && submissions == 1;
    automaticTile->SetSelected(&tileAutomatic);
    ok = ok && tileAutomatic;
    automaticTile->SetDeselected();
    automaticTile->SetSelected(&tileAutomatic);
    ok = ok && !tileAutomatic && !automaticTile->AutoPending();
    PWSTR title = nullptr;
    automaticTile->GetStringValue(1, &title);
    ok = ok && title && wcscmp(title, L"マイナンバーカードによるログイン") == 0;
    CoTaskMemFree(title);
    HBITMAP iconBitmap = nullptr;
    ok = ok && SUCCEEDED(automaticTile->GetBitmapValue(0, &iconBitmap));
    BITMAP bitmap{};
    if (iconBitmap)
    {
        GetObjectW(iconBitmap, sizeof(bitmap), &bitmap);
        DWORD* pixels = static_cast<DWORD*>(bitmap.bmBits);
        unsigned int glyphPixels = 0;
        unsigned int transparentPixels = 0;
        for (int index = 0; pixels && index < 64 * 64; index++)
        {
            if (pixels[index] >> 24) glyphPixels++;
            else transparentPixels++;
        }
        ok = ok && bitmap.bmWidth == 64 && bitmap.bmHeight == 64 && glyphPixels > 100 && transparentPixels > 1000;
        if (count == 3 && pixels)
        {
            BITMAPFILEHEADER fileHeader{}; fileHeader.bfType = 0x4D42;
            fileHeader.bfOffBits = sizeof(fileHeader) + sizeof(BITMAPINFOHEADER);
            fileHeader.bfSize = fileHeader.bfOffBits + 64 * 64 * 4;
            BITMAPINFOHEADER imageHeader{}; imageHeader.biSize = sizeof(imageHeader);
            imageHeader.biWidth = 64; imageHeader.biHeight = -64; imageHeader.biPlanes = 1; imageHeader.biBitCount = 32;
            std::ofstream output(args[2], std::ios::binary);
            output.write(reinterpret_cast<const char*>(&fileHeader), sizeof(fileHeader));
            output.write(reinterpret_cast<const char*>(&imageHeader), sizeof(imageHeader));
            output.write(reinterpret_cast<const char*>(pixels), 64 * 64 * 4);
        }
        DeleteObject(iconBitmap);
    }
    automaticTile->Release();
    std::cout << (ok ? "Automatic submit, duplicate suppression, deselection reset, Japanese title and font icon checks passed.\n" : "Automatic submit or visual checks failed.\n");
    std::cout << (ok ? "Provider COM and field checks passed. No registration or logon attempted.\n" : "Provider checks failed.\n");
    return ok ? 0 : 5;
}
