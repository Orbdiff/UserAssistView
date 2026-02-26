#include "icon_loader.h"

#include <shlobj.h>
#include <vector>
#include <algorithm>

static std::mutex g_iconMutex;
static std::unordered_map<std::wstring, IconDataDX11> g_iconsCache;

bool LoadFileIconDX11(ID3D11Device* device, const std::wstring& filePath, IconDataDX11& outIcon)
{
    if (!device || filePath.empty())
        return false;

    int size_needed = WideCharToMultiByte(CP_ACP, 0, filePath.c_str(), -1, NULL, 0, NULL, NULL);
    std::string filePathA(size_needed, 0);
    WideCharToMultiByte(CP_ACP, 0, filePath.c_str(), -1, &filePathA[0], size_needed, NULL, NULL);

    DWORD fileAttributes = GetFileAttributesA(filePathA.c_str());
    bool fileExists = (fileAttributes != INVALID_FILE_ATTRIBUTES);

    SHFILEINFOA shfi = { 0 };
    DWORD dwFlags = SHGFI_ICON | SHGFI_SMALLICON;
    if (!fileExists)
    {
        dwFlags |= SHGFI_USEFILEATTRIBUTES;
    }

    DWORD_PTR result = SHGetFileInfoA(filePathA.c_str(), fileExists ? 0 : FILE_ATTRIBUTE_NORMAL, &shfi, sizeof(SHFILEINFOA), dwFlags);

    if (result == 0 || shfi.hIcon == NULL)
        return false;

    ICONINFO iconInfo;
    if (!GetIconInfo(shfi.hIcon, &iconInfo)) 
    {
        DestroyIcon(shfi.hIcon);
        return false;
    }

    BITMAP bm;
    if (!GetObject(iconInfo.hbmColor, sizeof(BITMAP), &bm)) 
    {
        DeleteObject(iconInfo.hbmMask);
        DeleteObject(iconInfo.hbmColor);
        DestroyIcon(shfi.hIcon);
        return false;
    }

    HDC hDC = CreateCompatibleDC(NULL);
    if (!hDC)
    {
        DeleteObject(iconInfo.hbmMask);
        DeleteObject(iconInfo.hbmColor);
        DestroyIcon(shfi.hIcon);
        return false;
    }

    HBITMAP oldBitmap = (HBITMAP)SelectObject(hDC, iconInfo.hbmColor);
    int width = bm.bmWidth;
    int height = bm.bmHeight;

    std::vector<BYTE> pixels(width * height * 4);
    BITMAPINFO bmi = {};
    bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth = width;
    bmi.bmiHeader.biHeight = -height;
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;
    bmi.bmiHeader.biCompression = BI_RGB;

    GetDIBits(hDC, iconInfo.hbmColor, 0, height, pixels.data(), &bmi, DIB_RGB_COLORS);

    for (size_t i = 0; i < pixels.size(); i += 4)
    {
        std::swap(pixels[i], pixels[i + 2]);
    }

    D3D11_TEXTURE2D_DESC desc = {};
    desc.Width = width;
    desc.Height = height;
    desc.MipLevels = 1;
    desc.ArraySize = 1;
    desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    desc.SampleDesc.Count = 1;
    desc.Usage = D3D11_USAGE_DEFAULT;
    desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;

    D3D11_SUBRESOURCE_DATA initData = {};
    initData.pSysMem = pixels.data();
    initData.SysMemPitch = width * 4;

    ComPtr<ID3D11Texture2D> texture;
    if (FAILED(device->CreateTexture2D(&desc, &initData, &texture)))
    {
        SelectObject(hDC, oldBitmap);
        DeleteDC(hDC);
        DeleteObject(iconInfo.hbmMask);
        DeleteObject(iconInfo.hbmColor);
        DestroyIcon(shfi.hIcon);
        return false;
    }

    if (FAILED(device->CreateShaderResourceView(texture.Get(), nullptr, &outIcon.TextureView)))
    {
        SelectObject(hDC, oldBitmap);
        DeleteDC(hDC);
        DeleteObject(iconInfo.hbmMask);
        DeleteObject(iconInfo.hbmColor);
        DestroyIcon(shfi.hIcon);
        return false;
    }

    SelectObject(hDC, oldBitmap);
    DeleteDC(hDC);
    DeleteObject(iconInfo.hbmMask);
    DeleteObject(iconInfo.hbmColor);
    DestroyIcon(shfi.hIcon);

    outIcon.Width = width;
    outIcon.Height = height;
    outIcon.IsLoaded = true;
    return true;
}

IconDataDX11* GetOrQueueIcon(ID3D11Device* device, const std::wstring& path)
{
    if (path.empty() || !device)
        return nullptr;

    {
        std::lock_guard<std::mutex> lock(g_iconMutex);
        auto it = g_iconsCache.find(path);
        if (it != g_iconsCache.end())
            return &it->second;
    }

    IconDataDX11 icon;
    if (LoadFileIconDX11(device, path, icon)) 
    {
        std::lock_guard<std::mutex> lock(g_iconMutex);
        auto result = g_iconsCache.emplace(path, std::move(icon));
        return &result.first->second;
    }

    return nullptr;
}