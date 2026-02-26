#pragma once

#include <windows.h>
#include <d3d11.h>
#include <string>
#include <unordered_map>
#include <mutex>
#include <wrl/client.h>

using Microsoft::WRL::ComPtr;

struct IconDataDX11
{
    ComPtr<ID3D11ShaderResourceView> TextureView;
    int Width = 0;
    int Height = 0;
    bool IsLoaded = false;
};

bool LoadFileIconDX11(ID3D11Device* device, const std::wstring& filePath, IconDataDX11& outIcon);
IconDataDX11* GetOrQueueIcon(ID3D11Device* device, const std::wstring& path);