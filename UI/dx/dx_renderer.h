#pragma once

#include <windows.h>
#include <d3d11.h>
#include <dxgi.h>
#include <wrl/client.h>

using Microsoft::WRL::ComPtr;

extern ID3D11Device*           g_pd3dDevice;
extern ID3D11DeviceContext*    g_pd3dDeviceContext;
extern IDXGISwapChain*         g_pSwapChain;
extern ID3D11RenderTargetView* g_mainRenderTargetView;
extern ID3D11RasterizerState*  g_rasterizerState;
extern HWND                    g_hWnd;

bool CreateDeviceD3D(HWND hWnd);
void CleanupDeviceD3D();
void CleanupRenderTarget();
void CreateRenderTarget();
void CreateRasterizerState();

LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);