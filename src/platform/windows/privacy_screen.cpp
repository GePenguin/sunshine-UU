/**
 * @file src/platform/windows/privacy_screen.cpp
 * @brief Windows privacy-screen overlay and remote-lock implementation.
 *
 * Reverse-engineered equivalent of UU Remote (GameViewer) 隐私屏, ported to
 * Sunshine.  Architecture (empirically verified on Win11 26200 + targeted
 * static analysis of GameViewerServer.exe):
 *
 *   physical monitor : full-screen, topmost, layered Win32 window painted with
 *                      the privacy wallpaper (private_screen_window.cpp).
 *   remote capture   : SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)
 *                      keeps that window out of DXGI Desktop Duplication, GDI
 *                      BitBlt and Windows.Graphics.Capture
 *                      (window_capture_exclusion.cpp).  No DWM cloaking, no
 *                      separate capture pipeline, no per-backend branching.
 *   restore          : destroy the window; optionally LockWorkStation()
 *                      (handleDisablePrivacyModeAndLock).
 *
 * Wallpaper decoding uses the GDI+ flat API (gdiplus.dll, loaded dynamically,
 * no .lib needed) so PNG/JPG/BMP/GIF all work with zero new deps.  All
 * post-Win7 user32 APIs are resolved dynamically for MinGW/MSVC parity.
 */
// platform includes
#include <Windows.h>
#include <wtsapi32.h>  // WTSQuerySessionInformation / WTSSessionInfoEx

// local includes
#include "privacy_screen.h"
#include "utf_utils.h"
#include "src/logging.h"

// standard includes
#include <algorithm>
#include <string>
#include <string_view>
#include <vector>

namespace platf::privacy {
  using namespace std::literals;

  // WDA_EXCLUDEFROMCAPTURE = 0x11 (Win10 2004+). Defined locally so MinGW's
  // winuser.h version does not gate the build; verified with a read-back.
  static constexpr DWORD kAffinityExclude = 0x00000011;
  // DWMWA_CLOAK (dwmapi.h): cloaks the window so DWM excludes it from all
  // composition/capture paths. UU sets attribute 0xC with value TRUE, size 4
  // (observed in window_capture_exclusion.cpp's DwmSetWindowAttribute wrapper).
  static constexpr DWORD kDwmwaCloak = 0x0000000C;
  static constexpr UINT WM_APP_PRIVACY_QUIT = WM_APP + 1;
  static constexpr UINT_PTR kImeHideTimerId = 0x5E1;
  static constexpr const wchar_t *kOverlayClass = L"SunshinePrivacyOverlay";

  // -------------------------------------------------------------------------
  // Dynamically-resolved user32 / magnification entry points.
  // -------------------------------------------------------------------------
  struct apis_t {
    using set_dpi_ctx_t = BOOL(WINAPI *)(void *);
    using set_thread_dpi_ctx_t = void *(WINAPI *)(void *);
    using set_affinity_t = BOOL(WINAPI *)(HWND, DWORD);
    using get_affinity_t = BOOL(WINAPI *)(HWND, DWORD *);
    using mag_init_t = BOOL(WINAPI *)(void);
    using mag_uninit_t = BOOL(WINAPI *)(void);
    using mag_show_cursor_t = BOOL(WINAPI *)(BOOL);
    // DwmSetWindowAttribute(HWND, DWORD attribute, LPCVOID value, DWORD size)
    using dwm_set_attr_t = HRESULT(WINAPI *)(HWND, DWORD, LPCVOID, DWORD);

    set_dpi_ctx_t set_dpi_ctx = nullptr;
    set_thread_dpi_ctx_t set_thread_dpi_ctx = nullptr;
    set_affinity_t set_affinity = nullptr;
    get_affinity_t get_affinity = nullptr;
    mag_init_t mag_init = nullptr;
    mag_uninit_t mag_uninit = nullptr;
    mag_show_cursor_t mag_show_cursor = nullptr;
    dwm_set_attr_t dwm_set_attr = nullptr;

    static apis_t &instance() {
      static apis_t a;
      return a;
    }

   private:
    apis_t() {
      HMODULE user32 = GetModuleHandleW(L"user32.dll");
      if (user32) {
        set_dpi_ctx = (set_dpi_ctx_t) GetProcAddress(user32, "SetProcessDpiAwarenessContext");
        set_thread_dpi_ctx = (set_thread_dpi_ctx_t) GetProcAddress(user32, "SetThreadDpiAwarenessContext");
        set_affinity = (set_affinity_t) GetProcAddress(user32, "SetWindowDisplayAffinity");
        get_affinity = (get_affinity_t) GetProcAddress(user32, "GetWindowDisplayAffinity");
      }
      if (HMODULE mag = LoadLibraryW(L"magnification.dll")) {
        mag_init = (mag_init_t) GetProcAddress(mag, "MagInitialize");
        mag_uninit = (mag_uninit_t) GetProcAddress(mag, "MagUninitialize");
        mag_show_cursor = (mag_show_cursor_t) GetProcAddress(mag, "MagShowSystemCursor");
      }
      if (HMODULE dwm = LoadLibraryW(L"dwmapi.dll")) {
        dwm_set_attr = (dwm_set_attr_t) GetProcAddress(dwm, "DwmSetWindowAttribute");
      }
    }
  };

  // -------------------------------------------------------------------------
  // Minimal GDI+ flat API (gdiplus.dll exports are undecorated stdcall on x64).
  // Only the entry points needed to decode an image into 32bpp ARGB pixels.
  // -------------------------------------------------------------------------
  struct gdiplus_t {
    using startup_t = int(WINAPI *)(ULONG_PTR *, const void *, void *);
    using shutdown_t = void(WINAPI *)(ULONG_PTR);
    using from_file_t = int(WINAPI *)(const WCHAR *, void **);
    using dispose_t = int(WINAPI *)(void *);
    using get_dim_t = int(WINAPI *)(void *, UINT *);
    using lock_bits_t = int(WINAPI *)(void *, const void *, UINT, int, void *);
    using unlock_bits_t = int(WINAPI *)(void *, void *);

    // GdiplusStartupInput { UINT32 Version; void* DebugEventCallback;
    //                       BOOL SuppressBackgroundThread; BOOL SuppressExternalCodecs; }
    struct startup_input_t {
      std::uint32_t version = 1;
      void *debug_cb = nullptr;
      // SuppressBackgroundThread MUST stay FALSE unless a GdiplusStartupOutput
      // is also supplied: passing TRUE with a null output makes GdiplusStartup
      // return GpStatus::InvalidParameter (2) and the whole decode fails.
      BOOL suppress_bg = FALSE;
      BOOL suppress_external = FALSE;
    };
    // GpRect { INT X, Y, Width, Height; }
    struct gp_rect_t { INT x, y, w, h; };
    // BitmapData { UINT Width, Height; INT Stride; INT PixelFormat;
    //              void* Scan0; UINT_PTR Reserved; } (natural x64 alignment)
    struct bitmap_data_t {
      UINT width;
      UINT height;
      INT stride;
      INT pixel_format;
      void *scan0;
      UINT_PTR reserved;
    };

    HMODULE mod = nullptr;
    startup_t startup = nullptr;
    shutdown_t shutdown = nullptr;
    from_file_t from_file = nullptr;
    dispose_t dispose = nullptr;
    get_dim_t get_width = nullptr;
    get_dim_t get_height = nullptr;
    lock_bits_t lock_bits = nullptr;
    unlock_bits_t unlock_bits = nullptr;
    ULONG_PTR token = 0;
    bool ready = false;

    static gdiplus_t &instance() {
      static gdiplus_t g;
      return g;
    }

    bool init() {
      if (ready) return true;
      mod = LoadLibraryW(L"gdiplus.dll");
      if (!mod) return false;
      startup = (startup_t) GetProcAddress(mod, "GdiplusStartup");
      shutdown = (shutdown_t) GetProcAddress(mod, "GdiplusShutdown");
      from_file = (from_file_t) GetProcAddress(mod, "GdipCreateBitmapFromFile");
      dispose = (dispose_t) GetProcAddress(mod, "GdipDisposeImage");
      get_width = (get_dim_t) GetProcAddress(mod, "GdipGetImageWidth");
      get_height = (get_dim_t) GetProcAddress(mod, "GdipGetImageHeight");
      lock_bits = (lock_bits_t) GetProcAddress(mod, "GdipBitmapLockBits");
      unlock_bits = (unlock_bits_t) GetProcAddress(mod, "GdipBitmapUnlockBits");
      if (!startup || !shutdown || !from_file || !dispose || !get_width ||
          !get_height || !lock_bits || !unlock_bits) {
        return false;
      }
      startup_input_t in;
      if (startup(&token, &in, nullptr) != 0) return false;  // GpStatus::Ok = 0
      ready = true;
      return true;
    }

    ~gdiplus_t() {
      if (ready && shutdown) shutdown(token);
      if (mod) FreeLibrary(mod);
    }

   private:
    gdiplus_t() = default;
  };

  /** @brief Decoded wallpaper: 32bpp top-down BGRA with opaque alpha. */
  struct image_t {
    UINT w = 0;
    UINT h = 0;
    std::vector<BYTE> bgra;
  };

  /**
   * @brief Decode a wallpaper via GDI+ into a 32bpp BGRA buffer.
   * Mirrors FreeImage_OpenMemory in UU's image_memory_painter.cpp, using only
   * OS-provided components.  GDI+ 32bppARGB scanlines are B,G,R,A in memory,
   * which is exactly the layout UpdateLayeredWindow's 32bpp DIB expects.
   */
  static bool decode_image(const std::wstring &path, image_t &out) {
    auto &g = gdiplus_t::instance();
    if (!g.init()) return false;

    void *bmp = nullptr;
    if (g.from_file(path.c_str(), &bmp) != 0 || !bmp) return false;  // GpStatus::Ok = 0

    UINT w = 0, h = 0;
    g.get_width(bmp, &w);
    g.get_height(bmp, &h);

    bool ok = false;
    const int kPixelFormat32bppARGB = 0x26200A;
    const UINT kImageLockModeRead = 0x0001;
    if (w > 0 && h > 0 && w <= 16384 && h <= 16384) {
      gdiplus_t::gp_rect_t r {0, 0, (INT) w, (INT) h};
      gdiplus_t::bitmap_data_t bd {};
      if (g.lock_bits(bmp, &r, kImageLockModeRead, kPixelFormat32bppARGB, &bd) == 0 && bd.scan0) {
        out.w = w;
        out.h = h;
        out.bgra.assign((size_t) w * h * 4, 0);
        INT stride = bd.stride >= 0 ? bd.stride : (INT) (w * 4);
        for (UINT y = 0; y < h; y++) {
          const BYTE *src = (const BYTE *) bd.scan0 + (size_t) y * stride;
          BYTE *dst = out.bgra.data() + (size_t) y * w * 4;
          memcpy(dst, src, (size_t) w * 4);
          for (UINT x = 0; x < w; x++) dst[x * 4 + 3] = 255;  // force opaque
        }
        g.unlock_bits(bmp, &bd);
        ok = true;
      }
    }
    g.dispose(bmp);
    return ok;
  }

  /** @brief Decode file, else build a solid-colour fallback (UU degrades to black). */
  static image_t make_wallpaper(const privacy_config_t &cfg, bool &image_ok) {
    image_t img;
    image_ok = false;
    if (!cfg.image_path.empty()) {
      image_ok = decode_image(utf_utils::from_utf8(cfg.image_path), img);
    }
    if (!image_ok) {
      int w = GetSystemMetrics(SM_CXSCREEN);
      int h = GetSystemMetrics(SM_CYSCREEN);
      if (w <= 0 || h <= 0) { w = 1920; h = 1080; }
      img.w = (UINT) w;
      img.h = (UINT) h;
      img.bgra.assign((size_t) w * h * 4, 0);
      BYTE r = (BYTE) ((cfg.fallback_rgb >> 16) & 0xFF);
      BYTE g = (BYTE) ((cfg.fallback_rgb >> 8) & 0xFF);
      BYTE b = (BYTE) (cfg.fallback_rgb & 0xFF);
      for (size_t i = 0; i < (size_t) w * h; i++) {
        img.bgra[i * 4 + 0] = b;
        img.bgra[i * 4 + 1] = g;
        img.bgra[i * 4 + 2] = r;
        img.bgra[i * 4 + 3] = 255;
      }
    }
    return img;
  }

  // -------------------------------------------------------------------------
  const char *result_name(result_e r) {
    switch (r) {
      case result_e::ok: return "ok";
      case result_e::already_active: return "already_active";
      case result_e::not_active: return "not_active";
      case result_e::unsupported_os: return "unsupported_os";
      case result_e::window_failed: return "window_failed";
      case result_e::affinity_failed: return "affinity_failed";
      case result_e::image_failed: return "image_failed";
      case result_e::lock_failed: return "lock_failed";
    }
    return "unknown";
  }

  /**
   * @brief True when the interactive session is locked (secure desktop active).
   *
   * Measured on Windows 11 26200, comparing an unlocked and a locked session:
   *
   *   signal                              unlocked        locked
   *   ----------------------------------  --------------  --------------
   *   OpenInputDesktop() name             "Default"       "Default"      <- USELESS
   *   WTSINFOEX.SessionFlags              0x00000001      0x00000000     <- works
   *   GetForegroundWindow class           Chrome_Widget…  Windows.UI.Co…
   *
   * OpenInputDesktop does NOT change when the workstation locks, which is why
   * an earlier version of this check never fired. WTSINFOEX via
   * WTSQuerySessionInformation(WTSSessionInfoEx) reports the documented
   * WTS_SESSIONSTATE_LOCK (0) / WTS_SESSIONSTATE_UNLOCK (1) reliably from any
   * thread in the session, so that is the primary signal. The foreground-window
   * class is kept as a fallback for builds where WTSSessionInfoEx is refused.
   */
  bool is_session_locked() {
    // Primary: documented session-state flag.
    WTSINFOEXW *info = nullptr;
    DWORD bytes = 0;
    if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION,
                                    WTSSessionInfoEx, (LPWSTR *) &info, &bytes)) {
      bool locked = false;
      bool valid = false;
      if (info && bytes >= sizeof(WTSINFOEXW) && info->Level == 1) {
        // SessionFlags: 0 = WTS_SESSIONSTATE_LOCK, 1 = WTS_SESSIONSTATE_UNLOCK
        locked = (info->Data.WTSInfoExLevel1.SessionFlags == 0);
        valid = true;
      }
      WTSFreeMemory(info);
      if (valid) {
        return locked;
      }
    }

    // Fallback: the lock screen's foreground window is a CoreWindow.
    HWND fg = GetForegroundWindow();
    if (fg) {
      wchar_t cls[128] = {0};
      if (GetClassNameW(fg, cls, 127)) {
        const std::wstring_view cn {cls};
        if (cn == L"Windows.UI.Core.CoreWindow" || cn == L"LogonUI") {
          return true;
        }
      }
    }
    return false;
  }

  // -------------------------------------------------------------------------
  // UI-thread context (opaque in the header, defined here).
  // -------------------------------------------------------------------------
  struct ui_ctx_t {
    privacy_config_t config;
    image_t image;
    HANDLE ready = nullptr;
    std::atomic<bool> *stop = nullptr;
    std::atomic<bool> *affinity_ok = nullptr;
    std::atomic<int> *overlay_count = nullptr;
    HWND *first_hwnd = nullptr;
    DWORD thread_id = 0;
    result_e result = result_e::ok;
    std::string diag;
    std::vector<HWND> windows;
  };

  /** @brief Stretch the wallpaper to one monitor's DIB (nearest neighbour). */
  static bool paint_overlay(HWND hwnd, const RECT &mon, const image_t &img, std::string &diag) {
    int w = mon.right - mon.left;
    int h = mon.bottom - mon.top;
    if (w <= 0 || h <= 0 || img.w == 0 || img.h == 0) return false;

    HDC screen = GetDC(nullptr);
    HDC mem = CreateCompatibleDC(screen);
    BITMAPINFO bi = {};
    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = w;
    bi.bmiHeader.biHeight = -h;  // top-down
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;
    void *bits = nullptr;
    HBITMAP dib = CreateDIBSection(mem, &bi, DIB_RGB_COLORS, &bits, nullptr, 0);
    if (!dib || !bits) {
      diag = "CreateDIBSection failed";
      if (dib) DeleteObject(dib);
      DeleteDC(mem);
      ReleaseDC(nullptr, screen);
      return false;
    }
    BYTE *dst = (BYTE *) bits;
    for (int y = 0; y < h; y++) {
      UINT sy = (UINT) ((int64_t) y * img.h / h);
      for (int x = 0; x < w; x++) {
        UINT sx = (UINT) ((int64_t) x * img.w / w);
        const BYTE *s = img.bgra.data() + ((size_t) sy * img.w + sx) * 4;
        BYTE *d = dst + ((size_t) y * w + x) * 4;
        d[0] = s[0]; d[1] = s[1]; d[2] = s[2]; d[3] = 255;
      }
    }
    HGDIOBJ old = SelectObject(mem, dib);
    POINT pt = {mon.left, mon.top};
    POINT src = {0, 0};
    SIZE sz = {w, h};
    BLENDFUNCTION bf = {AC_SRC_OVER, 0, 255, AC_SRC_ALPHA};
    BOOL ok = UpdateLayeredWindow(hwnd, screen, &pt, &sz, mem, &src, 0, &bf, ULW_ALPHA);
    if (!ok) diag = "UpdateLayeredWindow failed: " + std::to_string(GetLastError());
    SelectObject(mem, old);
    DeleteObject(dib);
    DeleteDC(mem);
    ReleaseDC(nullptr, screen);
    return ok != FALSE;
  }

  /**
   * @brief Overlay HWNDs of the active session, readable from the IME helper.
   * Only touched on the overlay UI thread.
   */
  static std::vector<HWND> g_overlay_windows;

  /**
   * @brief Windows we cloak'd for the current session, so they can be restored.
   */
  static std::vector<HWND> g_cloaked_windows;

  /** @brief Whether the overlays are currently hidden because the session locked. */
  static bool g_session_locked = false;

  /**
   * @brief Force-hide every foreign window that DWM would compose above the overlay.
   *
   * Empirical finding on Windows 11 26200 (measured, not guessed):
   *   Microsoft Pinyin's candidate list is class
   *     "Microsoft.IME.UIManager.CandidateWindow.Host"
   *   hosted by the *focused application's* process (not TextInputHost.exe),
   *   with WS_EX_TOPMOST set and DWM_CLOAKED == 0.
   *   The shell's overflow flyout is "TopLevelWindowForOverflowXamlIsland",
   *   and third-party always-on-top tools (e.g. clocks) also sit above us.
   *
   * Those are XAML islands composed through DirectComposition, so re-asserting
   * HWND_TOPMOST with SetWindowPos does not move them below the overlay.  The
   * only reliable primitive is DWMWA_CLOAK (value 14), which forces DWM to
   * stop composing the window entirely - the same API the overlay itself uses
   * for capture exclusion.
   *
   * Cloaking is recorded in g_cloaked_windows and undone in
   * restore_cloaked_windows(), so nothing stays hidden after the session.
   */
  static void hide_ime_candidate_windows() {
    if (g_overlay_windows.empty()) return;

    struct ctx_t {
      std::vector<HWND> *ours;
      std::vector<RECT> rects;
      int cloaked = 0;
    } ctx;
    ctx.ours = &g_overlay_windows;
    for (HWND o : g_overlay_windows) {
      RECT r {};
      if (IsWindow(o) && GetWindowRect(o, &r)) ctx.rects.push_back(r);
    }
    if (ctx.rects.empty()) return;

    EnumWindows([](HWND hwnd, LPARAM p) -> BOOL {
      auto *c = (ctx_t *) p;
      if (!IsWindowVisible(hwnd)) return TRUE;

      // never touch our own overlays
      for (HWND o : *c->ours) {
        if (o == hwnd) return TRUE;
      }

      wchar_t cls[256] = {0};
      GetClassNameW(hwnd, cls, 255);
      const std::wstring_view cn {cls};

      // Shell chrome that legitimately lives above everything. Cloaking the
      // taskbar would make the desktop look broken, and the wallpaper already
      // covers it from the client's point of view.
      static const std::wstring_view kAllowExact[] = {
        L"Shell_TrayWnd", L"Shell_SecondaryTrayWnd", L"Progman", L"WorkerW",
        L"ForegroundStaging", L"MultitaskingViewFrame",
        L"Windows.UI.Core.CoreWindow", L"SunshinePrivacyOverlay"
      };
      for (auto a : kAllowExact) {
        if (cn == a) return TRUE;
      }
      // Never cloak the secure/credential surfaces.
      if (cn.find(L"Credential") != std::wstring_view::npos ||
          cn.find(L"LogonUI") != std::wstring_view::npos ||
          cn.find(L"LockApp") != std::wstring_view::npos) {
        return TRUE;
      }

      // Only windows the compositor actually draws above us matter. Topmost is
      // the necessary condition; without it DWM already keeps them below.
      if (!(GetWindowLongW(hwnd, GWL_EXSTYLE) & WS_EX_TOPMOST)) return TRUE;

      RECT wr {};
      if (!GetWindowRect(hwnd, &wr)) return TRUE;
      if (wr.right <= wr.left || wr.bottom <= wr.top) return TRUE;

      bool overlaps = false;
      for (const RECT &or_ : c->rects) {
        if (wr.left < or_.right && wr.right > or_.left &&
            wr.top < or_.bottom && wr.bottom > or_.top) {
          overlaps = true;
          break;
        }
      }
      if (!overlaps) return TRUE;

      // Already cloaked by us? Skip (also avoids redundant DWM calls).
      for (HWND w : g_cloaked_windows) {
        if (w == hwnd) return TRUE;
      }

      auto &apis = apis_t::instance();
      if (apis.dwm_set_attr) {
        BOOL cloak = TRUE;
        HRESULT hr = apis.dwm_set_attr(hwnd, kDwmwaCloak, &cloak, sizeof(cloak));
        if (SUCCEEDED(hr)) {
          g_cloaked_windows.push_back(hwnd);
          c->cloaked++;
          BOOST_LOG(info) << "PrivacyScreen: cloaked topmost window above overlay: class="sv
                          << utf_utils::to_utf8(std::wstring(cls)) << " title="sv
                          << [&] {
                               wchar_t t[128] = {0};
                               GetWindowTextW(hwnd, t, 127);
                               return utf_utils::to_utf8(std::wstring(t));
                             }();
        }
      }
      return TRUE;
    }, (LPARAM) &ctx);
  }

  /**
   * @brief Un-cloak every window hidden by hide_ime_candidate_windows().
   * Called when the overlay is torn down so nothing is left invisible.
   */
  static void restore_cloaked_windows() {
    auto &apis = apis_t::instance();
    int restored = 0;
    for (HWND hwnd : g_cloaked_windows) {
      if (IsWindow(hwnd) && apis.dwm_set_attr) {
        BOOL uncloak = FALSE;
        if (SUCCEEDED(apis.dwm_set_attr(hwnd, kDwmwaCloak, &uncloak, sizeof(uncloak)))) {
          restored++;
        }
      }
    }
    if (!g_cloaked_windows.empty()) {
      BOOST_LOG(info) << "PrivacyScreen: restored "sv << restored << " cloaked window(s)"sv;
    }
    g_cloaked_windows.clear();
  }

  static LRESULT CALLBACK overlay_wnd_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    switch (msg) {
      // WS_EX_TRANSPARENT already makes the window click-through for other
      // processes; HTTRANSPARENT additionally covers same-process hit tests.
      case WM_NCHITTEST: return HTTRANSPARENT;
      case WM_MOUSEACTIVATE: return MA_NOACTIVATE;
      case WM_ERASEBKGND:
      case WM_PAINT: return 0;  // content is from UpdateLayeredWindow, not WM_PAINT
      case WM_DISPLAYCHANGE:
        BOOST_LOG(debug) << "PrivacyScreen: WM_DISPLAYCHANGE"sv;
        return 0;
      case WM_TIMER:
        if (wparam == kImeHideTimerId) {
          // If the workstation got locked while the overlay is up, hide the
          // overlays so the physical screen and the capture both show the
          // password prompt. They come back when the session is unlocked.
          if (is_session_locked()) {
            if (!g_session_locked) {
              g_session_locked = true;
              BOOST_LOG(info) << "PrivacyScreen: session locked, hiding overlay to expose login UI"sv;
              for (HWND w : g_overlay_windows) {
                if (IsWindow(w)) ShowWindow(w, SW_HIDE);
              }
            }
            return 0;
          }
          if (g_session_locked) {
            g_session_locked = false;
            BOOST_LOG(info) << "PrivacyScreen: session unlocked, restoring overlay"sv;
            for (HWND w : g_overlay_windows) {
              if (IsWindow(w)) {
                ShowWindow(w, SW_SHOWNOACTIVATE);
                SetWindowPos(w, HWND_TOPMOST, 0, 0, 0, 0,
                             SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_SHOWWINDOW);
              }
            }
          }
          // Keep our topmost overlay above freshly created IME candidate
          // windows (UU ime_candidate_window_hider.cpp does the same job).
          hide_ime_candidate_windows();
          return 0;
        }
        return 0;
      case WM_APP_PRIVACY_QUIT:
        PostQuitMessage(0);
        return 0;
      case WM_CLOSE: return 0;  // only the manager destroys these windows
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
  }

  /**
   * @brief UI thread: per-monitor DPI awareness, GDI+ decode, create + paint
   * one layered topmost window per monitor, then pump until WM_APP_PRIVACY_QUIT.
   */
  static DWORD WINAPI ui_thread_proc(LPVOID param) {
    ui_ctx_t *c = (ui_ctx_t *) param;
    c->thread_id = GetCurrentThreadId();
    auto &apis = apis_t::instance();

    // The overlay must cover each monitor in *physical pixels*. Calling the
    // process-wide SetProcessDpiAwarenessContext here is useless: Sunshine has
    // already created windows, so the process DPI awareness is locked in and
    // the call fails with ERROR_ACCESS_DENIED, leaving this thread DPI-unaware.
    // That made EnumDisplayMonitors report scaled (e.g. 1536x864 at 125%)
    // rectangles and the overlay covered only part of the screen.
    // SetThreadDpiAwarenessContext affects only the calling thread and works
    // after process startup, which is exactly what we need.
    // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = (HANDLE)-4
    if (apis.set_thread_dpi_ctx) {
      apis.set_thread_dpi_ctx((void *) -4);
    } else if (apis.set_dpi_ctx) {
      apis.set_dpi_ctx((void *) -4);
    } else {
      SetProcessDPIAware();
    }

    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = &overlay_wnd_proc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.lpszClassName = kOverlayClass;
    wc.hCursor = nullptr;
    if (!RegisterClassExW(&wc)) {
      c->result = result_e::window_failed;
      c->diag = "RegisterClassExW failed: " + std::to_string(GetLastError());
      SetEvent(c->ready);
      return 1;
    }

    bool image_ok = false;
    c->image = make_wallpaper(c->config, image_ok);
    if (!image_ok) {
      BOOST_LOG(warning) << "PrivacyScreen: wallpaper unavailable, degraded to solid colour"sv;
      c->result = result_e::image_failed;  // non-fatal
    }

    // Cursor handling: DO NOT call MagShowSystemCursor(FALSE) here.
    // MagShowSystemCursor hides the *system* cursor globally, and DXGI Desktop
    // Duplication captures that very cursor, so the remote client would lose
    // its pointer too. UU only needs the physical screen cursor hidden, which
    // is unnecessary because our opaque overlay already covers it. The
    // hide_cursor option therefore only suppresses the overlay window's own
    // cursor, never the system one.
    (void) apis.mag_init;
    (void) apis.mag_show_cursor;

    // One overlay per monitor. Enumerated on this (UI) thread, which is
    // per-monitor-v2 DPI aware, so the rectangles are physical pixels.
    EnumDisplayMonitors(nullptr, nullptr,
                        [](HMONITOR, HDC, LPRECT rect, LPARAM p) -> BOOL {
                          ui_ctx_t *c = (ui_ctx_t *) p;
                          auto &a = apis_t::instance();
                          int w = rect->right - rect->left;
                          int h = rect->bottom - rect->top;
                          // WS_EX_TRANSPARENT is required for real click-through:
                          // WM_NCHITTEST/HTTRANSPARENT only affects same-process
                          // hit testing, so without this flag the overlay would
                          // swallow mouse input destined for the remote session
                          // and for any local pointing device.
                          DWORD ex = WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE |
                                     WS_EX_LAYERED | WS_EX_TRANSPARENT;
                          HWND hwnd = CreateWindowExW(ex, kOverlayClass, L"Sunshine Privacy Screen",
                                                      WS_POPUP, rect->left, rect->top, w, h,
                                                      nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);
                          if (!hwnd) {
                            c->diag = "CreateWindowExW failed: " + std::to_string(GetLastError());
                            return FALSE;
                          }

                          // CRITICAL: set affinity BEFORE showing. Without it the
                          // privacy image would leak into the remote capture.
                          bool aff = false;
                          if (a.set_affinity) {
                            aff = a.set_affinity(hwnd, kAffinityExclude) != FALSE;
                            if (aff && a.get_affinity) {
                              DWORD got = 0xFFFFFFFF;
                              if (!a.get_affinity(hwnd, &got) || got != kAffinityExclude) {
                                aff = false;
                                c->diag = "affinity read-back mismatch";
                              }
                            }
                          }
                          if (!aff) {
                            DestroyWindow(hwnd);
                            c->result = result_e::affinity_failed;
                            if (c->diag.empty()) c->diag = "SetWindowDisplayAffinity failed";
                            return FALSE;
                          }

                          // Second layer of defence (UU 实证): DWMWA_CLOAK with
                          // BOOL TRUE, size 4. Non-fatal when unavailable (older
                          // DWM); SWDA read-back above is the hard requirement.
                          if (a.dwm_set_attr) {
                            BOOL cloak = TRUE;
                            HRESULT hr = a.dwm_set_attr(hwnd, kDwmwaCloak, &cloak, sizeof(cloak));
                            if (FAILED(hr)) {
                              BOOST_LOG(debug) << "PrivacyScreen: DwmSetWindowAttribute(DWMWA_CLOAK) unavailable ["sv
                                               << (unsigned) hr << ']';
                            }
                          }

                          ShowWindow(hwnd, SW_SHOWNOACTIVATE);
                          SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0,
                                       SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_SHOWWINDOW);
                          std::string d;
                          paint_overlay(hwnd, *rect, c->image, d);
                          c->windows.push_back(hwnd);
                          g_overlay_windows.push_back(hwnd);
                          if (c->windows.size() == 1) *c->first_hwnd = hwnd;
                          c->overlay_count->store((int) c->windows.size());
                          c->affinity_ok->store(true);
                          BOOST_LOG(debug) << "PrivacyScreen: overlay "sv
                                           << (int) c->windows.size() << " rect="sv
                                           << (int) rect->left << ',' << (int) rect->top << ' '
                                           << (int) (rect->right - rect->left) << 'x'
                                           << (int) (rect->bottom - rect->top);
                          return TRUE;
                        },
                        (LPARAM) c);

    // Sanity check: the union of overlay rects must cover the whole virtual
    // screen. A mismatch means DPI awareness did not take effect and part of
    // the physical desktop would stay visible.
    {
      int vx = GetSystemMetrics(SM_XVIRTUALSCREEN);
      int vy = GetSystemMetrics(SM_YVIRTUALSCREEN);
      int vw = GetSystemMetrics(SM_CXVIRTUALSCREEN);
      int vh = GetSystemMetrics(SM_CYVIRTUALSCREEN);
      long covered = 0;
      for (HWND w : c->windows) {
        RECT r {};
        if (IsWindow(w) && GetWindowRect(w, &r)) {
          covered += (long) (r.right - r.left) * (r.bottom - r.top);
        }
      }
      long total = (long) vw * vh;
      BOOST_LOG(info) << "PrivacyScreen: virtual screen "sv << vx << ',' << vy << ' '
                      << vw << 'x' << vh << ", covered="sv << covered
                      << " ("sv << (total ? (int) (100.0 * covered / total) : 0) << "%)"sv;
      if (total > 0 && covered * 100 / total < 95) {
        BOOST_LOG(warning) << "PrivacyScreen: overlay does not fully cover the desktop; "
                              "DPI awareness may not be applied"sv;
      }
    }

    SetEvent(c->ready);

    // If the session was already locked when we started, keep the freshly
    // created overlays hidden until the guard timer detects the unlock.
    if (is_session_locked()) {
      g_session_locked = true;
      for (HWND w : c->windows) {
        if (IsWindow(w)) ShowWindow(w, SW_HIDE);
      }
      BOOST_LOG(info) << "PrivacyScreen: overlays created but hidden (session locked)"sv;
    }

    // Poll for IME candidate windows: they are created/re-shown by the IME at
    // unpredictable moments and are always topmost, so they would otherwise
    // float above the privacy wallpaper (UU ime_candidate_window_hider.cpp).
    UINT_PTR timer = 0;
    if (!c->windows.empty()) {
      // 50 ms keeps IME candidate popups from being visible for more than a
      // couple of frames on the physical screen.
      timer = SetTimer(c->windows.front(), kImeHideTimerId, 50, nullptr);
      if (timer) {
        BOOST_LOG(info) << "PrivacyScreen: topmost-guard timer armed (50 ms)"sv;
      } else {
        BOOST_LOG(warning) << "PrivacyScreen: SetTimer failed, IME popups may float above the overlay"sv;
      }
    }

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
      TranslateMessage(&msg);
      DispatchMessageW(&msg);
    }

    if (timer && !c->windows.empty()) KillTimer(c->windows.front(), timer);
    g_session_locked = false;
    // Un-hide anything we cloaked before we go away.
    restore_cloaked_windows();
    g_overlay_windows.clear();
    for (HWND w : c->windows) if (IsWindow(w)) DestroyWindow(w);
    c->windows.clear();
    UnregisterClassW(kOverlayClass, GetModuleHandleW(nullptr));
    c->overlay_count->store(0);
    c->affinity_ok->store(false);
    return 0;
  }

  // -------------------------------------------------------------------------
  // privacy_screen_manager_t
  // -------------------------------------------------------------------------
  privacy_screen_manager_t &privacy_screen_manager_t::instance() {
    static privacy_screen_manager_t inst;
    return inst;
  }

  privacy_screen_manager_t::~privacy_screen_manager_t() {
    std::unique_lock<std::mutex> lock(mutex_);
    disable_locked(lock, false);
  }

  bool privacy_screen_manager_t::supports_exclusion() const {
    auto &a = apis_t::instance();
    if (!a.set_affinity || !a.get_affinity) {
      BOOST_LOG(warning) << "PrivacyScreen: SetWindowDisplayAffinity unavailable; privacy screen would leak into capture"sv;
      return false;
    }
    return true;
  }

  void privacy_screen_manager_t::configure(const privacy_config_t &cfg) {
    std::lock_guard lock(mutex_);
    config_ = cfg;
  }

  bool privacy_screen_manager_t::active() const { return active_.load(); }
  int privacy_screen_manager_t::overlay_count() const { return overlay_count_.load(); }

  /** @brief Join the UI thread and release its context (lock may be held). */
  static void join_and_release(std::thread &t, void *&ctx) {
    if (t.joinable() && t.get_id() != std::this_thread::get_id()) t.join();
    delete (ui_ctx_t *) ctx;
    ctx = nullptr;
  }

  /**
   * @brief Ask the UI thread to quit.
   * Only a thread message is used: it needs no window handle, so there is no
   * race with the UI thread still populating ctx->windows.  GetMessageW returns
   * 0 for WM_QUIT, which ends the pump and runs the thread's cleanup.
   */
  static void signal_stop(void *ctx) {
    if (!ctx) return;
    ui_ctx_t *c = (ui_ctx_t *) ctx;
    if (c->thread_id) PostThreadMessageW(c->thread_id, WM_QUIT, 0, 0);
  }

  result_e privacy_screen_manager_t::enable_locked(std::unique_lock<std::mutex> &lock) {
    if (active_.load()) return result_e::already_active;
    if (!config_.enabled) return result_e::ok;  // disabled by configuration

    if (!supports_exclusion()) return result_e::unsupported_os;

    // If the session is locked, still build the overlay windows but keep them
    // HIDDEN.  They must exist so the guard timer can show them the moment the
    // user unlocks; returning early here left a reconnect-after-lock session
    // with no overlay at all, so the wallpaper never came back.
    const bool start_locked = is_session_locked();
    if (start_locked) {
      BOOST_LOG(info) << "PrivacyScreen: session is locked; creating hidden overlay "
                         "to be revealed after unlock"sv;
      g_session_locked = true;
    }

    // UU applies display-topology changes first (DisplayLayout::tryOpen with
    // PrivacyPostAction&) and paints afterwards; settle briefly.
    if (config_.settle_delay.count() > 0) {
      lock.unlock();
      std::this_thread::sleep_for(config_.settle_delay);
      lock.lock();
    }

    ready_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    stop_requested_.store(false);
    auto *ctx = new ui_ctx_t {};
    ctx->config = config_;
    ctx->ready = ready_event_;
    ctx->stop = &stop_requested_;
    ctx->affinity_ok = &affinity_ok_;
    ctx->overlay_count = &overlay_count_;
    ctx->first_hwnd = &hwnd_;
    ui_ctx_ = ctx;

    ui_thread_ = std::thread([ctx]() { ui_thread_proc(ctx); });
    // The UI thread records its own GetCurrentThreadId() in ctx->thread_id as
    // its very first action (before SetEvent(ready)).  Do NOT use
    // std::thread::native_handle() here: under MinGW it is a pthread_t, not a
    // Win32 HANDLE, so GetThreadId() would be invalid.

    lock.unlock();
    DWORD wait = WaitForSingleObject(ready_event_, 5000);
    lock.lock();

    bool failed = (wait != WAIT_OBJECT_0) || overlay_count_.load() == 0 || !affinity_ok_.load();
    if (failed) {
      BOOST_LOG(error) << "PrivacyScreen: enable failed ("sv << ctx->diag << ")"sv;
      signal_stop(ctx);
      lock.unlock();
      join_and_release(ui_thread_, ui_ctx_);
      lock.lock();
      if (ready_event_) { CloseHandle(ready_event_); ready_event_ = nullptr; }
      return wait != WAIT_OBJECT_0 ? result_e::window_failed : result_e::affinity_failed;
    }

    active_.store(true);
    BOOST_LOG(info) << "PrivacyScreen: active, overlays="sv << overlay_count_.load()
                    << ", WDA_EXCLUDEFROMCAPTURE verified"sv;
    return ctx->result == result_e::image_failed ? result_e::image_failed  // non-fatal
                                                 : result_e::ok;
  }

  result_e privacy_screen_manager_t::enable() {
    std::unique_lock<std::mutex> lock(mutex_);
    return enable_locked(lock);
  }

  result_e privacy_screen_manager_t::disable_locked(std::unique_lock<std::mutex> &lock, bool lock_requested) {
    if (!active_.load() && !ui_thread_.joinable()) return result_e::not_active;

    stop_requested_.store(true);
    signal_stop(ui_ctx_);

    lock.unlock();
    join_and_release(ui_thread_, ui_ctx_);
    lock.lock();

    if (ready_event_) { CloseHandle(ready_event_); ready_event_ = nullptr; }
    ui_thread_id_ = 0;
    hwnd_ = nullptr;
    active_.store(false);
    overlay_count_.store(0);
    affinity_ok_.store(false);
    BOOST_LOG(info) << "PrivacyScreen: overlay removed, physical display restored"sv;

    result_e r = result_e::ok;
    if (lock_requested) {
      r = remote_lock_manager_t::instance().request_lock(true);
      if (r != result_e::ok) BOOST_LOG(warning) << "PrivacyScreen: lock on disable failed ["sv << result_name(r) << ']';
    }
    return r;
  }

  result_e privacy_screen_manager_t::disable(bool lock_requested) {
    std::unique_lock<std::mutex> lock(mutex_);
    return disable_locked(lock, lock_requested);
  }

  // -------------------------------------------------------------------------
  // remote_lock_manager_t
  // -------------------------------------------------------------------------
  remote_lock_manager_t &remote_lock_manager_t::instance() {
    static remote_lock_manager_t inst;
    return inst;
  }

  result_e remote_lock_manager_t::do_lock() {
    if (!LockWorkStation()) {
      BOOST_LOG(error) << "RemoteLock: LockWorkStation failed ["sv << GetLastError() << ']';
      return result_e::lock_failed;
    }
    BOOST_LOG(info) << "RemoteLock: workstation locked"sv;
    return result_e::ok;
  }

  result_e remote_lock_manager_t::request_lock(bool /*from_stream_session*/) {
    // A stream-session action is already authenticated by the RTSP layer; a
    // Web UI action must have passed authenticate()+CSRF before reaching here.
    if (!streaming_.load()) {
      pending_.store(true);  // latch: flush on next session start
      BOOST_LOG(info) << "RemoteLock: lock latched (no active session)"sv;
      return result_e::ok;
    }
    pending_.store(false);
    return do_lock();
  }

  void remote_lock_manager_t::on_session_start() {
    streaming_.store(true);
    if (pending_.exchange(false)) {
      BOOST_LOG(info) << "RemoteLock: flushing latched lock on session start"sv;
      do_lock();
    }
  }

  void remote_lock_manager_t::on_session_stop(const privacy_config_t &cfg) {
    streaming_.store(false);
    if (cfg.lock_on_disconnect) do_lock();  // UU handleDisablePrivacyModeAndLock
  }

  bool remote_lock_manager_t::pending() const { return pending_.load(); }
  void remote_lock_manager_t::clear_pending() { pending_.store(false); }

}  // namespace platf::privacy
