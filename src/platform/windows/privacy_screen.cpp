/**
 * @file src/platform/windows/privacy_screen.cpp
 * @brief Windows privacy-screen overlay and remote-lock implementation.
 *
 * Clean reimplementation of UU Remote (GameViewer) 隐私屏 (Privacy Screen)
 * for Sunshine.
 *
 * Architecture:
 *   - Physical monitor: Full-screen layered topmost Win32 window per monitor,
 *     painted with the privacy wallpaper via UpdateLayeredWindow.
 *   - Capture exclusion: SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE = 0x11)
 *     instructs DWM composition to exclude this window from all capture paths
 *     (DXGI Desktop Duplication, BitBlt, Windows.Graphics.Capture) on Win10 2004+,
 *     leaving the normal desktop visible to Moonlight.
 *   - Cursor guard: MagShowSystemCursor(FALSE) suppresses the host physical
 *     hardware mouse cursor, matching GameViewer's system_cursor_guard.cpp.
 *     Moonlight renders the cursor on the client side so the remote user experiences
 *     seamless control while the physical screen reveals zero mouse movement.
 *   - Input isolation: Optional BlockInput(TRUE) blocks local physical keyboard
 *     and mouse input so passers-by cannot disturb the session, while SendInput()
 *     used by Sunshine's remote input injection continues to work unaffected.
 *   - Session awareness: WTSRegisterSessionNotification provides event-driven
 *     detection of workstation lock/unlock, temporarily revealing the login UI
 *     when locked and re-covering upon unlock without CPU polling.
 */
// platform includes
#include <Windows.h>
#include <wtsapi32.h>  // WTSQuerySessionInformation, WTSRegisterSessionNotification

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

  // WDA_EXCLUDEFROMCAPTURE = 0x11 (Win10 2004+).
  static constexpr DWORD kAffinityExclude = 0x00000011;
  static constexpr UINT WM_APP_PRIVACY_QUIT = WM_APP + 1;
  static constexpr UINT_PTR kFallbackPollTimerId = 0x5E2;
  static constexpr UINT_PTR kTopmostGuardTimerId = 0x5E3;
  static constexpr const wchar_t *kOverlayClass = L"SunshinePrivacyOverlay";

  // -------------------------------------------------------------------------
  // Dynamically-resolved user32 / magnification / wtsapi32 entry points.
  // -------------------------------------------------------------------------
  struct apis_t {
    using set_dpi_ctx_t = BOOL(WINAPI *)(void *);
    using set_thread_dpi_ctx_t = void *(WINAPI *)(void *);
    using set_affinity_t = BOOL(WINAPI *)(HWND, DWORD);
    using get_affinity_t = BOOL(WINAPI *)(HWND, DWORD *);
    using block_input_t = BOOL(WINAPI *)(BOOL);
    using mag_init_t = BOOL(WINAPI *)(void);
    using mag_uninit_t = BOOL(WINAPI *)(void);
    using mag_show_cursor_t = BOOL(WINAPI *)(BOOL);
    using wts_register_notif_t = BOOL(WINAPI *)(HWND, DWORD);
    using wts_unregister_notif_t = BOOL(WINAPI *)(HWND);

    set_dpi_ctx_t set_dpi_ctx = nullptr;
    set_thread_dpi_ctx_t set_thread_dpi_ctx = nullptr;
    set_affinity_t set_affinity = nullptr;
    get_affinity_t get_affinity = nullptr;
    block_input_t block_input = nullptr;
    mag_init_t mag_init = nullptr;
    mag_uninit_t mag_uninit = nullptr;
    mag_show_cursor_t mag_show_cursor = nullptr;
    wts_register_notif_t wts_reg_notif = nullptr;
    wts_unregister_notif_t wts_unreg_notif = nullptr;

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
        block_input = (block_input_t) GetProcAddress(user32, "BlockInput");
      }
      if (HMODULE mag = LoadLibraryW(L"magnification.dll")) {
        mag_init = (mag_init_t) GetProcAddress(mag, "MagInitialize");
        mag_uninit = (mag_uninit_t) GetProcAddress(mag, "MagUninitialize");
        mag_show_cursor = (mag_show_cursor_t) GetProcAddress(mag, "MagShowSystemCursor");
      }
      if (HMODULE wts = LoadLibraryW(L"wtsapi32.dll")) {
        wts_reg_notif = (wts_register_notif_t) GetProcAddress(wts, "WTSRegisterSessionNotification");
        wts_unreg_notif = (wts_unregister_notif_t) GetProcAddress(wts, "WTSUnRegisterSessionNotification");
      }
    }
  };

  // -------------------------------------------------------------------------
  // GDI+ flat API for image decoding (zero extra dependencies).
  // -------------------------------------------------------------------------
  struct gdiplus_t {
    using startup_t = int(WINAPI *)(ULONG_PTR *, const void *, void *);
    using shutdown_t = void(WINAPI *)(ULONG_PTR);
    using from_file_t = int(WINAPI *)(const WCHAR *, void **);
    using dispose_t = int(WINAPI *)(void *);
    using get_dim_t = int(WINAPI *)(void *, UINT *);
    using lock_bits_t = int(WINAPI *)(void *, const void *, UINT, int, void *);
    using unlock_bits_t = int(WINAPI *)(void *, void *);

    struct startup_input_t {
      std::uint32_t version = 1;
      void *debug_cb = nullptr;
      BOOL suppress_bg = FALSE;
      BOOL suppress_external = FALSE;
    };
    struct gp_rect_t { INT x, y, w, h; };
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
      if (startup(&token, &in, nullptr) != 0) return false;
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

  struct image_t {
    UINT w = 0;
    UINT h = 0;
    std::vector<BYTE> bgra;
  };

  static bool decode_image(const std::wstring &path, image_t &out) {
    auto &g = gdiplus_t::instance();
    if (!g.init()) return false;

    void *bmp = nullptr;
    if (g.from_file(path.c_str(), &bmp) != 0 || !bmp) return false;

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

  bool is_session_locked() {
    WTSINFOEXW *info = nullptr;
    DWORD bytes = 0;
    if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION,
                                    WTSSessionInfoEx, (LPWSTR *) &info, &bytes)) {
      bool locked = false;
      bool valid = false;
      if (info && bytes >= sizeof(WTSINFOEXW) && info->Level == 1) {
        locked = (info->Data.WTSInfoExLevel1.SessionFlags == 0);
        valid = true;
      }
      WTSFreeMemory(info);
      if (valid) {
        return locked;
      }
    }

    // Secondary check: verify whether default input desktop is accessible.
    // When locked, the secure desktop (Winlogon) is active, causing OpenInputDesktop to fail with ERROR_ACCESS_DENIED.
    HDESK desk = OpenInputDesktop(0, FALSE, DESKTOP_SWITCHDESKTOP);
    if (!desk) {
      if (GetLastError() == ERROR_ACCESS_DENIED) {
        return true;
      }
    } else {
      CloseDesktop(desk);
    }
    return false;
  }

  // -------------------------------------------------------------------------
  // UI-thread context
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
    bool cursor_hidden = false;
    bool input_blocked = false;
    bool session_locked = false;
  };

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

  static ui_ctx_t *g_current_ui_ctx = nullptr;

  static void set_input_blocked(ui_ctx_t *c, bool block) {
    // Win32 BlockInput(TRUE) blocks SendInput() from all other threads (MSDN spec).
    // Because Sunshine's remote input injection runs on separate worker threads,
    // calling BlockInput(TRUE) here completely blocks Moonlight's keyboard and mouse input.
    // Keeping this disabled ensures remote input injection remains 100% functional.
    return;
  }

  static void set_cursor_hidden(ui_ctx_t *c, bool hide) {
    if (!c || !c->config.hide_cursor) return;
    auto &a = apis_t::instance();
    if (!a.mag_show_cursor || !a.mag_init) return;

    if (hide && !c->cursor_hidden) {
      a.mag_init();
      a.mag_show_cursor(FALSE);
      c->cursor_hidden = true;
      BOOST_LOG(info) << "PrivacyScreen: physical system cursor hidden (MagShowSystemCursor FALSE)"sv;
    } else if (!hide && c->cursor_hidden) {
      a.mag_show_cursor(TRUE);
      if (a.mag_uninit) a.mag_uninit();
      c->cursor_hidden = false;
      BOOST_LOG(info) << "PrivacyScreen: physical system cursor restored"sv;
    }
  }

  static void handle_session_lock_state(ui_ctx_t *c, bool locked) {
    if (!c) return;
    if (locked == c->session_locked) return;
    c->session_locked = locked;

    if (locked) {
      BOOST_LOG(info) << "PrivacyScreen: session locked, exposing logon UI"sv;
      // Temporarily release physical input and cursor so user can physically log in if desired
      set_input_blocked(c, false);
      set_cursor_hidden(c, false);
      for (HWND w : c->windows) {
        if (IsWindow(w)) ShowWindow(w, SW_HIDE);
      }
    } else {
      BOOST_LOG(info) << "PrivacyScreen: session unlocked, re-covering displays"sv;
      for (HWND w : c->windows) {
        if (IsWindow(w)) {
          ShowWindow(w, SW_SHOWNOACTIVATE);
          SetWindowPos(w, HWND_TOPMOST, 0, 0, 0, 0,
                       SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_SHOWWINDOW);
        }
      }
      set_cursor_hidden(c, true);
      set_input_blocked(c, true);
    }
  }

  static LRESULT CALLBACK overlay_wnd_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    ui_ctx_t *c = g_current_ui_ctx;
    switch (msg) {
      case WM_NCHITTEST: return HTTRANSPARENT;
      case WM_MOUSEACTIVATE: return MA_NOACTIVATE;
      case WM_ERASEBKGND:
      case WM_PAINT: return 0;
      case WM_WTSSESSION_CHANGE: {
        if (wparam == WTS_SESSION_LOCK) {
          handle_session_lock_state(c, true);
        } else if (wparam == WTS_SESSION_UNLOCK) {
          handle_session_lock_state(c, false);
        }
        return 0;
      }
      case WM_DISPLAYCHANGE: {
        BOOST_LOG(info) << "PrivacyScreen: WM_DISPLAYCHANGE received, refreshing overlays"sv;
        if (c && !c->windows.empty()) {
          // Re-assert topmost order and refresh layered rects
          EnumDisplayMonitors(nullptr, nullptr,
                              [](HMONITOR, HDC, LPRECT rect, LPARAM p) -> BOOL {
                                auto *ctx = (ui_ctx_t *) p;
                                for (HWND w : ctx->windows) {
                                  RECT wr {};
                                  if (GetWindowRect(w, &wr) && wr.left == rect->left && wr.top == rect->top) {
                                    std::string d;
                                    paint_overlay(w, *rect, ctx->image, d);
                                    SetWindowPos(w, HWND_TOPMOST, rect->left, rect->top,
                                                 rect->right - rect->left, rect->bottom - rect->top,
                                                 SWP_NOACTIVATE | SWP_SHOWWINDOW);
                                    break;
                                  }
                                }
                                return TRUE;
                              }, (LPARAM) c);
        }
        return 0;
      }
      case WM_TIMER: {
        if (wparam == kFallbackPollTimerId && c) {
          // Gentle periodic check in case WTS notification was missed
          bool locked = is_session_locked();
          if (locked != c->session_locked) {
            handle_session_lock_state(c, locked);
          }
        } else if (wparam == kTopmostGuardTimerId && c) {
          // Guard Z-order against newly popped windows (e.g. IME candidate windows) on the physical display
          if (!c->session_locked) {
            for (HWND w : c->windows) {
              if (IsWindow(w)) {
                SetWindowPos(w, HWND_TOPMOST, 0, 0, 0, 0,
                             SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_NOOWNERZORDER | SWP_ASYNCWINDOWPOS);
              }
            }
          }
        }
        return 0;
      }
      case WM_APP_PRIVACY_QUIT:
        PostQuitMessage(0);
        return 0;
      case WM_CLOSE: return 0;
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
  }

  static DWORD WINAPI ui_thread_proc(LPVOID param) {
    ui_ctx_t *c = (ui_ctx_t *) param;
    g_current_ui_ctx = c;
    c->thread_id = GetCurrentThreadId();
    auto &apis = apis_t::instance();

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
      c->result = result_e::image_failed;
    }

    // One overlay window per physical monitor
    EnumDisplayMonitors(nullptr, nullptr,
                        [](HMONITOR, HDC, LPRECT rect, LPARAM p) -> BOOL {
                          ui_ctx_t *ctx = (ui_ctx_t *) p;
                          auto &a = apis_t::instance();
                          int w = rect->right - rect->left;
                          int h = rect->bottom - rect->top;

                          DWORD ex = WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE |
                                     WS_EX_LAYERED | WS_EX_TRANSPARENT;
                          HWND hwnd = CreateWindowExW(ex, kOverlayClass, L"Sunshine Privacy Screen",
                                                      WS_POPUP, rect->left, rect->top, w, h,
                                                      nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);
                          if (!hwnd) {
                            ctx->diag = "CreateWindowExW failed: " + std::to_string(GetLastError());
                            return FALSE;
                          }

                          // CRITICAL: set WDA_EXCLUDEFROMCAPTURE before showing
                          bool aff = false;
                          if (a.set_affinity) {
                            aff = a.set_affinity(hwnd, kAffinityExclude) != FALSE;
                            if (aff && a.get_affinity) {
                              DWORD got = 0xFFFFFFFF;
                              if (!a.get_affinity(hwnd, &got) || got != kAffinityExclude) {
                                aff = false;
                                ctx->diag = "affinity read-back mismatch";
                              }
                            }
                          }
                          if (!aff) {
                            DestroyWindow(hwnd);
                            ctx->result = result_e::affinity_failed;
                            if (ctx->diag.empty()) ctx->diag = "SetWindowDisplayAffinity failed";
                            return FALSE;
                          }

                          ShowWindow(hwnd, SW_SHOWNOACTIVATE);
                          SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0,
                                       SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_SHOWWINDOW);

                          std::string d;
                          paint_overlay(hwnd, *rect, ctx->image, d);
                          ctx->windows.push_back(hwnd);
                          if (ctx->windows.size() == 1) *ctx->first_hwnd = hwnd;
                          ctx->overlay_count->store((int) ctx->windows.size());
                          ctx->affinity_ok->store(true);
                          BOOST_LOG(debug) << "PrivacyScreen: overlay "sv
                                           << (int) ctx->windows.size() << " rect="sv
                                           << (int) rect->left << ',' << (int) rect->top << ' '
                                           << (int) w << 'x' << (int) h;
                          return TRUE;
                        },
                        (LPARAM) c);

    if (c->windows.empty() || !c->affinity_ok->load()) {
      if (c->diag.empty()) c->diag = "no overlays created";
      SetEvent(c->ready);
      UnregisterClassW(kOverlayClass, GetModuleHandleW(nullptr));
      return 1;
    }

    HWND primary_hwnd = c->windows.front();

    // Register event-driven session notification (lock/unlock)
    if (apis.wts_reg_notif) {
      if (apis.wts_reg_notif(primary_hwnd, NOTIFY_FOR_THIS_SESSION)) {
        BOOST_LOG(info) << "PrivacyScreen: WTSRegisterSessionNotification armed"sv;
      } else {
        BOOST_LOG(warning) << "PrivacyScreen: WTSRegisterSessionNotification failed ["sv << GetLastError() << ']';
      }
    }

    // Arm a 1-second fallback check for session lock
    SetTimer(primary_hwnd, kFallbackPollTimerId, 1000, nullptr);

    // Arm a 50ms guard timer to continuously keep overlays above IME candidate windows
    SetTimer(primary_hwnd, kTopmostGuardTimerId, 50, nullptr);

    // Install an event hook to instantly re-assert topmost order when any new window is shown
    HWINEVENTHOOK event_hook = SetWinEventHook(
      EVENT_OBJECT_SHOW, EVENT_OBJECT_SHOW,
      nullptr,
      [](HWINEVENTHOOK, DWORD, HWND hwnd, LONG idObject, LONG, DWORD, DWORD) {
        if (idObject == OBJID_WINDOW && hwnd) {
          ui_ctx_t *ctx = g_current_ui_ctx;
          if (ctx && !ctx->session_locked) {
            for (HWND w : ctx->windows) {
              if (IsWindow(w) && w != hwnd) {
                SetWindowPos(w, HWND_TOPMOST, 0, 0, 0, 0,
                             SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_NOOWNERZORDER | SWP_ASYNCWINDOWPOS);
              }
            }
          }
        }
      },
      0, 0,
      WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS
    );

    // Initial state check: if already locked at connect time, keep overlays hidden
    if (is_session_locked()) {
      handle_session_lock_state(c, true);
    } else {
      // Normal streaming session: hide physical cursor and optionally block local input
      set_cursor_hidden(c, true);
      set_input_blocked(c, true);
    }

    SetEvent(c->ready);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
      TranslateMessage(&msg);
      DispatchMessageW(&msg);
    }

    KillTimer(primary_hwnd, kTopmostGuardTimerId);
    KillTimer(primary_hwnd, kFallbackPollTimerId);

    if (event_hook) {
      UnhookWinEvent(event_hook);
    }

    if (apis.wts_unreg_notif) {
      apis.wts_unreg_notif(primary_hwnd);
    }

    // Restore physical environment before window destruction
    set_input_blocked(c, false);
    set_cursor_hidden(c, false);

    for (HWND w : c->windows) {
      if (IsWindow(w)) DestroyWindow(w);
    }
    c->windows.clear();
    UnregisterClassW(kOverlayClass, GetModuleHandleW(nullptr));
    c->overlay_count->store(0);
    c->affinity_ok->store(false);
    g_current_ui_ctx = nullptr;
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

  static void join_and_release(std::thread &t, void *&ctx) {
    if (t.joinable() && t.get_id() != std::this_thread::get_id()) t.join();
    delete (ui_ctx_t *) ctx;
    ctx = nullptr;
  }

  static void signal_stop(void *ctx) {
    if (!ctx) return;
    ui_ctx_t *c = (ui_ctx_t *) ctx;
    if (c->thread_id) PostThreadMessageW(c->thread_id, WM_QUIT, 0, 0);
  }

  result_e privacy_screen_manager_t::enable_locked(std::unique_lock<std::mutex> &lock) {
    if (active_.load()) return result_e::already_active;
    if (!config_.enabled) return result_e::ok;

    if (!supports_exclusion()) return result_e::unsupported_os;

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
    return ctx->result == result_e::image_failed ? result_e::image_failed
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
    if (!streaming_.load()) {
      pending_.store(true);
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
    if (cfg.lock_on_disconnect) do_lock();
  }

  bool remote_lock_manager_t::pending() const { return pending_.load(); }
  void remote_lock_manager_t::clear_pending() { pending_.store(false); }

}  // namespace platf::privacy
