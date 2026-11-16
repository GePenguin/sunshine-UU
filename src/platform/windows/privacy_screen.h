/**
 * @file src/platform/windows/privacy_screen.h
 * @brief Declarations for the Windows privacy-screen and remote-lock managers.
 *
 * Reimplementation of the UU Remote (GameViewer) 隐私屏 behaviour, ported to
 * Sunshine.  The two managers are deliberately independent:
 *
 *  - privacy_screen_manager_t owns a full-screen, topmost, layered Win32
 *    overlay whose display affinity is WDA_EXCLUDEFROMCAPTURE.  That single
 *    flag keeps the overlay out of DXGI Desktop Duplication, GDI BitBlt and
 *    Windows.Graphics.Capture on Windows 10 2004+, while leaving it visible on
 *    the physical monitor.  Verified empirically on Win11 26200.
 *  - remote_lock_manager_t exposes an authenticated "lock the workstation"
 *    action and keeps a latch across disconnect/reconnect so a lock requested
 *    while streaming is not lost.
 *
 * Everything here is Windows-only; the files are listed in
 * cmake/compile_definitions/windows.cmake::PLATFORM_TARGET_FILES.
 */
#pragma once

// standard includes
#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>

// platform includes
#include <Windows.h>

namespace platf::privacy {

  /**
   * @brief Runtime-tunable privacy-screen configuration.
   *
   * Mirrored out of config::video_t::privacy_t (see config.h).  Defaults
   * reproduce UU's normal privacy path: an opaque image overlay excluded from
   * capture, shown for the whole streaming session.
   */
  struct privacy_config_t {
    bool enabled = false;  ///< Master switch: show the overlay for each streaming session.
    std::string image_path;  ///< Optional UTF-8 path to a BMP/PNG/JPG privacy wallpaper. Empty = solid colour.
    std::uint32_t fallback_rgb = 0x00000000;  ///< 0x00RRGGBB when no image loads (UU degrades to black).
    bool lock_on_disable = true;  ///< Reproduce handleDisablePrivacyModeAndLock: lock when privacy turns off.
    bool lock_on_disconnect = false;  ///< Lock the workstation when the last client disconnects.
    bool hide_cursor = true;  ///< Hide the system cursor while the overlay is up (UU system_cursor_guard).
    std::chrono::milliseconds settle_delay {250};  ///< Delay between topology settle and overlay creation.
  };

  /**
   * @brief Outcome of an enable/disable/lock attempt.
   */
  enum class result_e {
    ok,
    already_active,
    not_active,
    unsupported_os,  ///< WDA_EXCLUDEFROMCAPTURE unavailable (pre Win10 2004).
    window_failed,
    affinity_failed,  ///< SetWindowDisplayAffinity failed (critical: overlay would leak into capture).
    image_failed,  ///< Non-fatal: image decode failed, fell back to solid colour.
    lock_failed,
  };

  const char *result_name(result_e r);

  /**
   * @brief Detect whether the interactive session is locked / on the secure desktop.
   *
   * The workstation is locked exactly when the *input* desktop is not "Default"
   * (it becomes "Winlogon" on the lock screen). UU relies on the same signal
   * internally (`is_system_locked=` appears throughout its server logs).
   *
   * This matters because the privacy overlay must NOT be shown while the secure
   * desktop is active: the user needs to see the password prompt to unlock, and
   * an opaque capture-excluded wallpaper would hide it from the client.
   *
   * @return true when the input desktop is not the normal "Default" desktop.
   */
  bool is_session_locked();

  /**
   * @brief Owns the capture-excluded privacy overlay.
   *
   * Thread-safe.  The overlay windows live on one UI thread (message pump +
   * GDI+ decoding).  enable() starts that thread; disable() stops it and
   * restores the physical monitor.  Process-wide singleton via instance().
   */
  class privacy_screen_manager_t {
  public:
    static privacy_screen_manager_t &instance();

    privacy_screen_manager_t(const privacy_screen_manager_t &) = delete;
    privacy_screen_manager_t &operator=(const privacy_screen_manager_t &) = delete;

    /** @brief Apply configuration (safe while active; takes effect on next enable). */
    void configure(const privacy_config_t &cfg);

    /** @brief Show the privacy overlay for the current streaming session. */
    result_e enable();

    /**
     * @brief Remove the overlay and restore the physical monitor.
     * @param lock_requested When true, lock the workstation afterwards.
     */
    result_e disable(bool lock_requested);

    /** @return True while an overlay window is active. */
    bool active() const;

    /** @brief Number of monitors covered by the current overlay set. */
    int overlay_count() const;

   private:
    privacy_screen_manager_t() = default;
    ~privacy_screen_manager_t();

    result_e enable_locked(std::unique_lock<std::mutex> &lock);
    result_e disable_locked(std::unique_lock<std::mutex> &lock, bool lock_requested);
    bool supports_exclusion() const;

    mutable std::mutex mutex_;
    privacy_config_t config_;
    std::atomic<bool> active_ {false};
    std::atomic<int> overlay_count_ {0};
    std::thread ui_thread_;
    HANDLE ready_event_ = nullptr;
    HWND hwnd_ = nullptr;  ///< First overlay HWND (diagnostics only).
    std::atomic<bool> affinity_ok_ {false};  ///< WDA_EXCLUDEFROMCAPTURE read-back verification.
    std::atomic<bool> stop_requested_ {false};
    void *ui_ctx_ = nullptr;  ///< Opaque pointer to the UI-thread context (owned until join).
    DWORD ui_thread_id_ = 0;  ///< UI thread id for WM_QUIT.
  };

  /**
   * @brief Locks the Windows workstation from an authenticated remote action.
   *
   * Keeps a pending latch: a lock requested while no streaming session is
   * active is remembered and executed when the next session starts, so a
   * disconnect/reconnect cycle cannot silently drop the request.
   */
  class remote_lock_manager_t {
  public:
    static remote_lock_manager_t &instance();

    remote_lock_manager_t(const remote_lock_manager_t &) = delete;
    remote_lock_manager_t &operator=(const remote_lock_manager_t &) = delete;

    /**
     * @brief Request a lock. Executes immediately when streaming, otherwise latches.
     * @param from_stream_session True for an in-band (already authenticated) stream action;
     *                            false for a Web UI action (caller must have authenticated).
     */
    result_e request_lock(bool from_stream_session);

    /** @brief Called from streaming_will_start(): flush any latched lock. */
    void on_session_start();

    /** @brief Called from streaming_will_stop(): optionally lock on disconnect. */
    void on_session_stop(const privacy_config_t &cfg);

    /** @return True when a lock request is pending. */
    bool pending() const;

    /** @brief Clear a pending request without locking (tests / config reload). */
    void clear_pending();

   private:
    remote_lock_manager_t() = default;
    result_e do_lock();

    mutable std::mutex mutex_;
    std::atomic<bool> pending_ {false};
    std::atomic<bool> streaming_ {false};
  };

}  // namespace platf::privacy
