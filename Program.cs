using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Forms;

namespace Win32
{
    static class AttachedHelpers
    {
        public static int ToInt(this Keys value)
        {
            return checked((int)value);
        }
    }

    struct ScanCode
    {
        public static ushort Backspace = checked((ushort)Keys.Back);
        public static ushort Break = 0x0e;
    }

    static class MsgCode
    {
        public const uint WM_GETTEXT = 0x000D;
        public const uint WM_KEYDOWN = 0x0100;
        public const uint WM_KEYUP = 0x0101;
        public const uint WM_CHAR = 0x0102;

        public const int WH_KEYBOARD_LL = 13;

        public const uint WM_INPUTLANGCHANGEREQUEST = 0x0050;
    }

    static class KFLFlag
    {
        public const uint KLF_ACTIVATE = 0x00000001;
    }

    public delegate IntPtr HookProc(int nCode, IntPtr wParam, IntPtr lParam);
    public delegate bool EnumThreadDelegate(IntPtr hWnd, IntPtr lParam);

    static class Interop
    {
        [DllImport("KERNEL32")]
        public static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("KERNEL32", CharSet = CharSet.Auto)]
        public static extern bool FreeLibrary(IntPtr hModule);

        /// <summary>
        /// The SetWindowsHookEx function installs an application-defined hook procedure into a hook chain.
        /// You would install a hook procedure to monitor the system for certain types of events. These events are
        /// associated either with a specific thread or with all threads in the same desktop as the calling thread.
        /// </summary>
        /// <param name="idHook">hook type</param>
        /// <param name="lpfn">hook procedure</param>
        /// <param name="hMod">handle to application instance</param>
        /// <param name="dwThreadId">thread identifier</param>
        /// <returns>If the function succeeds, the return value is the handle to the hook procedure.</returns>
        [DllImport("USER32", SetLastError = true)]
        public static extern IntPtr SetWindowsHookEx(int idHook, HookProc lpfn, IntPtr hMod, int dwThreadId);

        /// <summary>
        /// The UnhookWindowsHookEx function removes a hook procedure installed in a hook chain by the SetWindowsHookEx function.
        /// </summary>
        /// <param name="hhk">handle to hook procedure</param>
        /// <returns>If the function succeeds, the return value is true.</returns>
        [DllImport("USER32", SetLastError = true)]
        public static extern bool UnhookWindowsHookEx(IntPtr hHook);

        /// <summary>
        /// The CallNextHookEx function passes the hook information to the next hook procedure in the current hook chain.
        /// A hook procedure can call this function either before or after processing the hook information.
        /// </summary>
        /// <param name="hHook">handle to current hook</param>
        /// <param name="code">hook code passed to hook procedure</param>
        /// <param name="wParam">value passed to hook procedure</param>
        /// <param name="lParam">value passed to hook procedure</param>
        /// <returns>If the function succeeds, the return value is true.</returns>
        [DllImport("USER32", SetLastError = true)]
        public static extern IntPtr CallNextHookEx(IntPtr hHook, int code, IntPtr wParam, IntPtr lParam);

        [DllImport("USER32")]
        public static extern int ToUnicode(
                    uint virtualKeyCode,
                    uint scanCode,
                    byte[] keyboardState,
                    [Out, MarshalAs(UnmanagedType.LPWStr, SizeConst = 64)] StringBuilder receivingBuffer,
                    int bufferSize,
                    uint flags
                );

        [DllImport("USER32")]
        public static extern IntPtr GetForegroundWindow();

        [DllImport("USER32")]
        public static extern IntPtr GetFocus();

        [DllImport("USER32")]
        public static extern UInt32 GetWindowThreadProcessId(IntPtr hWnd, out UInt32 lpdwProcessId);

        [DllImport("USER32")]
        public static extern bool AttachThreadInput(UInt32 idAttach, UInt32 idAttachTo, bool fAttach);

        [DllImport("KERNEL32")]
        public static extern UInt32 GetCurrentThreadId();

        [DllImport("USER32")]
        public static extern IntPtr LoadKeyboardLayout(string pwszKLID, UInt32 Flags);

        [DllImport("USER32")]
        public static extern int MapVirtualKey(int key_code, int mapType);

        public static void PostMessage(IntPtr hWnd, uint msg, int wParam, int lParam)
        {
            for (var i = 0; i < 100; i++)
            {
                if (PostMessageWin32(hWnd, msg, wParam, lParam))
                {
                    break;
                }
                System.Threading.Thread.Sleep(1);
            }
        }

        public static void PostMessage(IntPtr hWnd, uint msg, Keys key_code, int lParam)
        {
            PostMessage(hWnd, msg, key_code.ToInt(), lParam);
        }

        public static void PostMessage(IntPtr hWnd, uint msg, int wParam, IntPtr lParam)
        {
            for (var i = 0; i < 100; i++)
            {
                if (PostMessageWin32(hWnd, msg, wParam, lParam))
                {
                    break;
                }
                System.Threading.Thread.Sleep(1);
            }
        }

        public static void KeyboardEvent(IntPtr hWnd, Keys key_code, uint dwFlags, uint dwExtraInfo)
        {
            if (hWnd != IntPtr.Zero)
            {
                SetForegroundWindow(hWnd);
            }
            keybd_event((byte)key_code.ToInt(), (byte)MapVirtualKey(key_code.ToInt(), 0), dwFlags, dwExtraInfo);
        }

        [DllImport("USER32", CharSet = CharSet.Auto)]
        public static extern bool SendMessage(IntPtr hWnd, uint msg, int wParam, int lParam);

        [DllImport("USER32", CharSet = CharSet.Auto)]
        public static extern short VkKeyScanExA(char ch, IntPtr dwhkl);

        [DllImport("USER32", CharSet = CharSet.Auto, EntryPoint = "PostMessage")]
        private static extern bool PostMessageWin32(IntPtr hWnd, uint msg, int wParam, int lParam);

        [DllImport("USER32", CharSet = CharSet.Auto, EntryPoint = "PostMessage")]
        private static extern bool PostMessageWin32(IntPtr hWnd, uint msg, int wParam, IntPtr lParam);

        [DllImport("USER32")]
        private static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, uint dwExtraInfo);

        [DllImport("User32.dll")]
        private static extern bool SetForegroundWindow(IntPtr hWnd);
    }

    struct KeyInfo
    {
        public KeyInfo(LowLevelKeyboardInputEvent e, bool shift, bool alt)
        {
            VirtualCode = checked((Keys)e.VirtualCode);
            HardwareScanCode = e.HardwareScanCode;
            Flags = e.Flags;
            Shifted = shift;
            Altered = alt;
        }

        public KeyInfo(Keys key_code, int scan_code, int flags, bool shift, bool alt)
        {
            VirtualCode = key_code;
            HardwareScanCode = scan_code;
            Flags = flags;
            Shifted = shift;
            Altered = alt;
        }

        public readonly Keys VirtualCode;
        public readonly int HardwareScanCode;
        public readonly int Flags;
        public readonly bool Shifted;
        public readonly bool Altered;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct LowLevelKeyboardInputEvent
    {
        /// <summary>
        /// A virtual-key code. The code must be a value in the range 1 to 254.
        /// </summary>
        public int VirtualCode;

        /// <summary>
        /// A hardware scan code for the key. 
        /// </summary>
        public int HardwareScanCode;

        /// <summary>
        /// The extended-key flag, event-injected Flags, context code, and transition-state flag. This member is specified as follows. An application can use the following values to test the keystroke Flags. Testing LLKHF_INJECTED (bit 4) will tell you whether the event was injected. If it was, then testing LLKHF_LOWER_IL_INJECTED (bit 1) will tell you whether or not the event was injected from a process running at lower integrity level.
        /// </summary>
        public int Flags;

        /// <summary>
        /// The time stamp stamp for this message, equivalent to what GetMessageTime would return for this message.
        /// </summary>
        public int TimeStamp;

        /// <summary>
        /// Additional information associated with the message. 
        /// </summary>
        public IntPtr AdditionalInformation;
    }
}

namespace KBS_Win
{
    using Win32;
    class GlobalKeyboardHook : IDisposable
    {
        public GlobalKeyboardHook()
        {
            _windowsHookHandle = IntPtr.Zero;
            _user32LibraryHandle = IntPtr.Zero;
            _hookProc = LowLevelKeyboardProc; // we must keep alive _hookProc, because GC is not aware about SetWindowsHookEx behaviour.

            _user32LibraryHandle = Interop.LoadLibrary("User32");
            if (_user32LibraryHandle == IntPtr.Zero)
            {
                int errorCode = Marshal.GetLastWin32Error();
                throw new Win32Exception(errorCode, $"Failed to load library 'USER32'. Error {errorCode}: {new Win32Exception(Marshal.GetLastWin32Error()).Message}.");
            }

            _windowsHookHandle = Interop.SetWindowsHookEx(MsgCode.WH_KEYBOARD_LL, _hookProc, _user32LibraryHandle, 0);
            if (_windowsHookHandle == IntPtr.Zero)
            {
                int errorCode = Marshal.GetLastWin32Error();
                throw new Win32Exception(errorCode, $"Failed to adjust keyboard hooks for '{Process.GetCurrentProcess().ProcessName}'. Error {errorCode}: {new Win32Exception(Marshal.GetLastWin32Error()).Message}.");
            }
        }

        public IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam)
        {
            bool fEatKeyStroke = false;

            var wparamTyped = unchecked((uint)wParam.ToInt32());
            var data = checked((LowLevelKeyboardInputEvent)Marshal.PtrToStructure(lParam, typeof(LowLevelKeyboardInputEvent)));
            var eventArguments = new GlobalKeyboardHookEventArgs(data, wparamTyped);
            var handler = KeyboardPressed;
            handler?.Invoke(this, eventArguments);

            fEatKeyStroke = eventArguments.Handled;

            return fEatKeyStroke ? (IntPtr)1 : Interop.CallNextHookEx(IntPtr.Zero, nCode, wParam, lParam);
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        public event EventHandler<GlobalKeyboardHookEventArgs> KeyboardPressed;

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                // because we can unhook only in the same thread, not in garbage collector thread
                if (_windowsHookHandle != IntPtr.Zero)
                {
                    if (!Interop.UnhookWindowsHookEx(_windowsHookHandle))
                    {
                        int errorCode = Marshal.GetLastWin32Error();
                        throw new Win32Exception(errorCode, $"Failed to remove keyboard hooks for '{Process.GetCurrentProcess().ProcessName}'. Error {errorCode}: {new Win32Exception(Marshal.GetLastWin32Error()).Message}.");
                    }
                    _windowsHookHandle = IntPtr.Zero;

                    // ReSharper disable once DelegateSubtraction
                    _hookProc -= LowLevelKeyboardProc;
                }
            }

            if (_user32LibraryHandle != IntPtr.Zero)
            {
                if (!Interop.FreeLibrary(_user32LibraryHandle)) // reduces reference to library by 1.
                {
                    int errorCode = Marshal.GetLastWin32Error();
                    throw new Win32Exception(errorCode, $"Failed to unload library 'USER32'. Error {errorCode}: {new Win32Exception(Marshal.GetLastWin32Error()).Message}.");
                }
                _user32LibraryHandle = IntPtr.Zero;
            }
        }

        ~GlobalKeyboardHook()
        {
            Dispose(false);
        }

        private IntPtr _windowsHookHandle;
        private IntPtr _user32LibraryHandle;
        private HookProc _hookProc;
    }

    class GlobalKeyboardHookEventArgs : HandledEventArgs
    {
        public GlobalKeyboardHookEventArgs(LowLevelKeyboardInputEvent keyboardData, uint msg_code)
        {
            KeyboardData = keyboardData;
            messageCode = msg_code;
        }

        public uint messageCode { get; private set; }

        public LowLevelKeyboardInputEvent KeyboardData { get; private set; }
    }

    class KeyboardEmulator
    {
        public static IntPtr ForegroundWindow
        {
            get
            {
                return Interop.GetForegroundWindow();
            }
        }

        public static IntPtr ForegroundEdit
        {
            get
            {
                //return FindWindowExA(GetForegroundWindow(), IntPtr.Zero, "EDIT", string.Empty);
                var foreground_window = Interop.GetForegroundWindow();
                if (foreground_window != IntPtr.Zero)
                {
                    UInt32 proc_id;
                    var thread_id = Interop.GetWindowThreadProcessId(foreground_window, out proc_id);
                    if (Interop.AttachThreadInput(Interop.GetCurrentThreadId(), thread_id, true))
                    {
                        var ret = Interop.GetFocus();
                        Interop.AttachThreadInput(Interop.GetCurrentThreadId(), thread_id, false);
                        return ret;
                    }
                }

                return IntPtr.Zero;
            }
        }

        public static void DownKey(IntPtr handle, Keys key_code, ushort repeat_count)
        {
            Interop.PostMessage(handle, MsgCode.WM_KEYDOWN, key_code, MakeLParam(key_code, repeat_count));
        }

        public static void CharKey(IntPtr handle, int char_code, int scan_code, ushort repeat_count)
        {
            Interop.PostMessage(handle, MsgCode.WM_CHAR, char_code, MakeLParam(scan_code, repeat_count));
        }

        public static void UpKey(IntPtr handle, Keys key_code, ushort repeat_count)
        {
            //0xC0000000 explanation:
            //30  The previous key state. The value is always 1 for a WM_KEYUP message.
            //31  The transition state.The value is always 1 for a WM_KEYUP message.
            int lparam = (int)(0xC0000000 | MakeLParam(key_code, repeat_count));
            Interop.PostMessage(handle, MsgCode.WM_KEYUP, key_code, lparam);
        }

        public static void SwitchKeyboardLayout(IntPtr window, string input_id_name)
        {
            Interop.PostMessage(window, MsgCode.WM_INPUTLANGCHANGEREQUEST, 0, Interop.LoadKeyboardLayout(input_id_name, KFLFlag.KLF_ACTIVATE));
        }

        public static string GetChars(KeyInfo keyInfo)
        {
            var buf = new StringBuilder(256);
            var keyboardState = new byte[256];
            if (keyInfo.Shifted)
            {
                keyboardState[Keys.ShiftKey.ToInt()] = 0xff;
            }
            if (keyInfo.Altered)
            {
                keyboardState[Keys.ControlKey.ToInt()] = 0xff;
                keyboardState[Keys.Menu.ToInt()] = 0xff;
            }
            Interop.ToUnicode(checked((uint)keyInfo.VirtualCode), checked((uint)keyInfo.HardwareScanCode), keyboardState, buf, 256, checked((uint)keyInfo.Flags));
            return buf.ToString();
        }

        public static int MakeLParam(Keys key_code, ushort repeat_count)
        {
            var scanCode = Interop.MapVirtualKey(key_code.ToInt(), 0);
            var lParam = KeyboardEmulator.MakeLParam(scanCode, 1);
            return lParam;
        }

        public static int MakeLParam(int scan_code, ushort repeat_count)
        {
            int lp = scan_code;
            return lp << 16 | repeat_count;
        }

        public static void CopyToClipboard(IntPtr handle)
        {
            const uint KEYEVENTF_KEYDOWN = 0;
            const uint KEYEVENTF_KEYUP = 2;
            Interop.KeyboardEvent(handle, Keys.ControlKey, KEYEVENTF_KEYDOWN, 0);
            Interop.KeyboardEvent(handle, Keys.C, KEYEVENTF_KEYDOWN, 0);
            Interop.KeyboardEvent(handle, Keys.C, KEYEVENTF_KEYUP, 0);
            Interop.KeyboardEvent(handle, Keys.ControlKey, KEYEVENTF_KEYUP, 0);
        }
    }

    class KeyboardMonitor : IDisposable
    {
        public KeyboardMonitor()
        {
            _kbHook = new GlobalKeyboardHook();
            _kbHook.KeyboardPressed += OnKeyPressed;
        }

        public void Dispose()
        {
            _kbHook?.Dispose();
            _kbHook = null;
        }

        public static int GetScanCode(char c)
        {
            var inputLocaleIdentifierName = GetInputLocaleIdentifierName(InputLanguage.CurrentInputLanguage);
            return Interop.VkKeyScanExA(c, Interop.LoadKeyboardLayout(inputLocaleIdentifierName, KFLFlag.KLF_ACTIVATE));
        }

        private static string GetInputLocaleIdentifierName(InputLanguage input_language)
        {
            var inputLocaleIdentifierName = input_language.Handle.ToString("X");
            inputLocaleIdentifierName = $"00000{inputLocaleIdentifierName.Substring(inputLocaleIdentifierName.Length - 3)}";
            return inputLocaleIdentifierName;
        }

        private void NextKeyboardLayout()
        {
            var langIndex = InputLanguage.InstalledInputLanguages.IndexOf(InputLanguage.CurrentInputLanguage);
            InputLanguage nextLanguage;
            if (langIndex >= 0)
            {
                langIndex = (langIndex + 1) % InputLanguage.InstalledInputLanguages.Count;
                nextLanguage = InputLanguage.InstalledInputLanguages[langIndex];
            }
            else
            {
                nextLanguage = InputLanguage.DefaultInputLanguage;
            }
            var inputLocaleIdentifierName = GetInputLocaleIdentifierName(nextLanguage);
            KeyboardEmulator.SwitchKeyboardLayout(KeyboardEmulator.ForegroundWindow, inputLocaleIdentifierName);
            InputLanguage.CurrentInputLanguage = nextLanguage;
        }

        private void RemoveTextWithBackspace()
        {
            var currentEditor = KeyboardEmulator.ForegroundEdit;
            for (var i = 0; i < _writeIndex; ++i)
            {
                KeyboardEmulator.DownKey(currentEditor, Keys.Back, 1);
            }
        }

        private void InsertConvertedChars()
        {
            var currentEditor = KeyboardEmulator.ForegroundEdit;
            for (var i = 0; i < _writeIndex; ++i)
            {
                var keyInfo = _lastEntered[i];
                foreach (var c in KeyboardEmulator.GetChars(keyInfo))
                {
                    KeyboardEmulator.CharKey(currentEditor, c, keyInfo.HardwareScanCode, 1);
                }
            }
        }

        private void InplaceChangeTextToNextKeyboardLayout()
        {
            if (IsSameEditor())
            {
                System.Threading.Thread.Sleep(100);
                KeyboardEmulator.CopyToClipboard(IntPtr.Zero);
                System.Threading.Thread.Sleep(100);
                if (Clipboard.ContainsText(TextDataFormat.Text))
                {
                    var text = Clipboard.GetText(TextDataFormat.Text);
                    NextKeyboardLayout();
                    _writeIndex = 0;
                    var currentEditor = KeyboardEmulator.ForegroundEdit;
                    foreach (var c in text)
                    {
                        var keyInfo = new KeyInfo((Keys)c, KeyboardMonitor.GetScanCode(c), 0, false, false);
                        foreach (var new_c in KeyboardEmulator.GetChars(keyInfo))
                        {
                            KeyboardEmulator.CharKey(currentEditor, new_c, keyInfo.HardwareScanCode, 1);
                        }
                    }
                }
            }
        }

        private void ChangeTextToNextKeyboardLayout()
        {
            if (IsSameEditor())
            {
                System.Threading.Tasks.Task.Run(() =>
                {
                    RemoveTextWithBackspace();
                    System.Threading.Thread.Sleep(100);
                    NextKeyboardLayout();
                    InsertConvertedChars();
                });
            }
        }

        private void OnBackspace()
        {
            if (_writeIndex > 0)
            {
                --_writeIndex;
            }
        }

        private void OnDrop()
        {
            _writeIndex = 0;
        }

        private bool IsSameEditor()
        {
            var currentEditor = KeyboardEmulator.ForegroundEdit;
            var ret = currentEditor != IntPtr.Zero && (_lastEditor == currentEditor || _lastEditor == IntPtr.MaxValue);
            _lastEditor = currentEditor;
            return ret;
        }

        private bool IsChar(LowLevelKeyboardInputEvent input_data)
        {
            return KeyboardEmulator.GetChars(new KeyInfo(input_data, _Shifted, false)).Length > 0;
        }

        private void OnKeyDown(GlobalKeyboardHookEventArgs e)
        {
            switch (checked((Keys)e.KeyboardData.VirtualCode))
            {
                case Keys.RShiftKey:
                case Keys.LShiftKey:
                    {
                        _Shifted = true;
                        break;
                    }
            }
        }

        private void OnKeyUp(GlobalKeyboardHookEventArgs e)
        {
            switch (checked((Keys)e.KeyboardData.VirtualCode))
            {
                case Keys.Scroll:
                    {
                        InplaceChangeTextToNextKeyboardLayout();
                        break;
                    }

                case Keys.RShiftKey:
                case Keys.LShiftKey:
                    {
                        _Shifted = false;
                        if (_InplaceChangeRequest)
                        {
                            InplaceChangeTextToNextKeyboardLayout();
                        }
                        break;
                    }
                case Keys.Pause:
                    {
                        if (_Shifted)
                        {
                            _InplaceChangeRequest = true;
                        }
                        else
                        {
                            ChangeTextToNextKeyboardLayout();
                        }
                        break;
                    }
                case Keys.Back:
                    {
                        OnBackspace();
                        break;
                    }
                case Keys.Enter:
                case Keys.Space:
                case Keys.Delete:
                case Keys.PageUp:
                case Keys.PageDown:
                case Keys.End:
                case Keys.Home:
                case Keys.Left:
                case Keys.Up:
                case Keys.Right:
                case Keys.Down:
                    {
                        OnDrop();
                        break;
                    }
                default:
                    {
                        if (!IsSameEditor())
                        {
                            OnDrop();
                        }

                        if (IsChar(e.KeyboardData))
                        {
                            _lastEntered[_writeIndex++] = new KeyInfo(e.KeyboardData, _Shifted, false);
                            if (_writeIndex >= _lastEntered.Length)
                            {
                                _writeIndex = _lastEntered.Length - 1;
                            }
                        }

                        break;
                    }
            }
        }

        private void OnKeyPressed(object sender, GlobalKeyboardHookEventArgs e)
        {
            switch (e.messageCode)
            {
                case MsgCode.WM_KEYDOWN:
                    {
                        OnKeyDown(e);
                        break;
                    }
                case MsgCode.WM_KEYUP:
                    {
                        OnKeyUp(e);
                        break;
                    }
            }
        }

        private GlobalKeyboardHook _kbHook;
        private int _writeIndex = 0;
        private IntPtr _lastEditor = IntPtr.MaxValue;
        private readonly KeyInfo[] _lastEntered = new KeyInfo[1024];
        private bool _Shifted = false;
        private bool _InplaceChangeRequest = false;
    }

    static class Program
    {
        /// <summary>
        ///  The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main()
        {
            using (new KeyboardMonitor())
            {
                Application.Run();
            }
        }
    }
}
