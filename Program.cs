using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
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

    struct KeyInfo
    {
        public KeyInfo(LowLevelKeyboardInputEvent e, bool shift, bool alt)
        {
            KeyCode = checked((Keys)e.VirtualCode);
            ScanCode = e.HardwareScanCode;
            Flags = e.Flags;
            Shifted = shift;
            Altered = alt;
        }

        public KeyInfo(Keys keyCode, int scanCode, int flags, bool shift, bool alt)
        {
            KeyCode = keyCode;
            ScanCode = scanCode;
            Flags = flags;
            Shifted = shift;
            Altered = alt;
        }

        public readonly Keys KeyCode;
        public readonly int ScanCode;
        public readonly int Flags;
        public readonly bool Shifted;
        public readonly bool Altered;
    }

    static class MsgCode
    {
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

    static class KeyEvent
    {
        public const uint KEYEVENTF_KEYDOWN = 0;
        public const uint KEYEVENTF_KEYUP = 2;
    }

    public delegate IntPtr HookProc(int nCode, IntPtr wParam, IntPtr lParam);
    public delegate bool EnumThreadDelegate(IntPtr hWnd, IntPtr lParam);

    static class Interop
    {
        public const int MAPVK_VK_TO_VSC = 0;

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
        public static extern int MapVirtualKey(int keyCode, int mapType = Interop.MAPVK_VK_TO_VSC);

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

        public static void PostMessage(IntPtr hWnd, uint msg, Keys keyCode, int lParam)
        {
            PostMessage(hWnd, msg, keyCode.ToInt(), lParam);
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

        public static void KeyboardEvent(IntPtr hWnd, Keys keyCode, uint dwFlags, uint dwExtraInfo)
        {
            if (hWnd != IntPtr.Zero)
            {
                SetForegroundWindow(hWnd);
            }
            keybd_event((byte)keyCode.ToInt(), (byte)MapVirtualKey(keyCode.ToInt()), dwFlags, dwExtraInfo);
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
    using Bucket = Dictionary<string, Win32.KeyInfo>;
    using Index = Dictionary<InputLanguage, Dictionary<string, Win32.KeyInfo>>;

    class GlobalKeyboardHook : IDisposable
    {
        public GlobalKeyboardHook()
        {
            m_windowsHookHandle = IntPtr.Zero;
            m_user32LibraryHandle = IntPtr.Zero;
            m_hookProc = LowLevelKeyboardProc; // we must keep alive m_hookProc, because GC is not aware about SetWindowsHookEx behaviour.

            m_user32LibraryHandle = Interop.LoadLibrary("User32");
            if (m_user32LibraryHandle == IntPtr.Zero)
            {
                int errorCode = Marshal.GetLastWin32Error();
                throw new Win32Exception(errorCode, $"Failed to load library 'USER32'. Error {errorCode}: {new Win32Exception(Marshal.GetLastWin32Error()).Message}.");
            }

            m_windowsHookHandle = Interop.SetWindowsHookEx(MsgCode.WH_KEYBOARD_LL, m_hookProc, m_user32LibraryHandle, 0);
            if (m_windowsHookHandle == IntPtr.Zero)
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
                if (m_windowsHookHandle != IntPtr.Zero)
                {
                    if (!Interop.UnhookWindowsHookEx(m_windowsHookHandle))
                    {
                        int errorCode = Marshal.GetLastWin32Error();
                        throw new Win32Exception(errorCode, $"Failed to remove keyboard hooks for '{Process.GetCurrentProcess().ProcessName}'. Error {errorCode}: {new Win32Exception(Marshal.GetLastWin32Error()).Message}.");
                    }
                    m_windowsHookHandle = IntPtr.Zero;

                    // ReSharper disable once DelegateSubtraction
                    m_hookProc -= LowLevelKeyboardProc;
                }
            }

            if (m_user32LibraryHandle != IntPtr.Zero)
            {
                if (!Interop.FreeLibrary(m_user32LibraryHandle)) // reduces reference to library by 1.
                {
                    int errorCode = Marshal.GetLastWin32Error();
                    throw new Win32Exception(errorCode, $"Failed to unload library 'USER32'. Error {errorCode}: {new Win32Exception(Marshal.GetLastWin32Error()).Message}.");
                }
                m_user32LibraryHandle = IntPtr.Zero;
            }
        }

        ~GlobalKeyboardHook()
        {
            Dispose(false);
        }

        private IntPtr m_windowsHookHandle;
        private IntPtr m_user32LibraryHandle;
        private HookProc m_hookProc;
    }

    class GlobalKeyboardHookEventArgs : HandledEventArgs
    {
        public GlobalKeyboardHookEventArgs(LowLevelKeyboardInputEvent keyboardData, uint msgCode)
        {
            KeyboardData = keyboardData;
            messageCode = msgCode;
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
                var foregroundWindow = Interop.GetForegroundWindow();
                if (foregroundWindow != IntPtr.Zero)
                {
                    UInt32 procId;
                    var threadId = Interop.GetWindowThreadProcessId(foregroundWindow, out procId);
                    if (Interop.AttachThreadInput(Interop.GetCurrentThreadId(), threadId, true))
                    {
                        var ret = Interop.GetFocus();
                        Interop.AttachThreadInput(Interop.GetCurrentThreadId(), threadId, false);
                        return ret;
                    }
                }

                return IntPtr.Zero;
            }
        }

        public static void DownKey(IntPtr handle, Keys keyCode, ushort repeatCount)
        {
            Interop.PostMessage(handle, MsgCode.WM_KEYDOWN, keyCode, MakeLParam(keyCode, repeatCount));
        }

        public static void CharKey(IntPtr handle, int charCode, int scanCode, ushort repeatCount)
        {
            Interop.PostMessage(handle, MsgCode.WM_CHAR, charCode, MakeLParam(scanCode, repeatCount));
        }

        public static void SwitchKeyboardLayout(IntPtr window, string inputIdName)
        {
            Interop.PostMessage(window, MsgCode.WM_INPUTLANGCHANGEREQUEST, 0, Interop.LoadKeyboardLayout(inputIdName, KFLFlag.KLF_ACTIVATE));
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
            Interop.ToUnicode(checked((uint)keyInfo.KeyCode), checked((uint)keyInfo.ScanCode), keyboardState, buf, 256, checked((uint)keyInfo.Flags));
            return buf.ToString();
        }

        public static int MakeLParam(Keys keyCode, ushort repeatCount)
        {
            var scanCode = Interop.MapVirtualKey(keyCode.ToInt());
            var lParam = KeyboardEmulator.MakeLParam(scanCode, 1);
            return lParam;
        }

        public static int MakeLParam(int scanCode, ushort repeatCount)
        {
            int lp = scanCode;
            return lp << 16 | repeatCount;
        }

        public static void CopyToClipboard(IntPtr handle)
        {
            Interop.KeyboardEvent(handle, Keys.ControlKey, KeyEvent.KEYEVENTF_KEYDOWN, 0);
            Interop.KeyboardEvent(handle, Keys.C, KeyEvent.KEYEVENTF_KEYDOWN, 0);
            Interop.KeyboardEvent(handle, Keys.C, KeyEvent.KEYEVENTF_KEYUP, 0);
            Interop.KeyboardEvent(handle, Keys.ControlKey, KeyEvent.KEYEVENTF_KEYUP, 0);
        }
    }

    class KeyboardMonitor
    {
        [STAThread]
        static void Main()
        {
            Application.Run();
        }

        static KeyboardMonitor()
        {
            m_keyboardHook = new GlobalKeyboardHook();
            m_keyboardHook.KeyboardPressed += OnKeyPressed;

            while (!m_transliterationIndex.ContainsKey(InputLanguage.CurrentInputLanguage))
            {
                var bucket = new Dictionary<string, KeyInfo>();
                for (var keyCode = 0; keyCode <= 0xff; ++keyCode)
                {
                    for (var shift = false; ; shift = true)
                    {
                        var scanCode = Interop.MapVirtualKey(keyCode);
                        var keyInfo = new KeyInfo(checked((Keys)keyCode), scanCode, 0, shift, false);
                        var chars = KeyboardEmulator.GetChars(keyInfo);
                        if (chars.Length > 0)
                        {
                            bucket[chars] = keyInfo;
                        }
                        if (shift)
                        {
                            break;
                        }
                    }
                }
                m_transliterationIndex[InputLanguage.CurrentInputLanguage] = bucket;
                NextKeyboardLayout();
            }
        }

        ~KeyboardMonitor()
        {
            m_keyboardHook?.Dispose();
            m_keyboardHook = null;
        }

        private static string GetInputLocaleIdentifierName(InputLanguage inputLanguage)
        {
            var inputLocaleIdentifierName = inputLanguage.Handle.ToString("X");
            inputLocaleIdentifierName = $"00000{inputLocaleIdentifierName.Substring(inputLocaleIdentifierName.Length - 3)}";
            return inputLocaleIdentifierName;
        }

        private static void NextKeyboardLayout()
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

        private static void RemoveTextWithBackspace()
        {
            var currentEditor = KeyboardEmulator.ForegroundEdit;
            for (var i = 0; i < m_writeIndex; ++i)
            {
                KeyboardEmulator.DownKey(currentEditor, Keys.Back, 1);
            }
        }

        private static void InsertConvertedChars()
        {
            var currentEditor = KeyboardEmulator.ForegroundEdit;
            for (var i = 0; i < m_writeIndex; ++i)
            {
                var keyInfo = m_lastEntered[i];
                foreach (var c in KeyboardEmulator.GetChars(keyInfo))
                {
                    KeyboardEmulator.CharKey(currentEditor, c, keyInfo.ScanCode, 1);
                }
            }
        }

        private static string TryGetTextFromClipboard()
        {
            if (Clipboard.ContainsText(TextDataFormat.UnicodeText))
            {
                return Clipboard.GetText(TextDataFormat.UnicodeText);
            }
            else if (Clipboard.ContainsText(TextDataFormat.Text))
            {
                return Clipboard.GetText(TextDataFormat.Text);
            }
            else
            {
                return null;
            }
        }

        private static void InplaceChangeTextToNextKeyboardLayout()
        {
            if (IsSameEditor())
            {
                var currentEditor = KeyboardEmulator.ForegroundEdit;
                System.Threading.Thread.Sleep(100);
                KeyboardEmulator.CopyToClipboard(currentEditor);
                System.Threading.Thread.Sleep(100);
                var text = TryGetTextFromClipboard();
                if (null != text)
                {
                    lock (m_syncObj)
                    {
                        try
                        {
                            m_suppressKeyboardProcessing = true;
                            Bucket backet;
                            if (m_transliterationIndex.TryGetValue(InputLanguage.CurrentInputLanguage, out backet))
                            {
                                NextKeyboardLayout();
                                m_writeIndex = 0;
                                foreach (var originalChar in text)
                                {
                                    KeyInfo keyInfo;
                                    if (backet.TryGetValue($"{originalChar}", out keyInfo))
                                    {
                                        foreach (var transliteratedChar in KeyboardEmulator.GetChars(keyInfo))
                                        {
                                            KeyboardEmulator.CharKey(currentEditor, transliteratedChar, keyInfo.ScanCode, 1);
                                        }
                                    }
                                }
                            }
                        }
                        finally
                        {
                            m_suppressKeyboardProcessing = false;
                        }
                    }
                }
                //Clipboard.Clear();
            }
        }

        private static void ChangeTextToNextKeyboardLayout()
        {
            if (IsSameEditor())
            {
                System.Threading.Tasks.Task.Run(() =>
                {
                    lock (m_syncObj)
                    {
                        try
                        {
                            m_suppressKeyboardProcessing = true;
                            RemoveTextWithBackspace();
                            System.Threading.Thread.Sleep(100);
                            NextKeyboardLayout();
                            InsertConvertedChars();
                        }
                        finally
                        {
                            m_suppressKeyboardProcessing = false;
                        }
                    }
                });
            }
        }

        private static void OnBackspace()
        {
            if (m_writeIndex > 0)
            {
                --m_writeIndex;
            }
        }

        private static void OnDrop()
        {
            m_writeIndex = 0;
        }

        private static bool IsSameEditor()
        {
            var currentEditor = KeyboardEmulator.ForegroundEdit;
            var ret = currentEditor != IntPtr.Zero && (m_lastEditor == currentEditor || m_lastEditor == IntPtr.MaxValue);
            m_lastEditor = currentEditor;
            return ret;
        }

        private static bool IsChar(LowLevelKeyboardInputEvent inputData)
        {
            return KeyboardEmulator.GetChars(new KeyInfo(inputData, m_shifted, false)).Length > 0;
        }

        private static void OnKeyDown(GlobalKeyboardHookEventArgs e)
        {
            switch (checked((Keys)e.KeyboardData.VirtualCode))
            {
                case Keys.RShiftKey:
                case Keys.LShiftKey:
                {
                    m_shifted = true;
                    break;
                }
            }
        }

        private static void OnSymbolEnter(GlobalKeyboardHookEventArgs e)
        {
            if (IsChar(e.KeyboardData))
            {
                m_lastEntered[m_writeIndex++] = new KeyInfo(e.KeyboardData, m_shifted, false);
                if (m_writeIndex >= m_lastEntered.Length)
                {
                    m_writeIndex = m_lastEntered.Length - 1;
                }
            }
        }

        private static void OnKeyUp(GlobalKeyboardHookEventArgs e)
        {
            switch (checked((Keys)e.KeyboardData.VirtualCode))
            {
                case Keys.ControlKey:
                case Keys.LControlKey:
                case Keys.RControlKey:
                    break;
                case Keys.Scroll:
                {
                    InplaceChangeTextToNextKeyboardLayout();
                    break;
                }
                case Keys.RShiftKey:
                case Keys.LShiftKey:
                {
                    m_shifted = false;
                    if (m_inplaceChangeRequest)
                    {
                        InplaceChangeTextToNextKeyboardLayout();
                    }
                    break;
                }
                case Keys.Pause:
                {
                    if (m_shifted)
                    {
                        m_inplaceChangeRequest = true;
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
                case Keys.Space:
                {
                    m_spaceEntered = true;
                    OnSymbolEnter(e);
                    break;
                }
                case Keys.Enter:
                case Keys.Delete:
                case Keys.PageUp:
                case Keys.PageDown:
                case Keys.End:
                case Keys.Home:
                case Keys.Left:
                case Keys.Up:
                case Keys.Right:
                case Keys.Down:
                case Keys.Tab:
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

                    if (m_spaceEntered)
                    {
                        m_spaceEntered = false;
                        OnDrop();
                    }

                    OnSymbolEnter(e);

                    break;
                }
            }
        }

        private static void OnKeyPressed(object sender, GlobalKeyboardHookEventArgs e)
        {
            if (!m_suppressKeyboardProcessing)
            {
                lock (m_syncObj)
                {
                    if (!m_suppressKeyboardProcessing)
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
                }
            }
        }

        private static Index m_transliterationIndex = new Index();
        private static object m_syncObj = new object();
        private static GlobalKeyboardHook m_keyboardHook;
        private static int m_writeIndex = 0;
        private static IntPtr m_lastEditor = IntPtr.MaxValue;
        private static readonly KeyInfo[] m_lastEntered = new KeyInfo[1024];
        private static bool m_shifted = false;
        private static bool m_inplaceChangeRequest = false;
        private static bool m_spaceEntered = false;
        private static bool m_suppressKeyboardProcessing = false;
    }
}
