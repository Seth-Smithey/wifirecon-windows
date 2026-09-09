' wifirecon launcher.
'
' Starts the desktop application with no console window. The interface is Qt,
' drawn in this process, so there is no server to wait for and no browser to
' fall back to.

Option Explicit
Dim shell, fso, here, pythonw, python, answer

Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
here = fso.GetParentFolderName(WScript.ScriptFullName)
shell.CurrentDirectory = here

pythonw = here & "\.venv\Scripts\pythonw.exe"
python  = here & "\.venv\Scripts\python.exe"

' --- first run -------------------------------------------------------------
If Not fso.FileExists(python) Then
    answer = MsgBox("wifirecon needs to set itself up first." & vbCrLf & vbCrLf & _
                    "This takes a couple of minutes, mostly downloading Qt." & _
                    vbCrLf & "Continue?", _
                    vbYesNo + vbQuestion, "wifirecon")
    If answer <> vbYes Then WScript.Quit 1
    shell.Run """" & here & "\Setup wifirecon.cmd""", 1, True
    If Not fso.FileExists(python) Then
        MsgBox "Setup did not finish. Run 'Setup wifirecon.cmd' and read the message.", _
               vbExclamation, "wifirecon"
        WScript.Quit 1
    End If
End If

If Not fso.FileExists(pythonw) Then pythonw = python

' --- the interface must be installed ---------------------------------------
Dim exec, hasQt
hasQt = False
On Error Resume Next
Set exec = shell.Exec("""" & python & """ -c ""from PySide6 import QtWidgets""")
If Err.Number = 0 Then
    Do While exec.Status = 0
        WScript.Sleep 60
    Loop
    hasQt = (exec.ExitCode = 0)
End If
Err.Clear
On Error GoTo 0

If Not hasQt Then
    answer = MsgBox("The interface component is not installed yet." & vbCrLf & _
                    vbCrLf & "Install it now? It is about 200 MB, so give it a " & _
                    "minute or two.", vbYesNo + vbQuestion, "wifirecon")
    If answer <> vbYes Then WScript.Quit 0
    shell.Run """" & python & """ -m pip install PySide6-Essentials", 1, True
    On Error Resume Next
    Set exec = shell.Exec("""" & python & """ -c ""from PySide6 import QtWidgets""")
    Do While exec.Status = 0
        WScript.Sleep 60
    Loop
    hasQt = (exec.ExitCode = 0)
    Err.Clear
    On Error GoTo 0
    If Not hasQt Then
        MsgBox "PySide6 would not install, so wifirecon cannot open its window." & _
               vbCrLf & vbCrLf & "Run 'Setup wifirecon.cmd' and read the message.", _
               vbExclamation, "wifirecon"
        WScript.Quit 1
    End If
End If

' --- launch ----------------------------------------------------------------
' 0 = hidden, so nothing flashes. True = wait, so a failure to start is
' reported rather than the shortcut appearing to do nothing at all.
Dim code
code = shell.Run("""" & pythonw & """ -m app", 0, True)

If code = 3 Then
    MsgBox "wifirecon could not open its window because the interface " & _
           "component is missing." & vbCrLf & vbCrLf & _
           "Run 'Setup wifirecon.cmd' and read the message it prints.", _
           vbExclamation, "wifirecon"
ElseIf code <> 0 Then
    MsgBox "wifirecon stopped unexpectedly (code " & code & ")." & vbCrLf & vbCrLf & _
           "The log is at:" & vbCrLf & _
           shell.ExpandEnvironmentStrings("%LOCALAPPDATA%") & _
           "\wifirecon-win\wifirecon.log", _
           vbExclamation, "wifirecon"
End If
