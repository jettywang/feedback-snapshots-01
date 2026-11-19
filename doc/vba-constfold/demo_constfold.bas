' Demo module for the traceable static constant-expression folder.
' It deliberately contains three categories of expressions:
'   1) same decoded value built from different source fragments,
'   2) partially evaluable expressions,
'   3) expressions where folding MUST stop (no value is guessed).

Sub DemoDeobfuscation()
    ' --- category 1: same value "wscript", three different origins ---------
    Dim a As String, b As String, c As String
    a = Chr(119) & Chr(115) & Chr(99) & Chr(114) & Chr(105) & Chr(112) & Chr(116)
    b = "wscrip" & "t"
    c = StrReverse("tpircsw")

    ' line continuation + nested parentheses + explicit type boundary
    Dim d As String
    d = Chr((40 + 3) * 2) & _
        UCase(Mid("shellcode", 1, 1))

    ' --- category 2: partially evaluable / stopped with retained input ----
    ' "Shell" is a known input but the variable is not, and no transformation
    ' completes: reported STOPPED with the "Shell" input step retained.
    Dim e As String
    e = "Shell" & UserInput

    ' --- category 3: folding must stop, nothing is guessed ------------------
    ' object/member call: Chr(100) already yields "d" (PARTIAL), then the
    ' member access forces a stop with an explicit reason.
    Dim f As String
    f = Chr(100) & Application.Environment

    ' explicit 16-bit Integer arithmetic that overflows -> stop, no wrap
    Dim g As Integer
    g = 32767% + 1%

    ' floating point and an unknown custom function: Chr(72) yields "H"
    ' (PARTIAL), the float argument then forces a stop.
    Dim h As String
    h = Chr(72) & DecodePayload(1.5)
End Sub
