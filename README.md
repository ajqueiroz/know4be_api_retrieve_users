py -m pip install -r requirements.txt
Instructions rewritten: How to run.txt now describes the VS Code route step by step, including what to do when there is no Run button or a library is missing.
Reports folder still opens by itself: the launcher used to do this, so I moved it into the script (Windows only).
What the person does each time
Open VS Code, which normally reopens the folder.
If the exception list changed, click exceptions.txt, edit and save.
Click knowbe4_users_export.py, then the Run button (the triangle, top right).
Wait for "Finished" in the Terminal panel; the Reports folder opens.
One-time setup

The computer needs Python 3, VS Code and the Microsoft "Python" extension. The first run then asks for the API key in the Terminal panel and stores it in Windows Credential Manager.

VS Code is a step up in difficulty for a non-technical person compared with a double-click: they have the script open in an editor and could change it by accident. If that worries you, IT could mark the script file read-only.
