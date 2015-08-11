git clone  git@github.com:131/pageantbridge.git
set dir=pageantbridge\PageantBridge
csc /optimize /target:winexe /out:PageantBridge.exe %dir%\Program.cs %dir%\PageantBridge.cs 