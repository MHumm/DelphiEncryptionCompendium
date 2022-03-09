program Hash_FMX;

uses
  FastMM4,
  System.StartUpCopy,
  FMX.Forms,
  MainForm in 'MainForm.pas' {Form1};

{$R *.res}

begin
  ReportMemoryLeaksOnShutdown := true;

  Application.Initialize;
  Application.CreateForm(TFormMain, FormMain);
  Application.Run;
end.
