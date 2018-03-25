program Hash_FMX;

uses
  System.StartUpCopy,
  FMX.Forms,
  MainForm in 'MainForm.pas' {Form1},
  DECBaseClass in '..\..\Source\DECBaseClass.pas',
  DECHash in '..\..\Source\DECHash.pas',
  DECUtil in '..\..\Source\DECUtil.pas',
  DECTypes in '..\..\Source\DECTypes.pas',
  DECCRC in '..\..\Source\DECCRC.pas',
  DECFormatBase in '..\..\Source\DECFormatBase.pas',
  DECHashBase in '..\..\Source\DECHashBase.pas',
  DECData in '..\..\Source\DECData.pas',
  DECFormat in '..\..\Source\DECFormat.pas';

{$R *.res}

begin
  ReportMemoryLeaksOnShutdown := true;

  Application.Initialize;
  Application.CreateForm(TMainForm, Form1);
  Application.Run;
end.
