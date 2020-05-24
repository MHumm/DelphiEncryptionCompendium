program Hash_FMX;

uses
  System.StartUpCopy,
  FMX.Forms,
  MainForm in 'MainForm.pas' {FormMain},
  DECBaseClass in '..\..\Source\DECBaseClass.pas',
  DECHash in '..\..\Source\DECHash.pas',
  DECUtil in '..\..\Source\DECUtil.pas',
  DECTypes in '..\..\Source\DECTypes.pas',
  DECCRC in '..\..\Source\DECCRC.pas',
  DECFormatBase in '..\..\Source\DECFormatBase.pas',
  DECHashBase in '..\..\Source\DECHashBase.pas',
  DECData in '..\..\Source\DECData.pas',
  DECFormat in '..\..\Source\DECFormat.pas',
  DECUtilRawByteStringHelper in '..\..\Source\DECUtilRawByteStringHelper.pas',
  DECHashInterface in '..\..\Source\DECHashInterface.pas',
  DECDataHash in '..\..\Source\DECDataHash.pas';

{$R *.res}

begin
  ReportMemoryLeaksOnShutdown := true;

  Application.Initialize;
  // TMainForm
  Application.CreateForm(TFormMain, FormMain);
  Application.Run;
end.
