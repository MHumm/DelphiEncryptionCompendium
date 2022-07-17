program Hash_FMX;

uses
  System.StartUpCopy,
  FMX.Forms,
<<<<<<< HEAD
  MainFormHashFMX in 'MainFormHashFMX.pas' {FormMain};
=======
  MainForm in 'MainFormHashFMX.pas' {FormMain};
>>>>>>> development

{$R *.res}

begin
  ReportMemoryLeaksOnShutdown := true;

  Application.Initialize;
  Application.CreateForm(TFormMain, FormMain);
  Application.Run;
end.
