program CipherBlockModesVCL;

uses
  Vcl.Forms,
  MainFormCipherBlockmodesVCL in 'MainFormCipherBlockmodesVCL.pas' {FormMain};

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TFormMain, FormMain);
  Application.Run;
end.
