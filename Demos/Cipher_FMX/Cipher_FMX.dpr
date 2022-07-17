program Cipher_FMX;

uses
  System.StartUpCopy,
  FMX.Forms,
  MainFormCipherFMX in 'MainFormCipherFMX.pas' {FormMain};

{$R *.res}

begin
  Application.Initialize;
  Application.CreateForm(TFormMain, FormMain);
  Application.Run;
end.
