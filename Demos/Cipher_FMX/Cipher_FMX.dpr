program Cipher_FMX;

uses
  System.StartUpCopy,
  FMX.Forms,
<<<<<<< HEAD
  MainFormCipherFMX in 'MainFormCipherFMX.pas' {FormMain};
=======
  MainForm in 'MainFormCipherFMX.pas' {FormMain};
>>>>>>> development

{$R *.res}

begin
  Application.Initialize;
  Application.CreateForm(TFormMain, FormMain);
  Application.Run;
end.
